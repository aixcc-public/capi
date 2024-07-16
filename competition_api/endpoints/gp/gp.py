from typing import Any
from uuid import UUID

from arq.connections import ArqRedis
from fastapi import HTTPException, status
from sqlalchemy import func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection
from structlog.contextvars import bind_contextvars, clear_contextvars, get_contextvars
from structlog.stdlib import get_logger
from vyper import v

from competition_api.audit import get_auditor
from competition_api.audit.types import EventType, GPSubmissionInvalidReason
from competition_api.db import GeneratedPatch, VulnerabilityDiscovery, db_session
from competition_api.flatfile import Flatfile, StorageType
from competition_api.models import GPResponse, GPStatusResponse, GPSubmission
from competition_api.models.types import FeedbackStatus, UUIDPathParameter
from competition_api.tasks.pool import get_queue_name

LOGGER = get_logger(__name__)


async def process_gp_upload(
    gp: GPSubmission,
    db: AsyncConnection,
    team_id: UUID,
    task_pool: ArqRedis,
) -> GPResponse:
    clear_contextvars()
    auditor = get_auditor(team_id=team_id)
    bind_contextvars(
        team_id=str(team_id), endpoint="GP upload", run_id=str(v.get("run_id"))
    )

    if v.get_bool("mock_mode"):
        await auditor.emit(EventType.MOCK_RESPONSE)
        return GPResponse(
            status=FeedbackStatus.ACCEPTED,
            patch_size=len(f"{gp.data}"),
            gp_uuid=gp.cpv_uuid,
        )

    # Create GP row
    row: dict[str, Any] = {}

    azure_container = f"worker-{team_id}"
    patch = Flatfile(azure_container, contents=gp.data.encode("utf8"))
    await patch.write(to=StorageType.FILESYSTEM)  # for archival purposes
    await patch.write(to=StorageType.AZUREBLOB)
    bind_contextvars(patch_size=len(gp.data), patch_sha256=patch.sha256)

    row["data_sha256"] = patch.sha256

    gp_row = (
        await db.execute(insert(GeneratedPatch).values(**row).returning(GeneratedPatch))
    ).fetchone()
    await db.commit()

    if gp_row is None:
        raise RuntimeError("No value returned on GeneratedPatch database insert")
    gp_row = gp_row[0]

    for update_context in [bind_contextvars, auditor.push_context]:
        update_context(gp_uuid=str(gp_row.id))
    await auditor.emit(
        EventType.GP_SUBMISSION,
        submitted_cpv_uuid=gp.cpv_uuid,
        patch_sha256=patch.sha256,
    )

    vds = (
        await db.execute(
            select(VulnerabilityDiscovery).where(
                VulnerabilityDiscovery.cpv_uuid == gp.cpv_uuid
            )
        )
    ).fetchall()

    if len(vds) == 0 or vds[0][0].team_id != team_id:
        async with db_session() as db:
            await db.execute(
                update(GeneratedPatch)
                .where(GeneratedPatch.id == gp_row.id)
                .values(status=FeedbackStatus.NOT_ACCEPTED)
            )
        await auditor.emit(
            EventType.GP_SUBMISSION_INVALID,
            reason=(
                GPSubmissionInvalidReason.VDS_WAS_FROM_ANOTHER_TEAM
                if vds and vds[0][0].team_id != team_id
                else GPSubmissionInvalidReason.INVALID_VDS_ID
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="cpv_uuid not found",
            headers={"WWW-Authenticate": "Basic"},
        )

    vds = vds[0][0]

    # Now that we have a VDS, add it to our audit context and DB row
    for update_context in [bind_contextvars, auditor.push_context]:
        update_context(
            cp_name=vds.cp_name, vd_uuid=str(vds.id), cpv_uuid=str(gp.cpv_uuid)
        )
    await db.execute(
        update(GeneratedPatch)
        .where(GeneratedPatch.id == gp_row.id)
        .values(cpv_uuid=gp.cpv_uuid)
    )
    await db.commit()

    gp_row = (
        await db.execute(select(GeneratedPatch).where(GeneratedPatch.id == gp_row.id))
    ).fetchall()[0][0]

    submissions_for_cpv_uuid = (
        await db.execute(
            select(func.count(GeneratedPatch.id)).where(  # pylint: disable=not-callable
                GeneratedPatch.cpv_uuid
                == gp_row.cpv_uuid,  # CPV UUIDs are globally unique
                GeneratedPatch.id != gp_row.id,
            )
        )
    ).fetchone()
    duplicate = submissions_for_cpv_uuid is not None and submissions_for_cpv_uuid[0] > 0

    # pylint: disable=duplicate-code
    job_id = "{capijobs}" + f"check-gp-{gp_row.id}"
    queue_name = get_queue_name(
        str(team_id) if str(team_id) in v.get("workers") else "default"
    )
    if queue_name == "default":
        await LOGGER.awarning("Putting job for %s on the default queue", str(team_id))
    await LOGGER.ainfo("Queuing %s on %s", job_id, queue_name)
    enqueued = await task_pool.enqueue_job(
        "check_gp",
        auditor.context,
        get_contextvars(),
        vds,
        gp_row,
        duplicate,
        azure_container,
        patch.container_sas(),
        _job_id=job_id,
        _queue_name=queue_name,
    )
    if not enqueued:
        await LOGGER.awarning("Job with ID %s was already enqueued", job_id)
    # pylint: enable=duplicate-code

    return GPResponse(
        status=gp_row.status,
        patch_size=len(gp.data),
        gp_uuid=gp_row.id,
    )


async def get_gp_status(
    gp_uuid: UUIDPathParameter,
    db: AsyncConnection,
    team_id: UUID,
) -> GPStatusResponse:
    if v.get_bool("mock_mode"):
        return GPStatusResponse(status=FeedbackStatus.ACCEPTED, gp_uuid=gp_uuid)

    result = (
        await db.execute(
            select(GeneratedPatch.status, VulnerabilityDiscovery.team_id)
            .join(VulnerabilityDiscovery)
            .where(GeneratedPatch.id == gp_uuid)
        )
    ).fetchone()

    if result is None or result.team_id != team_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="gp_uuid not found",
            headers={"WWW-Authenticate": "Basic"},
        )

    return GPStatusResponse(
        status=result.status,
        gp_uuid=gp_uuid,
    )
