import asyncio
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection
from structlog.stdlib import get_logger
from vyper import v

from competition_api.audit import get_auditor
from competition_api.audit.types import EventType, GPSubmissionInvalidReason
from competition_api.db import GeneratedPatch, VulnerabilityDiscovery, db_session
from competition_api.flatfile import Flatfile
from competition_api.models import GPResponse, GPStatusResponse, GPSubmission
from competition_api.models.types import FeedbackStatus, UUIDPathParameter
from competition_api.tasks import TaskRunner

LOGGER = get_logger(__name__)


async def process_gp_upload(
    gp: GPSubmission, db: AsyncConnection, team_id: UUID
) -> GPResponse:
    auditor = get_auditor(team_id)

    if v.get_bool("mock_mode"):
        await auditor.emit(EventType.MOCK_RESPONSE)
        return GPResponse(
            status=FeedbackStatus.ACCEPTED,
            patch_size=len(f"{gp.data}"),
            gp_uuid=gp.cpv_uuid,
        )

    # Create GP row
    row: dict[str, Any] = {}

    patch = Flatfile(contents=gp.data.encode("utf8"))
    await patch.write()

    row["data_sha256"] = patch.sha256

    gp_row = (
        await db.execute(insert(GeneratedPatch).values(**row).returning(GeneratedPatch))
    ).fetchone()[0]
    await db.commit()

    auditor.push_context(gp_uuid=gp_row.id)
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
    auditor.push_context(cp_name=vds.cp_name, vd_uuid=vds.id, cpv_uuid=gp.cpv_uuid)
    await db.execute(
        update(GeneratedPatch)
        .where(GeneratedPatch.id == gp_row.id)
        .values(cpv_uuid=gp.cpv_uuid)
    )
    await db.commit()

    gp_row = (await db.execute(select(GeneratedPatch))).fetchall()[0][0]

    asyncio.create_task(TaskRunner(vds.cp_name, auditor).test_gp(gp_row, vds))

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
