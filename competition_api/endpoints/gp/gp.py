import asyncio
import base64
from uuid import UUID

from aiopg.sa import SAConnection
from fastapi import Depends, HTTPException, status
from sqlalchemy import insert, select, update
from structlog.stdlib import get_logger
from vyper import v

from competition_api.audit import get_auditor
from competition_api.audit.types import EventType, GPSubmissionInvalidReason
from competition_api.db import GeneratedPatch, VulnerabilityDiscovery, fastapi_get_db
from competition_api.endpoints.lib.auth import get_token_id
from competition_api.models import GPResponse, GPStatusResponse, GPSubmission
from competition_api.models.types import FeedbackStatus, UUIDPathParameter
from competition_api.tasks import TaskRunner

LOGGER = get_logger(__name__)


async def process_gp_upload(
    gp: GPSubmission, db: SAConnection, team_id: UUID
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
    row: dict[str, bytes] = {}
    # Postgres wants a binary format for this field
    row["data"] = gp.data.encode("utf8")

    gp_row = await db.execute(
        insert(GeneratedPatch).values(**row).returning(GeneratedPatch)
    )
    gp_row = await gp_row.fetchone()

    auditor.push_context(gp_uuid=gp_row.id)
    await auditor.emit(
        EventType.GP_SUBMISSION,
        submitted_cpv_uuid=gp.cpv_uuid,
        patch_b64=base64.b64encode(row["data"]),
    )

    vds = await db.execute(
        select(VulnerabilityDiscovery).where(
            VulnerabilityDiscovery.cpv_uuid == gp.cpv_uuid
        )
    )
    vds = await vds.fetchall()

    if len(vds) == 0 or vds[0].team_id != team_id:
        await db.execute(
            update(GeneratedPatch)
            .where(GeneratedPatch.id == gp_row.id)
            .values(status=FeedbackStatus.NOT_ACCEPTED)
        )
        await auditor.emit(
            EventType.GP_SUBMISSION_INVALID,
            reason=(
                GPSubmissionInvalidReason.VDS_WAS_FROM_ANOTHER_TEAM
                if vds and vds[0].team_id != team_id
                else GPSubmissionInvalidReason.INVALID_VDS_ID
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="cpv_uuid not found",
            headers={"WWW-Authenticate": "Basic"},
        )

    vds = vds[0]

    # Now that we have a VDS, add it to our audit context and DB row
    auditor.push_context(cp_name=vds.cp_name, vd_uuid=vds.id, cpv_uuid=gp.cpv_uuid)
    await db.execute(
        update(GeneratedPatch)
        .where(GeneratedPatch.id == gp_row.id)
        .values(cpv_uuid=gp.cpv_uuid)
    )

    asyncio.create_task(TaskRunner(vds.cp_name, auditor).test_gp(gp_row, vds))

    return GPResponse(
        status=gp_row.status,
        patch_size=len(gp_row.data),
        gp_uuid=gp_row.id,
    )


async def get_gp_status(
    gp_uuid: UUIDPathParameter,
    db: SAConnection = Depends(fastapi_get_db),
    team_id: UUID = Depends(get_token_id),
) -> GPStatusResponse:
    if v.get_bool("mock_mode"):
        return GPStatusResponse(status=FeedbackStatus.ACCEPTED, gp_uuid=gp_uuid)

    result = await db.execute(
        select(GeneratedPatch.status, VulnerabilityDiscovery.team_id)
        .join(VulnerabilityDiscovery)
        .where(GeneratedPatch.id == gp_uuid)
    )
    result = await result.fetchone()

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
