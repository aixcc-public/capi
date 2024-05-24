import asyncio
from typing import Any
from uuid import UUID

from aiopg.sa import SAConnection
from fastapi import Depends, HTTPException, status
from sqlalchemy import insert, select
from structlog.stdlib import get_logger
from vyper import v

from competition_api.audit import Auditor
from competition_api.db import GeneratedPatch, VulnerabilityDiscovery, fastapi_get_db
from competition_api.endpoints.lib.auth import get_token_id
from competition_api.models import GPResponse, GPStatusResponse, GPSubmission
from competition_api.models.types import FeedbackStatus, UUIDPathParameter
from competition_api.tasks import TaskRunner

LOGGER = get_logger(__name__)


async def process_gp_upload(
    gp: GPSubmission, db: SAConnection, team_id: UUID
) -> GPResponse:
    auditor = Auditor(team_id)

    if v.get_bool("mock_mode"):
        return GPResponse(
            status=FeedbackStatus.ACCEPTED,
            patch_size=len(f"{gp.data}"),
            gp_uuid=gp.cpv_uuid,
        )

    vds = await db.execute(
        select(VulnerabilityDiscovery.team_id).where(
            VulnerabilityDiscovery.cpv_uuid == gp.cpv_uuid
        )
    )
    vds = await vds.fetchall()

    if len(vds) == 0 or vds[0].team_id != team_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="cpv_uuid not found",
            headers={"WWW-Authenticate": "Basic"},
        )
    row: dict[str, Any] = {"cpv_uuid": gp.cpv_uuid}

    try:
        # Postgres wants a binary format for this field
        row["data"] = gp.data.encode("utf8")
    except AttributeError:
        row["data"] = gp.data

    gp_row = await db.execute(
        insert(GeneratedPatch).values(**row).returning(GeneratedPatch)
    )
    gp_row = await gp_row.fetchone()

    vds_row = await db.execute(
        select(VulnerabilityDiscovery).where(
            VulnerabilityDiscovery.cpv_uuid == gp.cpv_uuid
        )
    )
    vds_row = await vds_row.fetchone()

    cp_name = await db.execute(
        select(VulnerabilityDiscovery.cp_name).where(
            VulnerabilityDiscovery.cpv_uuid == gp.cpv_uuid
        )
    )
    cp_name = await cp_name.fetchone()

    asyncio.create_task(TaskRunner(cp_name.cp_name, auditor).test_gp(gp_row, vds_row))

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
