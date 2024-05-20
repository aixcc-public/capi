import asyncio
import uuid

from aiopg.sa import SAConnection
from fastapi import HTTPException, status
from sqlalchemy import insert, select
from structlog.stdlib import get_logger
from vyper import v

from competition_api.db import VulnerabilityDiscovery
from competition_api.models.types import FeedbackStatus, UUIDPathParameter
from competition_api.models.vds import VDSResponse, VDSStatusResponse, VDSubmission
from competition_api.tasks import TaskRunner

LOGGER = get_logger(__name__)


async def process_vd_upload(
    vds: VDSubmission,
    db: SAConnection,
    team_id: str,
) -> VDSResponse:
    if v.get_bool("mock_mode"):
        return VDSResponse(
            status=FeedbackStatus.ACCEPTED,
            cp_name=f"{vds.cp_name}",
            vd_uuid=uuid.uuid4(),
        )

    row = {
        "team_id": team_id,
        "cp_name": vds.cp_name,
        "pou_commit_sha1": vds.pou.commit_sha1,
        "pou_sanitizer": vds.pou.sanitizer,
        "pov_harness": vds.pov.harness,
        "pov_data": vds.pov.data,
    }
    result = await db.execute(
        insert(VulnerabilityDiscovery).values(**row).returning(VulnerabilityDiscovery)
    )
    result = await result.fetchone()

    asyncio.create_task(TaskRunner(vds.cp_name).test_vds(result))

    return VDSResponse(
        status=result.status,
        cp_name=result.cp_name,
        vd_uuid=result.id,
    )


async def get_vd_status(
    vd_uuid: UUIDPathParameter,
    db: SAConnection,
    team_id: str,
) -> VDSStatusResponse:
    if v.get_bool("mock_mode"):
        return VDSStatusResponse(
            status=FeedbackStatus.ACCEPTED,
            vd_uuid=vd_uuid,
            cpv_uuid=uuid.uuid4(),
        )

    result = await db.execute(
        select(
            VulnerabilityDiscovery.status,
            VulnerabilityDiscovery.cpv_uuid,
            VulnerabilityDiscovery.team_id,
        ).where(VulnerabilityDiscovery.id == vd_uuid)
    )
    result = await result.fetchone()

    if result is None or result.team_id != team_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="vd_uuid not found",
            headers={"WWW-Authenticate": "Basic"},
        )

    return VDSStatusResponse(
        status=result.status, vd_uuid=vd_uuid, cpv_uuid=result.cpv_uuid
    )
