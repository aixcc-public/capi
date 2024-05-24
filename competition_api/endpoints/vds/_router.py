from uuid import UUID

from aiopg.sa import SAConnection
from fastapi import APIRouter, Depends
from structlog.stdlib import get_logger

from competition_api.db import fastapi_get_db
from competition_api.endpoints.lib.auth import get_token_id
from competition_api.models.types import UUIDPathParameter
from competition_api.models.vds import VDSResponse, VDSStatusResponse, VDSubmission

from .vds import get_vd_status, process_vd_upload

router = APIRouter()

LOGGER = get_logger(__name__)


@router.post("/submission/vds/", tags=["submission"])
async def upload_vd(
    vds: VDSubmission,
    db: SAConnection = Depends(fastapi_get_db),
    team_id: UUID = Depends(get_token_id),
) -> VDSResponse:
    return await process_vd_upload(vds, db, team_id)


@router.get("/submission/vds/{vd_uuid}", tags=["submission"])
async def check_vd(
    vd_uuid: UUIDPathParameter,
    db: SAConnection = Depends(fastapi_get_db),
    team_id: UUID = Depends(get_token_id),
) -> VDSStatusResponse:
    return await get_vd_status(vd_uuid, db, team_id)
