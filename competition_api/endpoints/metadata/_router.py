from fastapi import APIRouter
from vyper import v

from competition_api.models import MetadataResponse

router = APIRouter()

v.set_default("run_id", "00000000-0000-0000-0000-000000000000")


@router.get("/metadata/", tags=["metadata"])
async def metadata() -> MetadataResponse:
    return MetadataResponse(run_id=v.get("run_id"))
