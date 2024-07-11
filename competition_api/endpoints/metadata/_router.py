from fastapi import APIRouter
from vyper import v

from competition_api.models import MetadataResponse

router = APIRouter()


@router.get("/metadata/", tags=["metadata"])
async def metadata() -> MetadataResponse:
    return MetadataResponse(run_id=v.get("run_id"))
