from uuid import UUID

from fastapi import APIRouter, Depends
from structlog.stdlib import get_logger

from competition_api.audit import get_auditor
from competition_api.audit.types import EventType
from competition_api.endpoints.lib.auth import get_token_id, has_admin_permissions
from competition_api.models import TimestampInput

router = APIRouter()

LOGGER = get_logger(__name__)


@router.post("/audit/start/")
async def start(
    event: TimestampInput,
    official: str = "false",
    team_id: UUID = Depends(get_token_id),
    _: bool = Depends(has_admin_permissions),
):
    official_bool = official.lower() in ["t", "true", "1", "yes", "y"]
    auditor = get_auditor(team_id=team_id)
    await auditor.emit(
        EventType.COMPETITION_START,
        timestamp=event.timestamp,
        official=official_bool,
    )
    return {"message": "Created competition start event", "official": official_bool}


@router.post("/audit/stop/")
async def stop(
    event: TimestampInput,
    team_id: UUID = Depends(get_token_id),
    _: bool = Depends(has_admin_permissions),
):
    auditor = get_auditor(team_id=team_id)
    await auditor.emit(EventType.COMPETITION_STOP, timestamp=event.timestamp)
    return {"message": "Created competition stop event"}
