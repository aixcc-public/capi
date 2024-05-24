from typing import Any
from uuid import UUID

from aiofile import async_open
from structlog.stdlib import get_logger
from vyper import v

from .models import (
    EventWrapper,
    GPSubmissionEvent,
    GPSubmissionInvalidEvent,
    MockResponseEvent,
    VDSanitizerResultEvent,
    VDSubmissionEvent,
    VDSubmissionFailEvent,
    VDSubmissionInvalidEvent,
    VDSubmissionSuccessEvent,
)
from .types import EventType

LOGGER = get_logger(__name__)

v.set_default("audit.file", "/var/log/capi/audit.log")


EVENTS = {
    EventType.GP_SUBMISSION: GPSubmissionEvent,
    EventType.GP_SUBMISSION_INVALID: GPSubmissionInvalidEvent,
    EventType.VD_SUBMISSION: VDSubmissionEvent,
    EventType.VD_SUBMISSION_INVALID: VDSubmissionInvalidEvent,
    EventType.VD_SUBMISSION_FAIL: VDSubmissionFailEvent,
    EventType.VD_SUBMISSION_SUCCESS: VDSubmissionSuccessEvent,
    EventType.VD_SANITIZER_RESULT: VDSanitizerResultEvent,
    EventType.MOCK_RESPONSE: MockResponseEvent,
}


class Auditor:
    def __init__(self, team_id: UUID):
        self._context: dict[str, Any] = {}
        self._team_id = team_id
        self._outfile = v.get("audit.file")

    async def _write_line(self, line: str, mode: str = "a"):
        async with async_open(self._outfile, mode, encoding="utf8") as auditfile:
            await auditfile.write(f"{line}\n")

    def push_context(self, **kwargs):
        self._context = self._context | kwargs

    def pop_context(self, key: str):
        self._context.pop(key)

    async def emit(self, event_type: EventType, **kwargs):
        wrapped = EventWrapper(
            team_id=self._team_id,
            event_type=event_type,
            event=EVENTS[event_type](**self._context, **kwargs),
        )
        output = wrapped.model_dump_json()
        await LOGGER.adebug("Audit event: %s", output)
        await self._write_line(output)
