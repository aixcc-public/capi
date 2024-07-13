from typing import Any

import redis.asyncio as redis
from aiofile import async_open
from structlog.stdlib import get_logger
from vyper import v

from .models import (
    CompetitionStartEvent,
    CompetitionStopEvent,
    CPOutputArchived,
    EventWrapper,
    GPFunctionalTestsPass,
    GPPatchBuiltEvent,
    GPSanitizerDidNotFire,
    GPSubmissionDuplicateCPVEvent,
    GPSubmissionEvent,
    GPSubmissionFailEvent,
    GPSubmissionInvalidEvent,
    GPSubmissionSuccessEvent,
    MockResponseEvent,
    TimeoutEvent,
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
    EventType.CP_OUTPUT_ARCHIVED: CPOutputArchived,
    EventType.COMPETITION_START: CompetitionStartEvent,
    EventType.COMPETITION_STOP: CompetitionStopEvent,
    EventType.DUPLICATE_GP_SUBMISSION_FOR_CPV_UUID: GPSubmissionDuplicateCPVEvent,
    EventType.GP_FUNCTIONAL_TESTS_PASS: GPFunctionalTestsPass,
    EventType.GP_PATCH_BUILT: GPPatchBuiltEvent,
    EventType.GP_SANITIZER_DID_NOT_FIRE: GPSanitizerDidNotFire,
    EventType.GP_SUBMISSION: GPSubmissionEvent,
    EventType.GP_SUBMISSION_FAIL: GPSubmissionFailEvent,
    EventType.GP_SUBMISSION_INVALID: GPSubmissionInvalidEvent,
    EventType.GP_SUBMISSION_SUCCESS: GPSubmissionSuccessEvent,
    EventType.MOCK_RESPONSE: MockResponseEvent,
    EventType.TIMEOUT: TimeoutEvent,
    EventType.VD_SANITIZER_RESULT: VDSanitizerResultEvent,
    EventType.VD_SUBMISSION: VDSubmissionEvent,
    EventType.VD_SUBMISSION_FAIL: VDSubmissionFailEvent,
    EventType.VD_SUBMISSION_INVALID: VDSubmissionInvalidEvent,
    EventType.VD_SUBMISSION_SUCCESS: VDSubmissionSuccessEvent,
}


class Auditor:
    def __init__(self):
        self.context: dict[str, Any] = {}
        self._outfile = v.get("audit.file")
        self._redis: redis.Redis | None = None

    async def _write_line(self, line: str):
        async with async_open(self._outfile, "a", encoding="utf8") as auditfile:
            await LOGGER.adebug("Audit event: %s", line)
            await auditfile.write(f"{line}\n")

    async def _emit_event(self, event: Any):
        await self._write_line(event.model_dump_json())

    def push_context(self, **kwargs):
        self.context = self.context | kwargs

    def pop_context(self, key: str):
        self.context.pop(key)

    async def emit(self, event_type: EventType, **kwargs):
        wrapped = EventWrapper(
            team_id=self.context["team_id"],
            run_id=v.get("run_id"),
            event_type=event_type,
            event=EVENTS[event_type](**(self.context | kwargs)),
        )
        await self._emit_event(wrapped)

    async def listen_for_worker_events(self):
        if self._redis is None:
            self._redis = redis.Redis(**v.get("redis.kwargs"))
        async with self._redis.pubsub() as pubsub:
            await LOGGER.adebug("Starting audit event processor")
            await pubsub.subscribe(v.get("redis.channels.audit"))
            while True:
                message = await pubsub.get_message(ignore_subscribe_messages=True)
                if message is not None:
                    await LOGGER.ainfo("Received audit message via redis: %s", message)
                    await self._write_line(message["data"].decode("utf8"))


class RedisAuditor(Auditor):
    def __init__(self):
        self.redis = redis.Redis(**v.get("redis.kwargs"))
        super().__init__()

    async def _emit_event(self, event: Any):
        event_str = event.model_dump_json()
        await self.redis.publish(v.get("redis.channels.audit"), event_str)


def get_auditor(cls=Auditor, **context) -> Auditor:
    auditor = cls()
    auditor.push_context(**context)
    return auditor
