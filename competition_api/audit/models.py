from datetime import UTC, datetime
from typing import Union
from uuid import UUID

from pydantic import BaseModel, Field

from competition_api.models import GPSubmission
from competition_api.models.types import FeedbackStatus

from .types import (
    Disposition,
    EventType,
    GPSubmissionInvalidReason,
    VDSubmissionFailReason,
    VDSubmissionInvalidReason,
)


class MockResponseEvent(BaseModel):
    """Emitted if the cAPI is operating in mock mode."""

    mock_content: bool = True
    description: str = "Mock content returned to client"


class GPSubmissionEvent(GPSubmission):
    """A CRS has submitted a generated patch."""


class GPSubmissionInvalidEvent(BaseModel):
    """The generated patch is broken and is not scoreable."""

    disposition: Disposition = Disposition.BAD

    gp_uuid: UUID | None
    reason: GPSubmissionInvalidReason


class VDEvent(BaseModel):
    """All events associated with the vulnerability discovery lifecycle will have
    these two fields."""

    vd_uuid: UUID
    cp_name: str


class VDSubmissionEvent(VDEvent):
    """A CRS has submitted a vulnerability discovery."""

    harness: str
    pov_blob_b64: str
    pou_commit: str
    sanitizer: str


class VDSubmissionInvalidEvent(VDEvent):
    """The vulnerability discovery is broken and is not scoreable."""

    disposition: Disposition = Disposition.BAD

    reason: VDSubmissionInvalidReason


class VDSubmissionFailEvent(VDEvent):
    """The vulnerability discovery failed one of the tests."""

    disposition: Disposition = Disposition.BAD
    feedback_status: FeedbackStatus = FeedbackStatus.NOT_ACCEPTED

    reasons: list[VDSubmissionFailReason]


class VDSubmissionSuccessEvent(VDEvent):
    """The vulnerability discovery has passed all tests."""

    disposition: Disposition = Disposition.GOOD
    feedback_status: FeedbackStatus = FeedbackStatus.ACCEPTED

    cpv_uuid: UUID


class VDSanitizerResultEvent(VDEvent):
    """The vulnerability discovery's input blob has been passed to the challenge
    problem at a particular commit.  This event contains the results of that test,
    including what sanitizers fired.

    expected_sanitizer contains which sanitizer the VD said would fire, but this event
    is also emitted when testing before the commit the VD said introduced the vuln.
    The sanitizer should not fire at this commit.  We include the disposition field to
    indicate whether the result is good or bad."""

    commit_sha: str
    disposition: Disposition
    expected_sanitizer: str | None
    expected_sanitizer_triggered: bool
    sanitizers_triggered: list[str]


class EventWrapper(BaseModel):
    schema_version: str = "1.0.0"
    team_id: UUID
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_type: EventType
    event: Union[
        MockResponseEvent,
        GPSubmissionEvent,
        GPSubmissionInvalidEvent,
        VDSubmissionEvent,
        VDSubmissionInvalidEvent,
        VDSubmissionFailEvent,
        VDSubmissionSuccessEvent,
        VDSanitizerResultEvent,
    ]
