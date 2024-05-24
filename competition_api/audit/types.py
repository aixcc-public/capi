from enum import Enum


class Disposition(Enum):
    """Some of our events do not change the FeedbackStatus, but have a bearing on the
    CRS's score."""

    GOOD = "good"
    BAD = "bad"


class GPSubmissionInvalidReason(Enum):
    NO_MATCHING_VDS = "no_matching_vds"


class VDSubmissionInvalidReason(Enum):
    SANITIZER_NOT_FOUND = "sanitizer_not_found"
    COMMIT_CHECKOUT_FAILED = "commit_checkout_failed"


class VDSubmissionFailReason(Enum):
    DUPLICATE_COMMIT = "duplicate_commit"
    SANITIZER_DID_NOT_FIRE_AT_COMMIT = "sanitizer_did_not_fire_at_commit"
    SANITIZER_DID_NOT_FIRE_AT_HEAD = "sanitizer_did_not_fire_at_head"
    SANITIZER_FIRED_BEFORE_COMMIT = "sanitizer_fired_before_commit"


class EventType(Enum):
    GP_SUBMISSION = "gp_submission"
    GP_SUBMISSION_INVALID = "gp_submission_invalid"
    VD_SANITIZER_RESULT = "vd_sanitizer_result"
    VD_SUBMISSION = "vd_submission"
    VD_SUBMISSION_FAIL = "vd_submission_failed"
    VD_SUBMISSION_INVALID = "vd_submission_invalid"
    VD_SUBMISSION_SUCCESS = "vd_submission_success"
    MOCK_RESPONSE = "mock_response"
