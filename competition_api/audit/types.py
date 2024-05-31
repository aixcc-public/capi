from enum import Enum


class Disposition(Enum):
    """Some of our events do not change the FeedbackStatus, but have a bearing on the
    CRS's score."""

    GOOD = "good"
    BAD = "bad"


class GPSubmissionInvalidReason(Enum):
    INVALID_VDS_ID = "invalid_vds_id"
    VDS_WAS_FROM_ANOTHER_TEAM = "vds_was_from_another_team"


class GPSubmissionFailReason(Enum):
    PATCH_DID_NOT_APPLY = "patch_did_not_apply"
    SANITIZER_FIRED_AFTER_PATCH = "sanitizer_fired_after_patch"
    FUNCTIONAL_TESTS_FAILED = "functional_tests_failed"
    DUPLICATE_CPV_UUID = "duplicate_cpv_uuid"


class VDSubmissionInvalidReason(Enum):
    SANITIZER_NOT_FOUND = "sanitizer_not_found"
    COMMIT_CHECKOUT_FAILED = "commit_checkout_failed"
    CP_NOT_IN_CP_ROOT_FOLDER = "cp_not_in_cp_root_folder"


class VDSubmissionFailReason(Enum):
    DUPLICATE_COMMIT = "duplicate_commit"
    SANITIZER_DID_NOT_FIRE_AT_COMMIT = "sanitizer_did_not_fire_at_commit"
    SANITIZER_DID_NOT_FIRE_AT_HEAD = "sanitizer_did_not_fire_at_head"
    SANITIZER_FIRED_BEFORE_COMMIT = "sanitizer_fired_before_commit"


class EventType(Enum):
    GP_SUBMISSION = "gp_submission"
    GP_SUBMISSION_INVALID = "gp_submission_invalid"
    GP_SUBMISSION_FAIL = "gp_submission_failed"
    GP_PATCH_BUILT = "gp_patch_built"
    GP_FUNCTIONAL_TESTS_PASS = "gp_functional_tests_pass"
    GP_SANITIZER_DID_NOT_FIRE = "gp_sanitizer_did_not_fire"
    GP_SUBMISSION_SUCCESS = "gp_submission_success"
    VD_SANITIZER_RESULT = "vd_sanitizer_result"
    VD_SUBMISSION = "vd_submission"
    VD_SUBMISSION_FAIL = "vd_submission_failed"
    VD_SUBMISSION_INVALID = "vd_submission_invalid"
    VD_SUBMISSION_SUCCESS = "vd_submission_success"
    MOCK_RESPONSE = "mock_response"
