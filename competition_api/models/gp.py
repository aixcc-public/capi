import uuid

from pydantic import UUID4, Base64Str, BaseModel

from competition_api.models.examples import EXAMPLE_B64
from competition_api.models.types import FeedbackStatus


class GPSubmission(BaseModel):
    cpv_uuid: UUID4
    data: Base64Str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "cpv_uuid": str(uuid.uuid4()),
                    "data": EXAMPLE_B64,
                }
            ]
        }
    }


class GPResponse(BaseModel):
    status: FeedbackStatus
    patch_size: int
    gp_uuid: UUID4

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "status": str(FeedbackStatus.ACCEPTED),
                    "patch_size": 1024,
                    "gp_uuid": str(uuid.uuid4()),
                }
            ]
        }
    }


class GPStatusResponse(BaseModel):
    status: FeedbackStatus
    gp_uuid: UUID4

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"status": str(FeedbackStatus.ACCEPTED), "gp_uuid": str(uuid.uuid4())}
            ]
        }
    }
