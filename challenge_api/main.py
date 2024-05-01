import uuid
from enum import Enum
from typing import Annotated

from fastapi import FastAPI, Path
from pydantic import UUID4, Base64Str, BaseModel, StringConstraints

SHA1_REGEX = r"[0-9a-f]{40}"
SHA1_CONSTRAINTS = StringConstraints(
    strip_whitespace=True,
    to_upper=True,
    pattern=SHA1_REGEX,
    max_length=40,
    min_length=40,
)
EXAMPLE_B64 = (
    "LS0tIGhlbGxvLmMJMjAxNC0xMC0wNyAxODoxNzo0OS4wMDAwMDAwMDAgKzA1MzANCisrKyBoZWxsb19uZXcuYwkyMDE0LT"
    "EwLTA3IDE4OjE3OjU0LjAwMDAwMDAwMCArMDUzMA0KQEAgLTEsNSArMSw2IEBADQogI2luY2x1ZGUgPHN0ZGlvLmg+DQog"
    "DQotaW50IG1haW4oKSB7DQoraW50IG1haW4oaW50IGFyZ2MsIGNoYXIgKmFyZ3ZbXSkgew0KIAlwcmludGYoIkhlbGxvIF"
    "dvcmxkXG4iKTsNCisJcmV0dXJuIDA7DQogfQ=="
)
EXAMPLE_SHA1 = "2923ffa6e0572ee6572245f980acfcfb872fcf74"
UUIDPathParameter = Annotated[
    UUID4, Path(description="Example: 744a8ead-9ebc-40cd-9f96-8edf187868fa")
]

OPENAPI_SUMMARY = (
    "I'm sorry, but as an AI language model, I do not have the ability to access or analyze "
    "specific vulnerabilities. Additionally, I am not able to provide opinions or make claims "
    "about the effectiveness or uniqueness of any particular solution or methodology. My primary "
    "function is to provide information and answer questions to the best of my ability based on my "
    "training and knowledge. If you have any other questions, I would be happy to try and answer "
    "them for you."
)

AIXCC_API_VERSION = "2.0.0"
EXAMPLE_SANITIZER = "KASAN: slab-out-of-bounds"
EXAMPLE_HARNESS = "linux_test_harness"

tags_metadata = [
    {
        "name": "health",
        "description": "This endpoint will be used to check health of API.",
    },
    {
        "name": "submission",
        "description": "This endpoint will be used to submit VD and GP.",
    },
]

app = FastAPI(
    title=f"iAPI v{AIXCC_API_VERSION} - AIXCC Competition API",
    version=AIXCC_API_VERSION,
    summary=OPENAPI_SUMMARY,
    terms_of_service="https://aicyberchallenge.com/terms-condition/",
    openapi_tags=tags_metadata,
    contact={
        "name": "AIXCC",
        "url": "https://aicyberchallenge.com/faqs/",
    },
)


class FeedbackStatus(Enum):
    ACCEPTED = "accepted"
    NOT_ACCEPTED = "rejected"
    PENDING = "pending"


class POU(BaseModel):
    commit_sha1: Annotated[str, SHA1_CONSTRAINTS]
    sanitizer: str

    model_config = {
        "json_schema_extra": {
            "examples": [{"commit_sha1": EXAMPLE_SHA1, "sanitizer": EXAMPLE_SANITIZER}]
        }
    }


class POV(BaseModel):
    harness: str
    data: Base64Str

    model_config = {
        "json_schema_extra": {
            "examples": [{"harness": EXAMPLE_HARNESS, "data": EXAMPLE_B64}]
        }
    }


class VDSubmission(BaseModel):
    cp_name: str
    pou: POU
    pov: POV

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "cp_name": "linux kernel",
                    "pou": {
                        "commit_sha1": EXAMPLE_SHA1,
                        "sanitizer": EXAMPLE_SANITIZER,
                    },
                    "pov": {"harness": EXAMPLE_HARNESS, "data": EXAMPLE_B64},
                }
            ]
        }
    }


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


class VDSResponse(BaseModel):
    status: FeedbackStatus
    cp_name: str
    vd_uuid: UUID4

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "status": str(FeedbackStatus.ACCEPTED),
                    "cp_name": "linux kernel",
                    "vd_uuid": str(uuid.uuid4()),
                }
            ]
        }
    }


class VDSStatusResponse(BaseModel):
    status: FeedbackStatus
    vd_uuid: UUID4
    cpv_uuid: UUID4

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "status": str(FeedbackStatus.ACCEPTED),
                    "vd_uuid": str(uuid.uuid4()),
                    "cpv_uuid": str(uuid.uuid4()),
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


class HealthResponse(BaseModel):
    status: str

    model_config = {"json_schema_extra": {"examples": [{"status": "ok"}]}}


@app.get("/health/", tags=["health"])
@app.get("/", tags=["health"])
async def default_healthcheck() -> HealthResponse:
    return HealthResponse(status="ok")


@app.post("/submission/gp/", tags=["submission"])
async def upload_gp(gp_data: GPSubmission) -> GPResponse:
    return GPResponse(
        status=FeedbackStatus.ACCEPTED,
        patch_size=len(f"{gp_data.data}"),
        gp_uuid=gp_data.cpv_uuid,
    )


@app.post("/submission/vds/", tags=["submission"])
async def upload_vd(vds: VDSubmission) -> VDSResponse:
    return VDSResponse(
        status=FeedbackStatus.ACCEPTED,
        cp_name=f"{vds.cp_name}",
        vd_uuid=uuid.uuid4(),
    )


@app.get("/submission/vds/{vd_uuid}", tags=["submission"])
async def check_vd(vd_uuid: UUIDPathParameter) -> VDSStatusResponse:
    return VDSStatusResponse(
        status=FeedbackStatus.ACCEPTED,
        vd_uuid=vd_uuid,
        cpv_uuid=uuid.uuid4(),
    )


@app.get("/submission/gp/{gp_uuid}", tags=["submission"])
async def check_gp(gp_uuid: UUIDPathParameter) -> GPStatusResponse:
    return GPStatusResponse(status=FeedbackStatus.ACCEPTED, gp_uuid=gp_uuid)
