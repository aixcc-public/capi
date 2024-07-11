from uuid import UUID

from pydantic import BaseModel


class MetadataResponse(BaseModel):
    run_id: UUID

    model_config = {
        "json_schema_extra": {
            "examples": [{"run_id": "00000000-0000-0000-0000-000000000000"}]
        }
    }
