from datetime import datetime

from pydantic import BaseModel


class TimestampInput(BaseModel):
    timestamp: datetime

    model_config = {
        "json_schema_extra": {
            "examples": [{"timestamp": "2024-05-28T17:47:27.547259Z"}]
        }
    }
