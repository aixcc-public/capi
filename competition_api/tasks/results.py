import os
from enum import Enum
from pathlib import Path
from typing import Any, Union
from uuid import UUID

import redis.asyncio as redis
from pydantic import BaseModel
from sqlalchemy import update
from structlog.stdlib import get_logger
from vyper import v

from competition_api.db import GeneratedPatch, VulnerabilityDiscovery, db_session
from competition_api.flatfile import Flatfile, StorageType
from competition_api.models.types import FeedbackStatus

LOGGER = get_logger(__name__)


class OutputType(Enum):
    RESULT = "result"
    ARCHIVE = "archive"


class ResultType(Enum):
    VDS = "vds"
    GP = "gp"


class Result(BaseModel):
    result_type: ResultType
    feedback_status: FeedbackStatus
    row_id: UUID
    cpv_uuid: UUID | None = None


class Archive(BaseModel):
    azure_container: str
    filename: str
    sha256: str


class OutputMessage(BaseModel):
    message_type: OutputType
    content: Union[Result, Archive]


async def report(
    redis_: redis.Redis,
    result_type: ResultType,
    row_id: UUID,
    feedback_status: FeedbackStatus,
    cpv_uuid: UUID | None = None,
):
    await redis_.publish(
        v.get("redis.channels.results"),
        OutputMessage(
            message_type=OutputType.RESULT,
            content=Result(
                result_type=result_type,
                row_id=row_id,
                feedback_status=feedback_status,
                cpv_uuid=cpv_uuid,
            ),
        ).model_dump_json(),
    )


class ResultReceiver:
    def __init__(self):
        self._redis = redis.Redis(**v.get("redis.kwargs"))

    async def _process_result(self, result: Result):
        await LOGGER.ainfo(
            "Received result: %s for %s %s",
            result.feedback_status,
            result.result_type,
            result.row_id,
        )

        updates: dict[str, Any] = {"status": result.feedback_status}

        table: type[VulnerabilityDiscovery] | type[GeneratedPatch]

        if result.result_type == ResultType.VDS:
            table = VulnerabilityDiscovery
            if result.cpv_uuid is not None:
                updates["cpv_uuid"] = result.cpv_uuid
        elif result.result_type == ResultType.GP:
            table = GeneratedPatch
        else:
            raise RuntimeError(f"Invalid result type {result.result_type}")

        async with db_session() as db:
            await db.execute(
                update(table).where(table.id == result.row_id).values(**updates)
            )

    async def _process_archive(self, archive: Archive):
        await LOGGER.ainfo(
            "Received archive %s -> %s", archive.sha256, archive.filename
        )
        flatfile = Flatfile(archive.azure_container, contents_hash=archive.sha256)
        archive_dir = Path(v.get("flatfile_dir")) / "output"
        os.makedirs(archive_dir, exist_ok=True)

        target_filename = archive_dir / archive.filename
        suffix: int | None = None
        while os.path.exists(
            f"{target_filename}" + (f"_copy{suffix}" if suffix is not None else "")
        ):
            suffix = 1 if suffix is None else suffix + 1

        with open(
            f"{target_filename}" + (f"_copy{suffix}" if suffix is not None else ""),
            mode="wb",
        ) as f:
            await LOGGER.ainfo("Writing %s", archive.filename)
            f.write(await flatfile.read(from_=StorageType.AZUREBLOB))

    async def listen_for_worker_events(self):
        await LOGGER.adebug("Starting result event processor")
        async with self._redis.pubsub() as pubsub:
            await pubsub.subscribe(v.get("redis.channels.results"))
            while True:
                message = await pubsub.get_message(ignore_subscribe_messages=True)
                if message is not None:
                    await LOGGER.ainfo(
                        "Received CP output message via redis: %s", message
                    )
                    message = OutputMessage.model_validate_json(
                        message["data"].decode("utf8")
                    )

                    if message.message_type == OutputType.RESULT:
                        await self._process_result(message.content)
                    elif message.message_type == OutputType.ARCHIVE:
                        await self._process_archive(message.content)
