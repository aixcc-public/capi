from asyncio import sleep

import redis.asyncio as aioredis
import redis.exceptions
from structlog.stdlib import get_logger
from vyper import v

from competition_api.cp_workspace import CPWorkspace

LOGGER = get_logger(__name__)


async def sanitizers_triggered_at(
    workspace: CPWorkspace,
    pov_data_sha256: str,
    harness: str,
):
    await LOGGER.adebug("Calling harness %s with POV blob", harness)
    return await workspace.check_sanitizers(pov_data_sha256, harness)
    # TODO: store logs as artifact


async def wait_for_redis():
    r = aioredis.Redis(**v.get("redis.kwargs"))

    while True:
        try:
            await r.ping()
            break
        except redis.exceptions.ConnectionError:
            await LOGGER.ainfo("Waiting for redis")
            await sleep(5)
