import asyncio

from structlog.stdlib import get_logger

from competition_api.audit import get_auditor
from competition_api.config import init_vyper
from competition_api.tasks.results import ResultReceiver

LOGGER = get_logger()


async def background():
    await asyncio.gather(
        get_auditor().listen_for_worker_events(),
        ResultReceiver().listen_for_worker_events(),
    )


def main():
    init_vyper()
    asyncio.run(background())
