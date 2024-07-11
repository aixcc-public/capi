import asyncio

from sqlalchemy_dlock.asyncio import create_async_sadlock
from structlog.stdlib import get_logger
from vyper import v

from competition_api.config import init_vyper
from competition_api.db import Token
from competition_api.db.session import db_session

LOGGER = get_logger()


async def auth_preload():
    async with db_session() as db:
        async with create_async_sadlock(db, "user_preload"):
            for token_id, token in v.get("auth.preload").items():
                await LOGGER.ainfo("Preloading auth for %s", token_id)
                kwargs = {"token_id": token_id, "token": token}

                if token_id in v.get("auth.admins"):
                    await LOGGER.awarning("Inserting %s as admin", token_id)
                    kwargs["admin"] = True

                await Token.upsert(db, **kwargs)


def main():
    init_vyper()
    v.set_default("auth.preload", {})
    asyncio.run(auth_preload())
