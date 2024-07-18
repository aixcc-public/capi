import asyncio
import os

import redis
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


async def create_worker_redis_creds():
    r = redis.Redis(**v.get("redis.kwargs"))

    while True:
        try:
            await LOGGER.ainfo("Waiting for redis")
            r.ping()
            break
        except redis.exceptions.ConnectionError:
            await asyncio.sleep(5)

    for worker in v.get("workers"):
        path = os.path.join("/etc/capi/workers", f"{worker}.env")
        if not os.path.isfile(path):
            raise RuntimeError(f"Missing worker config for {worker}")

        envs: dict[str, str] = {}
        with open(path, "r", encoding="utf8") as envfile:
            for line in envfile:
                key, val = line.split("=")
                envs[key] = val

        redis_user = envs.get("AIXCC_REDIS_USERNAME")
        redis_pass = envs.get("AIXCC_REDIS_PASSWORD")

        if not all([redis_user, redis_pass]):
            raise RuntimeError(f"Not all worker config is set for {worker}")

        await LOGGER.ainfo("Creating redis creds for %s: user %s", worker, redis_user)
        r.execute_command(
            "ACL SETUSER "
            f"{redis_user} >{redis_pass} on "
            f"+@read ~arq:*{worker}* "
            f"+@write ~arq:*{worker}* "
            "+@write ~arq:abort "
            "+publish ~channel:audit "
            "+publish ~channel:results "
            "+@transaction +@connection +info"
        )


async def prestart():
    async with asyncio.TaskGroup() as tg:
        tg.create_task(auth_preload())
        tg.create_task(create_worker_redis_creds())


def main():
    init_vyper()
    v.set_default("auth.preload", {})
    asyncio.run(prestart())
