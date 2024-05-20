from contextlib import asynccontextmanager

from aiopg.sa import create_engine
from vyper import v


@asynccontextmanager
async def db_session():
    async with create_engine(dsn=v.get("database.dsn")) as engine:
        async with engine.acquire() as db:
            try:
                yield db
            finally:
                await db.close()


async def fastapi_get_db():
    async with db_session() as db:
        yield db
