from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from vyper import v


@asynccontextmanager
async def db_session():
    engine = create_async_engine(url=v.get("database.url"))
    session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)()
    try:
        session.begin_nested()  # this automatically rolls back on exception
        yield session
        await session.commit()
    finally:
        await session.close()


async def fastapi_get_db():
    async with db_session() as db:
        yield db
