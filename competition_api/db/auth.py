import secrets
from typing import Any
from uuid import UUID, uuid4

import argon2
from aiopg.sa import SAConnection
from sqlalchemy import String, Uuid, insert, select, update
from sqlalchemy.orm import Mapped, mapped_column
from structlog.stdlib import get_logger

from competition_api.db.common import Base

GENERATED_TOKEN_LEN = 32
HASHER = argon2.PasswordHasher()
LOGGER = get_logger(__name__)


class Token(Base):
    __tablename__ = "token"

    id: Mapped[UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid4
    )  # pylint: disable=redefined-builtin
    token: Mapped[str] = mapped_column("token", String, nullable=True)

    @classmethod
    async def create(
        cls, db: SAConnection, token_id: UUID | None = None, token: str | None = None
    ) -> tuple[UUID, str]:
        token = (
            token if token is not None else secrets.token_urlsafe(GENERATED_TOKEN_LEN)
        )
        values: dict[str, Any] = {"token": HASHER.hash(token)}

        if token_id:
            values["id"] = token_id

        db_token_id = await db.execute(insert(cls).values(**values).returning(cls.id))
        db_token_id = await db_token_id.fetchone()

        return db_token_id.id, token

    @classmethod
    async def update(
        cls, db: SAConnection, token_id: UUID, token: str | None = None
    ) -> tuple[UUID, str]:
        token = (
            token if token is not None else secrets.token_urlsafe(GENERATED_TOKEN_LEN)
        )
        values = {"token": HASHER.hash(token)}

        await db.execute(update(cls).values(**values))

        return token_id, token

    @classmethod
    async def verify(cls, db: SAConnection, token_id: UUID, token: str) -> bool:
        await LOGGER.adebug("Verifying token for %s", token_id)

        result = await db.execute(select(cls.token).where(cls.id == token_id))
        result = await result.fetchall()

        if len(result) == 0:
            await LOGGER.adebug("No such id: %s", token_id)
            return False

        try:
            HASHER.verify(result[0][0], token)
            await LOGGER.adebug("Successful auth for %s", token_id)
            return True
        except argon2.exceptions.VerifyMismatchError:
            await LOGGER.adebug("Invalid token for id %s", token_id)
            return False
