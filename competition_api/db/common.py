from sqlalchemy import insert
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    @classmethod
    def insert_returning(cls, returning=None, **row):
        returning = returning or [cls.id, cls.status]  # pylint: disable=no-member
        return insert(cls).values(**row).returning(*returning)
