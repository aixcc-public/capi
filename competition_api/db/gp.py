from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import sqlalchemy
from sqlalchemy import Boolean, ForeignKey, LargeBinary, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from competition_api.db.common import Base
from competition_api.db.vds import TABLENAME as vds_tablename
from competition_api.models.types import FeedbackStatus

if TYPE_CHECKING:
    from competition_api.db.vds import VulnerabilityDiscovery


class GeneratedPatch(Base):
    __tablename__ = "generated_patch"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)

    cpv_uuid: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey(f"{vds_tablename}.cpv_uuid"), nullable=False
    )
    data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # scoring
    patch_applied: Mapped[bool] = mapped_column(Boolean, nullable=True)
    sanitizer_did_not_fire: Mapped[bool] = mapped_column(Boolean, nullable=True)
    functional_tests_passed: Mapped[bool] = mapped_column(Boolean, nullable=True)

    status: Mapped[FeedbackStatus] = mapped_column(
        sqlalchemy.Enum(FeedbackStatus, native_enum=False),
        default=FeedbackStatus.PENDING,
    )

    vds: Mapped["VulnerabilityDiscovery"] = (  # noqa: F821 # sqlalchemy resolves this
        relationship(back_populates="gp", lazy="joined")
    )

    def __repr__(self):
        return f"GeneratedPatch<{len(self.data)} bytes>"

    def __str__(self):
        return repr(self)
