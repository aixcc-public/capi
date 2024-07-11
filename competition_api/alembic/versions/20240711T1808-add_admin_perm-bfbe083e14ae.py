"""Add admin perm

Revision ID: bfbe083e14ae
Revises: ba5ffed4c3b9
Create Date: 2024-07-11 18:08:23.921412

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "bfbe083e14ae"
down_revision: Union[str, None] = "ba5ffed4c3b9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("token", sa.Column("admin", sa.Boolean(), nullable=False))


def downgrade() -> None:
    op.drop_column("token", "admin")
