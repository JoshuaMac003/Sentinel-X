"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-09-08

"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Development bootstrap also uses Base.metadata.create_all.
    # This revision documents the Review 1 schema for Alembic workflows.
    bind = op.get_bind()
    from app.database.base import Base
    import app.models  # noqa: F401

    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    bind = op.get_bind()
    from app.database.base import Base
    import app.models  # noqa: F401

    Base.metadata.drop_all(bind=bind)
