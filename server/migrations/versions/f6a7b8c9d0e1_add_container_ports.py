"""Add container.ports (published host ports, for exposure detection).

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-10-28 13:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f6a7b8c9d0e1'
down_revision = 'e5f6a7b8c9d0'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('container', schema=None) as batch_op:
        batch_op.add_column(sa.Column('ports', sa.String(length=512), nullable=True))


def downgrade():
    with op.batch_alter_table('container', schema=None) as batch_op:
        batch_op.drop_column('ports')
