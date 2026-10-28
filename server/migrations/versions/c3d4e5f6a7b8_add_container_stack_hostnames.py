"""Add container.stack and container.hostnames (from Docker/Traefik labels).

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-10-28 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c3d4e5f6a7b8'
down_revision = 'b2c3d4e5f6a7'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('container', schema=None) as batch_op:
        batch_op.add_column(sa.Column('stack', sa.String(length=254), nullable=True))
        batch_op.add_column(sa.Column('hostnames', sa.String(length=512), nullable=True))


def downgrade():
    with op.batch_alter_table('container', schema=None) as batch_op:
        batch_op.drop_column('hostnames')
        batch_op.drop_column('stack')
