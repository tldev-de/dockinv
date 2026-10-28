"""Add image.scan_error_trivy / scan_error_xeol (last scanner failure).

Lets the UI show "scan failed: …" instead of conflating a failed scan with
"never scanned". NULL means the last run of that scanner succeeded (or never ran).

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-10-28 21:30:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a7b8c9d0e1f2'
down_revision = 'f6a7b8c9d0e1'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('image', schema=None) as batch_op:
        batch_op.add_column(sa.Column('scan_error_trivy', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('scan_error_xeol', sa.Text(), nullable=True))


def downgrade():
    with op.batch_alter_table('image', schema=None) as batch_op:
        batch_op.drop_column('scan_error_xeol')
        batch_op.drop_column('scan_error_trivy')
