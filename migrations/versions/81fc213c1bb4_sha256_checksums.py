"""sha256 checksums

Revision ID: 81fc213c1bb4
Revises: 4162eecef2d0
Create Date: 2018-06-20 17:14:20.330524

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '81fc213c1bb4'
down_revision = '4162eecef2d0'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('certificates', sa.Column('cert_sha256', sa.String(length=64), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('certificates', 'cert_sha256')
    # ### end Alembic commands ###
