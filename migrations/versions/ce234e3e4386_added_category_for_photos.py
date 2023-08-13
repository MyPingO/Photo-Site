"""added category for photos

Revision ID: ce234e3e4386
Revises: 
Create Date: 2023-08-12 22:37:48.725346

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ce234e3e4386'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('photo', sa.Column('category', sa.String(length=80), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('photo', 'category')
    # ### end Alembic commands ###