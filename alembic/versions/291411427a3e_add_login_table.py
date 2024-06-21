"""Add login table

Revision ID: 291411427a3e
Revises: 12de07b8d683
Create Date: 2024-06-03 10:51:27.635619

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '291411427a3e'
down_revision: Union[str, None] = '12de07b8d683'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    op.create_table('logins',
    sa.Column('login_id', sa.Integer(), nullable=False),
    sa.Column('user', sa.Integer(), nullable=True),
    sa.Column('portal_name', sa.String(length=200), nullable=True),
    sa.Column('login_name', sa.String(length=50), nullable=True),
    sa.Column('login_password', sa.LargeBinary(), nullable=True),
    sa.ForeignKeyConstraint(['users'], ['users.user_id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('user_id')
    )


def downgrade():
    op.drop_table('logins')
