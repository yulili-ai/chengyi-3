"""Add email users, verification codes, auth sessions and project ownership."""
from alembic import op
import sqlalchemy as sa


revision = "f6c1a2b8d401"
down_revision = "d64fb2231c10"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_login_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("email", name="uq_users_email"))
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table("email_verification_codes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("code_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("consumed_at", sa.DateTime(), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False))
    op.create_index("ix_email_verification_codes_email", "email_verification_codes", ["email"])

    op.create_table("auth_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("token_hash", name="uq_auth_sessions_token_hash"))
    op.create_index("ix_auth_sessions_user_id", "auth_sessions", ["user_id"])

    with op.batch_alter_table("pottery_projects") as batch:
        batch.add_column(sa.Column("owner_user_id", sa.String(36), nullable=True))
        batch.create_foreign_key("fk_pottery_projects_owner_user_id", "users",
                                 ["owner_user_id"], ["id"])
        batch.create_index("ix_pottery_projects_owner_user_id", ["owner_user_id"])


def downgrade():
    with op.batch_alter_table("pottery_projects") as batch:
        batch.drop_index("ix_pottery_projects_owner_user_id")
        batch.drop_constraint("fk_pottery_projects_owner_user_id", type_="foreignkey")
        batch.drop_column("owner_user_id")
    op.drop_index("ix_auth_sessions_user_id", table_name="auth_sessions")
    op.drop_table("auth_sessions")
    op.drop_index("ix_email_verification_codes_email", table_name="email_verification_codes")
    op.drop_table("email_verification_codes")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
