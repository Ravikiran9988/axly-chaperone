"""Administrative bootstrap CLI utilities for AXLY Chaperone."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os

from sqlalchemy import select

from app.core.config import get_settings
from app.core.database import build_engine, build_session_factory
from app.core.security import generate_admin_bootstrap_key, hash_password
from app.models.admin import AdminUser
from app.models.enums import AdminRole, AdminStatus


async def _create_admin_user_async(username: str, password: str, role: AdminRole) -> None:
    settings = get_settings()
    engine = build_engine(settings.database_url)
    session_factory = build_session_factory(engine)
    try:
        async with session_factory() as session:
            existing = (
                await session.execute(select(AdminUser).where(AdminUser.username == username))
            ).scalar_one_or_none()
            if existing is not None:
                raise SystemExit(f"Admin user '{username}' already exists.")
            user = AdminUser(
                username=username,
                password_hash=hash_password(
                    password,
                    iterations=settings.api_key_hash_iterations,
                    pepper=settings.get_api_key_pepper(),
                ),
                role=role.value,
                status=AdminStatus.ACTIVE.value,
            )
            session.add(user)
            await session.commit()
            print(f"Created admin user '{username}' with role '{role.value}'.")
    finally:
        await engine.dispose()


def main() -> None:
    """CLI entry point for generating bootstrap keys and administrator accounts."""
    parser = argparse.ArgumentParser(description="AXLY Chaperone administrative utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "generate-admin-key",
        help="Generate a cryptographically random CHAPERONE_ADMIN_API_KEY value.",
    )
    user_parser = subparsers.add_parser(
        "create-admin-user",
        help="Create an individual administrator account in the database.",
    )
    user_parser.add_argument("--username", required=True, help="Unique admin username (2-64 chars).")
    user_parser.add_argument(
        "--role",
        choices=[r.value for r in AdminRole],
        default=AdminRole.SUPER_ADMIN.value,
        help="RBAC role assigned to the administrator account.",
    )
    user_parser.add_argument(
        "--password",
        default=None,
        help="Optional password (prefer CHAPERONE_NEW_ADMIN_PASSWORD env or interactive prompt).",
    )

    args = parser.parse_args()
    if args.command == "generate-admin-key":
        print(generate_admin_bootstrap_key())
    elif args.command == "create-admin-user":
        raw_pw = args.password or os.environ.get("CHAPERONE_NEW_ADMIN_PASSWORD")
        if not raw_pw:
            raw_pw = getpass.getpass(f"Password for {args.username} (min 12 chars): ")
        if len(raw_pw) < 12:
            raise SystemExit("Administrator password must be at least 12 characters.")
        asyncio.run(_create_admin_user_async(args.username.strip(), raw_pw, AdminRole(args.role)))


if __name__ == "__main__":
    main()
