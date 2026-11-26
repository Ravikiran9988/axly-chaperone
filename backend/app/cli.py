"""Administrative bootstrap CLI utilities for AXLY Chaperone."""

from __future__ import annotations

import argparse

from app.core.security import generate_admin_bootstrap_key


def main() -> None:
    """CLI entry point for generating secure bootstrap configuration secrets."""
    parser = argparse.ArgumentParser(description="AXLY Chaperone administrative utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "generate-admin-key",
        help="Generate a cryptographically random CHAPERONE_ADMIN_API_KEY value.",
    )

    args = parser.parse_args()
    if args.command == "generate-admin-key":
        print(generate_admin_bootstrap_key())


if __name__ == "__main__":
    main()
