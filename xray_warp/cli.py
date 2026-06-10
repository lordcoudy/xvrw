from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .core import (
    Runner,
    XrayWarpError,
    build_vless_link,
    load_state,
    local_port_warning,
    run_add_user,
    run_install,
    status_report,
    user_by_name,
    validate_name,
    validate_server,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xray-warp",
        description="Install and manage Xray Reality Vision over WARP.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    install = subparsers.add_parser("install", help="Install Xray, WARP, and first user")
    install.add_argument("--server", required=True, type=validate_server)
    install.add_argument("--client", required=True, type=validate_name)

    add_user = subparsers.add_parser("add-user", help="Add a VLESS user")
    add_user.add_argument("--name", required=True, type=validate_name)

    list_users = subparsers.add_parser("list-users", help="List configured users")
    list_users.add_argument("--json", action="store_true", help="Print raw JSON")

    show_link = subparsers.add_parser("show-link", help="Print a user VLESS link")
    show_link.add_argument("--name", required=True, type=validate_name)

    subparsers.add_parser("status", help="Check Xray and wgcf status")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    runner = Runner()
    try:
        if args.command == "install":
            link = run_install(args.server, args.client, runner)
            print(link)
            warning = local_port_warning(load_state())
            if warning:
                print(warning, file=sys.stderr)
            return 0

        if args.command == "add-user":
            link = run_add_user(args.name, runner)
            print(link)
            warning = local_port_warning(load_state())
            if warning:
                print(warning, file=sys.stderr)
            return 0

        if args.command == "list-users":
            state = load_state()
            users = state.get("users", [])
            if args.json:
                print(json.dumps(users, indent=2, ensure_ascii=False))
            else:
                for user in users:
                    print(f"{user['name']}\t{user['uuid']}")
            return 0

        if args.command == "show-link":
            state = load_state()
            print(build_vless_link(state, user_by_name(state, args.name)))
            return 0

        if args.command == "status":
            print(json.dumps(status_report(runner), indent=2))
            return 0

        parser.error("unknown command")
        return 2
    except XrayWarpError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
