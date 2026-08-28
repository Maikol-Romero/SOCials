"""SOCials unified CLI — one command to rule them all.

Usage:
  socials status           System-wide health overview
  socials machines list    List registered machines
  socials machines add     Add a production machine (interactive)
  socials machines remove  Remove a machine (interactive)
  socials deploy <name>    Deploy SOC agents to a machine
  socials generate         Generate configs from inventory.json
  socials diff             Show differences with current configs
  socials deploy-otel [name]    Deploy OTEL configs to machines
  socials warden-enroll <name>  Enroll socialwarden agent on a machine
  socials version          Show version
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .utils import C, error, section


def cmd_version(_args: argparse.Namespace) -> None:
    print(f"SOCials v{__version__}")


def cmd_status(_args: argparse.Namespace) -> None:
    from .status import show_status
    show_status()


def cmd_machines(args: argparse.Namespace) -> None:
    from .machines import list_machines, add_machine, remove_machine

    action = getattr(args, "action", None)
    if action == "list" or action is None:
        list_machines()
    elif action == "add":
        add_machine()
    elif action == "remove":
        remove_machine()
    else:
        error(f"Unknown machines action: {action}")


def cmd_deploy(args: argparse.Namespace) -> None:
    from .machines import deploy_to_machine
    deploy_to_machine(args.name)


def cmd_deploy_db(args: argparse.Namespace) -> None:
    from .machines import deploy_db
    deploy_db(args.name)


def cmd_generate(_args: argparse.Namespace) -> None:
    from .generate import run_generate
    run_generate()


def cmd_diff(_args: argparse.Namespace) -> None:
    from .generate import run_diff
    run_diff()


def cmd_deploy_otel(args: argparse.Namespace) -> None:
    from .generate import run_deploy_otel
    run_deploy_otel(getattr(args, "name", None))


def cmd_warden(args: argparse.Namespace) -> None:
    from .warden import enroll
    enroll(args.name, no_restart=args.no_restart, force=args.force)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="socials",
        description="SOCials — Self-hosted SOC + observability stack",
    )
    parser.add_argument(
        "--version", action="version", version=f"SOCials v{__version__}"
    )
    sub = parser.add_subparsers(dest="command")

    # socials status
    p_status = sub.add_parser("status", help="System-wide health overview")
    p_status.set_defaults(func=cmd_status)

    # socials machines [list|add|remove]
    p_machines = sub.add_parser("machines", help="Manage fleet machines")
    p_machines.add_argument(
        "action", nargs="?", default="list",
        choices=["list", "add", "remove"],
        help="Action to perform (default: list)",
    )
    p_machines.set_defaults(func=cmd_machines)

    # socials deploy <name>
    p_deploy = sub.add_parser("deploy", help="Deploy SOC agents to a machine")
    p_deploy.add_argument("name", help="Machine name from inventory")
    p_deploy.set_defaults(func=cmd_deploy)

    # socials deploy-db <name>
    p_deploy_db = sub.add_parser("deploy-db", help="Deploy database to a machine")
    p_deploy_db.add_argument("name", help="Machine name from inventory")
    p_deploy_db.set_defaults(func=cmd_deploy_db)

    # socials generate
    p_gen = sub.add_parser("generate", help="Generate configs from inventory")
    p_gen.set_defaults(func=cmd_generate)

    # socials diff
    p_diff = sub.add_parser("diff", help="Show config differences")
    p_diff.set_defaults(func=cmd_diff)

    # socials deploy-otel [name]
    p_otel = sub.add_parser("deploy-otel", help="Deploy OTEL configs to fleet machines")
    p_otel.add_argument("name", nargs="?", default=None, help="Target machine (all if omitted)")
    p_otel.set_defaults(func=cmd_deploy_otel)

    # socials warden-enroll <name>
    p_warden = sub.add_parser("warden-enroll", help="Enroll socialwarden agent on a machine")
    p_warden.add_argument("name", help="Machine name from inventory")
    p_warden.add_argument("--no-restart", action="store_true", help="Skip service restart after install")
    p_warden.add_argument("--force", action="store_true", help="Reinstall even if same version present")
    p_warden.set_defaults(func=cmd_warden)

    # socials version
    p_ver = sub.add_parser("version", help="Show version")
    p_ver.set_defaults(func=cmd_version)

    return parser


BANNER = f"""{C.CYAN}{C.BOLD}
  ███████╗ ██████╗  ██████╗██╗ █████╗ ██╗     ███████╗
  ██╔════╝██╔═══██╗██╔════╝██║██╔══██╗██║     ██╔════╝
  ███████╗██║   ██║██║     ██║███████║██║     ███████╗
  ╚════██║██║   ██║██║     ██║██╔══██║██║     ╚════██║
  ███████║╚██████╔╝╚██████╗██║██║  ██║███████╗███████║
  ╚══════╝ ╚═════╝  ╚═════╝╚═╝╚═╝  ╚═╝╚══════╝╚══════╝
{C.NC}  v{__version__} — Self-hosted SOC + observability stack
"""


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        print(BANNER)
        parser.print_help()
        sys.exit(0)

    func = getattr(args, "func", None)
    if func:
        func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
