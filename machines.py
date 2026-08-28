#!/usr/bin/env python3
"""SOCials — Machine Manager (legacy wrapper).

Delegates to the socials package. For the full CLI, use:
  socials machines list|add|remove
  socials deploy <name>
  socials deploy-db <name>
  socials warden-enroll <name>
"""

import sys

from socials.utils import C, error, ask
from socials import inventory
from socials.machines import (
    list_machines, add_machine, remove_machine,
    deploy_to_machine, deploy_db,
)
from socials.warden import enroll as socialwarden_enroll


def main():
    if len(sys.argv) < 2:
        print(f"""
{C.CYAN}{C.BOLD}  SOCials — Machine Manager{C.NC}

  Usage:
    python3 machines.py {C.BOLD}list{C.NC}                         List registered machines
    python3 machines.py {C.BOLD}add{C.NC}                          Add machine (interactive)
    python3 machines.py {C.BOLD}remove{C.NC}                       Remove machine
    python3 machines.py {C.BOLD}deploy{C.NC} <name>                Deploy SOC agents
    python3 machines.py {C.BOLD}deploy-db{C.NC} <name>             Deploy database (PG/MySQL/MariaDB)
    python3 machines.py {C.BOLD}socialwarden-enroll{C.NC} <name>   Install socialwarden-agent

  Tip: use the unified CLI instead: {C.BOLD}socials machines list{C.NC}
""")
        return

    cmd = sys.argv[1].lower()

    def _dispatch():
        if cmd == "list":
            list_machines()
        elif cmd == "add":
            add_machine()
        elif cmd == "remove":
            remove_machine()
        elif cmd == "deploy":
            name = sys.argv[2] if len(sys.argv) >= 3 else ask("Machine name: ")
            deploy_to_machine(name)
        elif cmd == "deploy-db":
            name = sys.argv[2] if len(sys.argv) >= 3 else ask("Machine name: ")
            deploy_db(name)
        elif cmd in ("socialwarden-enroll", "enroll"):
            args = sys.argv[2:]
            no_restart = "--no-restart" in args
            force = "--force" in args
            name_args = [a for a in args if not a.startswith("--")]
            name = name_args[0] if name_args else ask("Machine name: ")
            socialwarden_enroll(name, no_restart=no_restart, force=force)
        else:
            error(f"Unknown command: {cmd}")

    if cmd == "list":
        _dispatch()
    else:
        with inventory.lock():
            _dispatch()


if __name__ == "__main__":
    main()
