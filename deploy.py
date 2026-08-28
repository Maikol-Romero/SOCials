#!/usr/bin/env python3
"""SOCials — Deploy Generator (legacy wrapper).

Delegates to the socials package. For the full CLI, use:
  socials generate       Generate configs from inventory
  socials diff           Show config differences
  socials deploy-otel    Deploy OTEL configs to all machines
"""

import sys

from socials.utils import C, error
from socials.generate import run_generate, run_diff, run_deploy_otel


def main():
    if len(sys.argv) < 2:
        print(f"""
{C.CYAN}{C.BOLD}  SOCials — Deploy Generator{C.NC}

  Usage:
    python3 deploy.py {C.BOLD}generate{C.NC}      Generate prometheus.yml and homepage services.yaml
    python3 deploy.py {C.BOLD}diff{C.NC}           Show differences with current configs
    python3 deploy.py {C.BOLD}deploy-otel{C.NC}    Deploy OTEL config to all machines

  Tip: use the unified CLI instead: {C.BOLD}socials generate{C.NC}
""")
        return

    cmd = sys.argv[1].lower()

    if cmd == "generate":
        run_generate()
    elif cmd == "diff":
        run_diff()
    elif cmd == "deploy-otel":
        run_deploy_otel()
    else:
        error(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
