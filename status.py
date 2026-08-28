#!/usr/bin/env python3
"""SOCials — System Status (legacy wrapper).

Delegates to the socials package. For the full CLI, use: socials status
"""

from socials.status import show_status

if __name__ == "__main__":
    show_status()
