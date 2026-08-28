"""Shared test setup: make the src/ package importable without an install.

The suite imports the real icloud_mcp modules and monkeypatches the network
clients (IMAP/SMTP/CalDAV). Nothing here touches Apple or any socket.
"""

import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
