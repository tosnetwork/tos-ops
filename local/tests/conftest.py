"""Shared setup: the drivers import their siblings and tos modules.

Use the prepared tos environment plus the hash-locked test requirements in the
repository README. Run from the tos-ops root so uv does not resync away those
extra dependencies:

    TOS_ROOT="$TOS_ROOT" "$TOS_ROOT/.venv/bin/python" -m pytest local/tests
"""

import os
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"

if not os.environ.get("TOS_ROOT"):
    raise SystemExit("set TOS_ROOT to the tos checkout before running these tests")
sys.path.insert(0, str(SCRIPTS))
