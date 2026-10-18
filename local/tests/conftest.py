"""Shared setup: the drivers import their siblings and tos modules.

Run from the tos checkout's uv environment with TOS_ROOT set, for example:

    cd "$TOS_ROOT" && TOS_ROOT="$TOS_ROOT" uv run python -m pytest <tos-ops>/local/tests
"""

import os
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"

if not os.environ.get("TOS_ROOT"):
    raise SystemExit("set TOS_ROOT to the tos checkout before running these tests")
sys.path.insert(0, str(SCRIPTS))
