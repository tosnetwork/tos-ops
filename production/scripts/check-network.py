#!/usr/bin/env python3
"""Check independent HTTP nodes against an explicitly held network identity.

No node keys, SSH or writes. The proof library is the existing consensus core;
its HTTP transport is provided here. Missing routes are reported as weaker
agreement; malformed or invalid proofs never fall back to agreement.
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from network_check import check_network  # noqa: E402


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--global-config", type=Path, required=True)
    p.add_argument("--global-id", type=int, required=True)
    p.add_argument("--rpc", action="append", required=True)
    p.add_argument("--max-age", type=int, default=120)
    p.add_argument("--min-version", type=int, default=16)
    p.add_argument("--expected-auth-tag")
    p.add_argument("--expected-cp48-hash")
    default = (
        Path(os.environ["TOS_ROOT"]) / "build/lite-client/proof-verify/libtosproofverify.so"
        if os.environ.get("TOS_ROOT")
        else None
    )
    p.add_argument("--proof-library", type=Path, default=default)
    a = p.parse_args(argv)
    if not 1 <= a.max_age <= 604800 or a.min_version < 0:
        p.error("max-age must be 1..604800 and min-version nonnegative")
    result = check_network(a)
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
