#!/usr/bin/env python3
"""Read-only liveness check for persistent local PQ elections and their candidate wallets."""

import argparse
import json
import subprocess
import time
from pathlib import Path

WALLET_OBSERVATION_MAX_AGE = 600


def check(directory, now=None):
    now = time.time() if now is None else now
    errors, warnings = [], []
    try:
        status = json.loads((directory / "status.json").read_text())
        if not status.get("healthy"):
            errors.append("election driver reports a failure")
        if not 0 <= now - status["at"] <= 180:
            errors.append("election driver heartbeat is stale or in the future")
        since = status.get("activation_since")
        if since is not None:
            activation = json.loads((directory / f"activation-{since}.json").read_text())
            if activation["config34"]["utime_until"] <= now:
                errors.append(
                    "Config34 expired without a new observed activation; key-block/GC risk"
                )
        for index in (1, 2, 3, 4, 7):
            # The driver observes each candidate's staking wallet about once a
            # minute while it asks the elector for returned stakes.
            row = json.loads((directory / f"wallet-{index}.json").read_text())
            if not row.get("deployed"):
                errors.append(f"candidate {index} staking wallet is not deployed")
            if not 0 <= now - row["checked_at"] <= WALLET_OBSERVATION_MAX_AGE:
                errors.append(f"candidate {index} staking wallet observation is stale")
    except (OSError, ValueError, KeyError, TypeError) as error:
        errors.append(f"missing or invalid election evidence: {error}")
    return dict(
        healthy=not errors,
        errors=errors,
        warnings=warnings,
        note="persistent elections drive key blocks; do not leave a stopped driver unnoticed",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("/data"))
    args = parser.parse_args()
    result = check(args.data / "elections")
    state = subprocess.run(["systemctl", "is-active", "--quiet", "tos-pq-elections"], check=False)
    if state.returncode:
        result["healthy"] = False
        result["errors"].append("tos-pq-elections is not active")
    print(json.dumps(result))
    return 0 if result["healthy"] and not result["warnings"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
