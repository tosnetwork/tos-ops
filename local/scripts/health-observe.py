#!/usr/bin/env python3
"""Take one MCP snapshot of every node from the local health stack's query service.

    health-observe.py [--state-dir D]

For each node it issues a short read grant through the control socket, asks
tos_get_node_snapshot for each served component, revokes the grant, and saves
the results as JSON under <state>/observe/, printing `saved <path>`. The query
client comes from the checkout in $TOS_ROOT, or else from the one health-deploy
recorded for this state directory, so a systemd service needs no environment.
"""

from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import os
import sys
import time
from pathlib import Path

HEALTH_ROOT = Path.home() / ".local/state/tos-local-health"
NODES = ("validator1", "validator2", "validator3", "validator4", "observer5", "observer6", "validator7")
COMPONENTS = ("process", "consensus", "storage", "chain", "host")
CLIENT = "tools/node-health-monitor/scripts/sample-query-functional.py"
KEEP = 50


def iso(seconds: float) -> str:
    stamp = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
    return stamp.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def checkout(state: Path) -> Path:
    named = os.environ.get("TOS_ROOT")
    if not named:
        try:
            named = json.loads((state / "deploy.json").read_text())["tos_root"]
        except (OSError, ValueError, KeyError) as error:
            raise SystemExit(f"health-observe: TOS_ROOT is unset and {state / 'deploy.json'} names no checkout ({error})")
    root = Path(named)
    if not (root / CLIENT).is_file():
        raise SystemExit(f"health-observe: {root} has no {CLIENT}")
    return root


def state_dir(given: Path | None) -> Path:
    if given:
        return given.resolve()
    try:
        return HEALTH_ROOT / (HEALTH_ROOT / "active").read_text().strip()
    except OSError:
        raise SystemExit("health-observe: no active stack recorded; pass --state-dir") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--state-dir", type=Path)
    state = state_dir(parser.parse_args(argv).state_dir)
    spec = importlib.util.spec_from_file_location("functional", checkout(state) / CLIENT)
    client = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(client)
    operator = client.private_token(state / "config/query-operator.token")
    service = client.private_token(state / "config/query-service.token")
    control, mcp = str(state / "sockets/control.sock"), str(state / "sockets/mcp.sock")
    rows = []
    for node in NODES:
        leases: list[str] = []
        session = None
        try:
            now = time.time()
            run, token = client.issue(control, operator, node, iso(now - 120), iso(now), leases)
            session = client.McpSession(mcp, service, run, token)
            session.initialize()
            tools = session.call("tools/list", {})
            results = {component: session.snapshot(run, node, iso(now), component) for component in COMPONENTS}
            rows.append({"node": node, "at": iso(now), "tools": [t["name"] for t in tools["tools"]], "results": results})
            print(node, {k: v.get("status") for k, v in results.items()}, flush=True)
        finally:
            if session:
                session.close()
            for lease in leases:
                if lease and not client.revoke(control, operator, lease):
                    raise RuntimeError("grant revoke failed")
    out_dir = state / "observe"
    out_dir.mkdir(mode=0o700, exist_ok=True)
    out = out_dir / f"mcp-{int(time.time())}.json"
    out.write_text(json.dumps(rows, indent=2) + "\n")
    for old in sorted(out_dir.glob("mcp-*.json"))[:-KEEP]:
        old.unlink()
    print("saved", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
