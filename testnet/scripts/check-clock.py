#!/usr/bin/env python3
"""Check that this host's clock is disciplined by NTP now; exit 1 when it is not.

  check-clock.py [--max-offset-ms 100] [--json] [--quiet]

Every validator keeps its clock disciplined by NTP at all times: consensus reads
the local clock (a candidate is validated no earlier than 300 ms after its
parent, slots target 400 ms). All testnet times are UTC; the host may keep any
time zone setting, since the kernel clock and NTP are UTC whatever the zone.

Passes only when all of these hold:

  * the kernel reports NTPSynchronized=yes (`timedatectl`);
  * ntpsec (ntpd, which setup-time.sh installs) or chrony answers and has a
    selected source (`ntpq -pn` line starting "*", `chronyc -n sources` "^*");
  * the selected source's offset is within --max-offset-ms (default 100 ms).

Prints one line, `clock ok: ...` or `clock NOT OK: ...` (with --json the facts
as JSON; with --quiet nothing when it passes), and exits 0 or 1. Standard
library only; it reads nothing but those three commands. Run it every day, and
from cron or a timer so a failure reaches you (OPERATOR.md, "Clock").
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


def host_checks():
    """check-host-disk.py beside this file: the clock readers live there, because
    the coordinator pipes that one file to team hosts."""
    path = Path(__file__).resolve().with_name("check-host-disk.py")
    spec = importlib.util.spec_from_file_location("check_host_disk", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(argv: list[str] | None = None, facts: dict | None = None) -> int:
    checks = host_checks()
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--max-offset-ms", type=float, default=checks.MAX_CLOCK_OFFSET_MS)
    parser.add_argument("--json", action="store_true", help="print the facts as JSON")
    parser.add_argument("--quiet", action="store_true", help="print nothing when it passes")
    args = parser.parse_args(argv)
    if not 0 < args.max_offset_ms <= 1000:
        parser.error("--max-offset-ms must be above 0 and at most 1000")
    facts = checks.clock_facts() if facts is None else facts
    problems = checks.clock_problems(facts, args.max_offset_ms)
    if args.json:
        print(json.dumps(dict(facts, ok=not problems, problems=problems)))
    elif problems:
        print("clock NOT OK: " + "; ".join(problems))
    elif not args.quiet:
        print(
            f"clock ok: {facts['clock_daemon']} with {facts['clock_sources']} selected source, "
            f"offset {facts['clock_offset_ms']:+.3f} ms (limit {args.max_offset_ms:g} ms), "
            "NTPSynchronized=yes"
        )
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
