#!/usr/bin/env python3
"""Check that this host's clock is disciplined by NTP now; exit 1 when it is not.

  check-clock.py [--max-offset-ms 100] [--boot-grace SECONDS] [--json] [--quiet]

Every validator keeps its clock disciplined by NTP at all times. Consensus reads
the local clock: a validator validates a candidate no earlier than 300 ms after
its parent's generation time by its own clock, so a clock behind NTP delays its
votes by the offset, and a leader whose clock is ahead gives its candidates
future timestamps that the other validators hold until their own clocks reach
them (refusing them beyond 30 s). All testnet times are UTC; the host may keep
any time zone setting, since the kernel clock and NTP are UTC whatever the zone.

The supported discipline is ntpsec, installed and configured by setup-time.sh
(which disables chrony and systemd-timesyncd). Passes only when all of these hold:

  * the kernel reports NTPSynchronized=yes (`timedatectl`);
  * ntpd answers and has a selected source (an `ntpq -pn` line starting "*");
  * the system clock offset (`ntpq -c "rv 0 offset"`, not one peer's last
    sample) is within --max-offset-ms (default 100 ms). Offsets are local clock
    minus NTP time: positive = local clock ahead.

Prints one line, `clock ok: ...` or `clock NOT OK: ...` (with --json the facts
as JSON; with --quiet nothing when it passes), and exits 0 or 1. With
--boot-grace N it passes, saying so, while the host has been up less than N
seconds: ntpd needs a few minutes after a boot to select a source, so the cron
alarm (OPERATOR.md, section 2) does not fire for that. Standard library only.

It gates the first `install-node.sh activate --role validator` and every
`enable-elections.sh`; it does not gate a service restart or a reboot, which
must not wait on NTP. The daily check, the cron alarm and the coordinator's
watch cover the clock from then on.
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


def uptime_seconds(path: Path = Path("/proc/uptime")) -> float | None:
    try:
        return float(path.read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def main(argv: list[str] | None = None, facts: dict | None = None, uptime=uptime_seconds) -> int:
    checks = host_checks()
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--max-offset-ms", type=float, default=checks.MAX_CLOCK_OFFSET_MS)
    parser.add_argument(
        "--boot-grace", type=float, default=0.0, help="pass while up less than this many seconds"
    )
    parser.add_argument("--json", action="store_true", help="print the facts as JSON")
    parser.add_argument("--quiet", action="store_true", help="print nothing when it passes")
    args = parser.parse_args(argv)
    if not 0 < args.max_offset_ms <= 1000:
        parser.error("--max-offset-ms must be above 0 and at most 1000")
    if not 0 <= args.boot_grace <= 3600:
        parser.error("--boot-grace must be between 0 and 3600 seconds")
    if args.boot_grace:
        up = uptime()
        if up is not None and up < args.boot_grace:
            if not args.quiet:
                print(
                    f"clock check skipped: up {up:.0f} s, within --boot-grace {args.boot_grace:g} s"
                )
            return 0
    facts = checks.clock_facts() if facts is None else facts
    problems = checks.clock_problems(facts, args.max_offset_ms)
    if args.json:
        print(json.dumps(dict(facts, ok=not problems, problems=problems)))
    elif problems:
        print("clock NOT OK: " + "; ".join(problems))
    elif not args.quiet:
        print(
            f"clock ok: {facts['clock_daemon']} with {facts['clock_sources']} selected source, "
            f"offset {facts['clock_offset_ms']:+.3f} ms (local minus NTP, limit "
            f"{args.max_offset_ms:g} ms), NTPSynchronized=yes"
        )
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
