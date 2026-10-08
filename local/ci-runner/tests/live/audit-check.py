"""Classify audited VM lifetimes from their consoles and audit archives (run as root).

For each tos-ci-vm@N invocation since --since that recorded an admission
verdict, take its serial console from the slot unit's journal and its audit
archive from /var/lib/tos-ci/audit/slotN (the file holding that lifetime's
end marker), then decide:

  validity: auditing came on (console `audit on nonce=<n>`); the console says
            `audit drained` and reports no forwarding or drain failure; the
            archive holds exactly one end marker, bound to that nonce; the
            serials are contiguous from the first record through the marker;
            the status marker before it reports lost=0; the hook's own
            EXECVE is in the stream before the marker; the console has the
            end-of-life record. Anything after the marker is not evidence.
  verdict:  the admission record ("allowed" or "denied", with its run id);
  job-controlled execution: step scripts under the runner's _work/_temp,
            docker, git; none may appear in a denied lifetime, and they must
            appear in an allowed one (positive control).

An invalid lifetime is neither a pass nor a fail of the property; it is
counted as a violation, because it is no evidence. Exit status is the number
of violations.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ARCHIVE = Path("/var/lib/tos-ci/audit")
JOB_EXEC = re.compile(r'(_work/_temp/|"/usr/bin/docker"|exe="/usr/bin/docker"|"/usr/bin/git"|exe="/usr/bin/git")')
ADMISSION = re.compile(r'\{.*"tos_ci_admission": "(allowed|denied)".*\}')
RECORD = re.compile(r"^type=([A-Z_]+) msg=audit\(\d+\.\d+:(\d+)\):")
AUDIT_ON = re.compile(r"audit on nonce=([0-9a-f]{32})")
CONSOLE_FAILURES = ("audit drain timeout", "audit drain failed", "audit-forward failed", "audit unavailable")


def evidence(archive: bytes, nonce: str) -> tuple[list[str], list[str]]:
    """(problems, record lines up to and including the end marker)."""
    # Split on newlines only: auditd's enriched format separates its appended
    # fields with \x1d, which str.splitlines() would treat as a line break.
    lines = archive.decode(errors="replace").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    ends = [i for i, line in enumerate(lines) if "tos-ci-audit-end nonce=" in line]
    if len(ends) != 1:
        return [f"{len(ends)} end markers in the archive"], []
    end = ends[0]
    if f"tos-ci-audit-end nonce={nonce}" not in lines[end]:
        return ["the end marker carries another nonce"], []
    kept = lines[: end + 1]
    problems = []
    serials = set()
    for line in kept:
        match = RECORD.match(line)
        if not match:
            problems.append(f"unparsable archive line: {line[:80]!r}")
            break
        # auditd numbers its own DAEMON_* records from a separate counter;
        # only kernel serials form the sequence that must have no gaps.
        if not match.group(1).startswith("DAEMON_"):
            serials.add(int(match.group(2)))
    marker = RECORD.match(lines[end])
    if marker and serials:
        last, first = int(marker.group(2)), min(serials)
        if max(serials) != last:
            problems.append("records after the end marker's serial precede it")
        missing = (last - first + 1) - len(serials)
        if missing:
            problems.append(f"{missing} audit serials missing between {first} and {last}")
    status = [line for line in kept if "tos-ci-audit-status " in line]
    if len(status) != 1 or "tos-ci-audit-status lost=0 " not in status[0]:
        problems.append("no single status marker reporting lost=0")
    if not any(line.startswith("type=EXECVE") and "admission.py" in line for line in kept):
        problems.append("the hook's execution is not in the audit stream")
    return problems, kept


def console_problems(console: str) -> list[str]:
    problems = [f"console reports '{failure}'" for failure in CONSOLE_FAILURES if failure in console]
    if "audit drained" not in console:
        problems.append("console never reports 'audit drained'")
    if "end-of-life" not in console:
        problems.append("no end-of-life record")
    return problems


def archive_for(slot: int, nonce: str, root: Path = ARCHIVE) -> bytes | None:
    needle = f"tos-ci-audit-end nonce={nonce}".encode()
    for path in sorted((root / f"slot{slot}").glob("*.log")):
        data = path.read_bytes()
        if needle in data:
            return data
    return None


def consoles(since: str) -> dict[tuple[int, str], list[str]]:
    groups: dict[tuple[int, str], list[str]] = defaultdict(list)
    for n in (1, 2, 3):
        out = subprocess.run(
            ["journalctl", "-u", f"tos-ci-vm@{n}", "--since", since, "-o", "json", "--no-pager"],
            capture_output=True, text=True, errors="replace",
        ).stdout
        for line in out.splitlines():
            entry = json.loads(line)
            message = entry.get("MESSAGE") or ""
            if isinstance(message, list):
                message = bytes(message).decode(errors="replace")
            groups[(n, entry.get("_SYSTEMD_INVOCATION_ID", "?"))].append(message)
    return groups


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--since", required=True)
    parser.add_argument("--run", action="append", default=[], help="run ids to report on")
    args = parser.parse_args()
    violations = seen_allowed = seen_denied = 0
    for (slot, invocation), lines in sorted(consoles(args.since).items()):
        console = "\n".join(lines)
        verdicts = [json.loads(m.group(0)) for m in ADMISSION.finditer(console)]
        runs = {v.get("run_id") for v in verdicts}
        if not verdicts or (args.run and not runs & set(args.run)):
            continue
        verdict = verdicts[0]["tos_ci_admission"]
        label = f"slot{slot} {invocation[:8]} run {sorted(runs)} {verdict}"
        problems = console_problems(console)
        on = AUDIT_ON.search(console)
        kept: list[str] = []
        if not on:
            problems.append("auditing was not on")
        else:
            archive = archive_for(slot, on.group(1))
            if archive is None:
                problems.append("no archive holds this lifetime's end marker")
            else:
                found, kept = evidence(archive, on.group(1))
                problems += found
        if problems:
            print(f"INVALID  {label}: {'; '.join(problems)}")
            violations += 1
            continue
        execs = sum(1 for line in kept if line.startswith("type=EXECVE"))
        job_execs = [line for line in kept if JOB_EXEC.search(line) and line.startswith(("type=EXECVE", "type=SYSCALL"))]
        label += f": {execs} execve records"
        if verdict == "denied":
            seen_denied += 1
            if job_execs:
                print(f"FAIL     {label}: job-controlled execution after a denial: {job_execs[0][:200]}")
                violations += 1
            else:
                print(f"PASS     {label}: denied, no job-controlled execution")
        else:
            seen_allowed += 1
            if job_execs:
                print(f"PASS     {label}: allowed, job-controlled execution visible ({len(job_execs)} records)")
            else:
                print(f"FAIL     {label}: allowed but no job-controlled execution was seen; the logger is blind")
                violations += 1
    print(f"lifetimes: {seen_denied} denied, {seen_allowed} allowed; violations: {violations}")
    return violations


if __name__ == "__main__":
    sys.exit(main())
