"""Classify audited VM lifetimes from their consoles and audit archives (run as root).

Every tos-ci-vm@N invocation since --since is reported. Its serial console
comes from the slot unit's journal and its audit archive from
/var/lib/tos-ci/audit/slotN (the file holding that lifetime's end marker).

Validity (otherwise INVALID, which is no evidence and counts as a violation):
  the console shows `audit on nonce=<n>`, `audit drained` and the end-of-life
  record, and no forwarding, drain or availability failure; the archive holds
  exactly one end marker and one status marker, each a complete,
  newline-terminated auditctl USER record, the end marker bound to the nonce
  and the status reporting lost=0; kernel serials are contiguous from the
  first record through the end marker; the hook's own execution is recorded.
  Anything after the end marker is not evidence.

Execution (valid lifetimes only): every successful exec event before the end
marker is matched against RULES, an explicit table of expected executables:
uid, exe, exact argv shape and the allowed parent (another rule, the same
process before an in-place exec, PID 1, or a parent with no recorded exec).
Ancestry alone never explains anything. An exec is job-controlled if it
descends from Runner.Worker outside the hook's own rules, or if it comes after
the hook's first exec and matches no rule.
  denied:  no job-controlled exec, or FAIL;
  allowed: at least one job-controlled exec (positive control), or FAIL.

A lifetime without an admission verdict is NO-JOB, unless its console shows a
failure, which makes it INVALID. --expect RUN=allowed:N,denied:M requires
exactly those valid verdict counts; checking no lifetime at all is a
violation. Exit status is the number of violations.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

ARCHIVE = Path("/var/lib/tos-ci/audit")
ADMISSION = re.compile(r'\{.*"tos_ci_admission": "(allowed|denied)".*\}')
RECORD = re.compile(r"^type=([A-Z_]+) msg=audit\(\d+\.\d+:(\d+)\): (.*)$")
AUDIT_ON = re.compile(r"audit on nonce=([0-9a-f]{32})")
CONSOLE_FAILURES = ("audit drain timeout", "audit drain failed", "audit-forward failed", "audit unavailable")
MARKER_TAIL = r' exe="/usr/sbin/auditctl" hostname=\? addr=\? terminal=\? res=success\''
MARKER_HEAD = r"type=USER msg=audit\(\d+\.\d+:(\d+)\): pid=\d+ uid=0 auid=\d+ ses=\d+ subj=\S+ msg='text="
END_MARKER = re.compile(MARKER_HEAD + r"tos-ci-audit-end nonce=([0-9a-f]{32})" + MARKER_TAIL)
STATUS_MARKER = re.compile(MARKER_HEAD + r"tos-ci-audit-status lost=(\d+) backlog=(\d+)" + MARKER_TAIL)
# Exec syscalls by audit arch: x86_64 execve/execveat, i386 execve.
EXEC_SYSCALLS = {("c000003e", "59"), ("c000003e", "322"), ("40000003", "11")}
WORKER_EXE = "/opt/actions-runner/bin/Runner.Worker"
NONCE = r"[0-9a-f]{32}"


@dataclass(frozen=True)
class Rule:
    """An expected exec: who runs what, with which argv, under which parent.

    parents: rule names; "inplace:<rule>" for an exec replacing that rule's
    process image; "PID1"; "UNRECORDED" for a parent whose own exec is not in
    the record (forked without exec, or exec'd before the rules were loaded).
    argv: one regex per argument, each a full match; the count must match.
    cwd: a full-match regex for the working directory, when it matters.
    in_worker: allowed inside Runner.Worker's tree (the hook, the runner's own
    action unpack); everything else there is job-controlled.
    runner: the actions runner version the rule was verified against; the
    rule applies only while the image runs that version.
    """

    name: str
    uid: str
    exe: str
    argv: tuple[str, ...]
    parents: frozenset[str]
    hook: bool = False
    cwd: str | None = None
    in_worker: bool = False
    runner: str | None = None


def rule(name, uid, exe, argv, parents, hook=False, cwd=None, in_worker=False, runner=None):
    return Rule(name, uid, exe, tuple(argv), frozenset(parents), hook, cwd, in_worker or hook, runner)


EXECUTOR = ["/usr/lib/systemd/systemd-executor", "--deserialize", r"\d+", "--log-level", "info",
            "--log-target", "journal-or-kmsg"]
FINGERPRINTS = r"/etc/ssh/ssh_host_(ecdsa|ed25519|rsa)_key\.pub"
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
# The actions runner version the version-scoped rules were verified against.
VERIFIED_RUNNER = "v2.338.0"

# Every rule comes from an observed record of a real lifetime; extend the
# table only from such a record, never by widening a pattern.
RULES = [
    # The admission hook, run by Runner.Worker as the runner account.
    rule("hook", "1000", "/usr/bin/bash", ["/usr/bin/bash", "-e", "/usr/lib/tos-ci-guest/admission-hook.sh"],
         ["WORKER"], hook=True),
    rule("hook-timeout", "1000", "/usr/bin/timeout",
         ["/usr/bin/timeout", "--kill-after=5", "30", "/usr/bin/python3", "-I", "/usr/lib/tos-ci-guest/admission.py"],
         ["inplace:hook"], hook=True),
    rule("hook-python", "1000", "/usr/bin/python3.12", ["/usr/bin/python3", "-I", "/usr/lib/tos-ci-guest/admission.py"],
         ["hook-timeout"], hook=True),
    # systemd starting a unit's process.
    rule("executor", "0", "/usr/lib/systemd/systemd-executor", EXECUTOR, ["PID1"]),
    # end-job, the runner unit's ExecStopPost.
    rule("end-job", "0", "/usr/bin/bash", ["/bin/bash", "/usr/lib/tos-ci-guest/end-job"], ["inplace:executor"]),
    rule("end-job-cat", "0", "/usr/bin/cat", ["cat", "/etc/tos-ci/(audit|vm-nonce)"], ["end-job", "UNRECORDED"]),
    rule("end-job-logger", "0", "/usr/bin/logger", ["logger", "-p", "user.notice", "-t", "tos-ci", f"end-of-life {NONCE}"],
         ["end-job"]),
    rule("end-job-sleep", "0", "/usr/bin/sleep", ["sleep", "1"], ["end-job"]),
    rule("end-job-poweroff", "0", "/usr/bin/systemctl", ["systemctl", "poweroff", "--no-block"], ["end-job"]),
    # audit-close, from end-job or as the forwarder unit's ExecStop.
    rule("close", "0", "/usr/bin/python3.12", ["/usr/bin/python3", "-I", "/usr/lib/tos-ci-guest/audit-close"],
         ["end-job", "inplace:executor"]),
    rule("close-status", "0", "/usr/sbin/auditctl", ["auditctl", "-s"], ["close"]),
    rule("close-status-marker", "0", "/usr/sbin/auditctl",
         ["auditctl", "-m", r"tos-ci-audit-status lost=\d+ backlog=\d+"], ["close"]),
    rule("close-end-marker", "0", "/usr/sbin/auditctl", ["auditctl", "-m", f"tos-ci-audit-end nonce={NONCE}"], ["close"]),
    rule("close-logger", "0", "/usr/bin/logger",
         ["logger", "-p", "user.notice", "-t", "tos-ci", r"audit (drained|drain timeout|drain failed: .*)"], ["close"]),
    # dmesg.service: savelog, then its ExecStartPost steps.
    rule("savelog", "0", "/usr/bin/dash", ["/bin/sh", "/usr/bin/savelog", "-m640", "-q", "-p", "-n", "-c", "5", "/var/log/dmesg"],
         ["PID1", "UNRECORDED"]),
    rule("savelog-date", "0", "/usr/bin/date", ["date", r"\+%Y%m%d%H%M%S"], ["savelog", "UNRECORDED"]),
    rule("savelog-basename", "0", "/usr/bin/basename", ["basename", "/usr/bin/savelog"], ["savelog", "UNRECORDED"]),
    rule("savelog-basename2", "0", "/usr/bin/basename", ["basename", "--", "/var/log/dmesg"], ["savelog", "UNRECORDED"]),
    rule("savelog-dirname", "0", "/usr/bin/dirname", ["dirname", "--", "/var/log/dmesg"], ["savelog", "UNRECORDED"]),
    rule("savelog-rm", "0", "/usr/bin/rm", ["rm", "-f", "--", r"/var/log//dmesg\.4", r"/var/log//dmesg\.4\.gz"],
         ["savelog", "UNRECORDED"]),
    rule("savelog-touch", "0", "/usr/bin/touch", ["touch", "--", "/var/log/dmesg.new"], ["savelog", "UNRECORDED"]),
    rule("savelog-chown", "0", "/usr/bin/chown", ["chown", "--reference=/var/log/dmesg", "--", "/var/log/dmesg.new"],
         ["savelog", "UNRECORDED"]),
    rule("savelog-chmod", "0", "/usr/bin/chmod", ["chmod", "--reference=/var/log/dmesg", "--", "/var/log/dmesg.new"],
         ["savelog", "UNRECORDED"]),
    rule("savelog-ln", "0", "/usr/bin/ln", ["ln", "-f", "--", "/var/log/dmesg", "/var/log//dmesg.0"], ["savelog", "UNRECORDED"]),
    rule("savelog-mv", "0", "/usr/bin/mv", ["mv", "-f", "--", "/var/log/dmesg.new", "/var/log/dmesg"], ["savelog", "UNRECORDED"]),
    rule("savelog-chmod2", "0", "/usr/bin/chmod", ["chmod", "--", "640", "/var/log//dmesg.0"], ["savelog", "UNRECORDED"]),
    rule("dmesg-journalctl", "0", "/usr/bin/journalctl",
         ["/bin/journalctl", "--boot", "0", "--dmesg", "--output", "short-monotonic", "--quiet", "--no-pager", "--no-hostname"],
         ["inplace:executor"]),
    rule("dmesg-chgrp", "0", "/usr/bin/chgrp", ["/bin/chgrp", "adm", "/var/log/dmesg"], ["inplace:executor"]),
    rule("dmesg-chmod", "0", "/usr/bin/chmod", ["/bin/chmod", "0640", "/var/log/dmesg"], ["inplace:executor"]),
    # cloud-init printing the host key fingerprints.
    rule("fingerprints", "0", "/usr/bin/dash", ["/bin/sh", "/usr/lib/cloud-init/write-ssh-key-fingerprints", "", ""],
         ["UNRECORDED"]),
    rule("fingerprints-logger", "0", "/usr/bin/logger", ["logger", "-s", "-p", "user.info", "-t", "cloud-init", "--", r".*"],
         ["fingerprints"]),
    rule("fingerprints-keygen", "0", "/usr/bin/ssh-keygen", ["ssh-keygen", "-l", "-f", FINGERPRINTS], ["fingerprints"]),
    rule("fingerprints-cat", "0", "/usr/bin/cat", ["cat", FINGERPRINTS], ["fingerprints"]),
    # Accepted pre-admission exposure, verified on runner v2.338.0: before the
    # job-started hook runs, Runner.Worker unpacks each remotely referenced
    # action's tarball (tar, then gzip as its decompressor) in that action's
    # _temp_<uuid>/_staging directory. It parses job-chosen archives; no job
    # code runs (a remote Dockerfile or JavaScript action builds and starts
    # only after the hook). Re-verify when the runner version changes: these
    # rules apply only to the version they were verified on.
    rule("action-unpack-tar", "1000", "/usr/bin/tar", ["/usr/bin/tar", "-xzf", rf"/opt/actions-runner/_work/_actions/_temp_{UUID}/{UUID}\.tar\.gz"],
         ["WORKER"], cwd=rf"/opt/actions-runner/_work/_actions/_temp_{UUID}/_staging", in_worker=True, runner=VERIFIED_RUNNER),
    rule("action-unpack-gzip", "1000", "/usr/bin/gzip", ["gzip", "-d"], ["action-unpack-tar"],
         cwd=rf"/opt/actions-runner/_work/_actions/_temp_{UUID}/_staging", in_worker=True, runner=VERIFIED_RUNNER),
    # Console getty respawns.
    rule("agetty-tty", "0", "/usr/sbin/agetty", ["/sbin/agetty", "-o", r"-p -- \\u", "--noclear", "-", "linux"], ["PID1"]),
    rule("agetty-serial", "0", "/usr/sbin/agetty",
         ["/sbin/agetty", "-o", r"-p -- \\u", "--keep-baud", "115200,57600,38400,9600", "-", "vt220"], ["PID1"]),
]


@dataclass
class Exec:
    serial: int
    pid: str
    ppid: str
    uid: str
    exe: str
    argv: list[str] | None
    known_syscall: bool
    cwd: str | None = None
    rule: Rule | None = None
    in_worker: bool = False
    after_hook: bool = False
    notes: list[str] = field(default_factory=list)

    def describe(self) -> str:
        return f"{self.exe} {self.argv[:4] if self.argv else self.argv} (serial {self.serial}, uid {self.uid})"


def records(archive: bytes) -> list[tuple[str, bool]]:
    """(line, newline-terminated) pairs. Splits on newlines only: auditd's
    enriched format separates its appended fields with \\x1d, which
    str.splitlines() would treat as a line break."""
    parts = archive.decode(errors="replace").split("\n")
    lines = [(p, True) for p in parts[:-1]]
    if parts[-1]:
        lines.append((parts[-1], False))
    return lines


def decode_arg(value: str) -> str:
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    try:
        return bytes.fromhex(value).decode(errors="replace")
    except ValueError:
        return value


def execve_argv(bodies: list[str]) -> list[str] | None:
    """The argv of an EXECVE event, joined across records and split arguments;
    None if it is incomplete."""
    argc = None
    whole: dict[int, str] = {}
    chunks: dict[int, dict[int, str]] = defaultdict(dict)
    for body in bodies:
        m = re.match(r"argc=(\d+)", body)
        if m:
            argc = int(m.group(1))
        for index, value in re.findall(r'\ba(\d+)=("[^"]*"|[0-9A-Fa-f]+)', body):
            whole[int(index)] = decode_arg(value)
        for index, part, value in re.findall(r'\ba(\d+)\[(\d+)\]=("[^"]*"|[0-9A-Fa-f]+)', body):
            chunks[int(index)][int(part)] = value
    for index, parts in chunks.items():
        whole[index] = decode_arg("".join(parts[i] for i in sorted(parts)))
    if argc is None or sorted(whole) != list(range(argc)):
        return None
    return [whole[i] for i in range(argc)]


def exec_events(kept: list[str]) -> list[Exec]:
    syscalls: dict[int, dict[str, str]] = {}
    execves: dict[int, list[str]] = defaultdict(list)
    cwds: dict[int, str | None] = {}
    for line in kept:
        m = RECORD.match(line.split("\x1d")[0])
        if not m:
            continue
        kind, serial, body = m.group(1), int(m.group(2)), m.group(3)
        if kind == "SYSCALL" and 'key="tos-ci-exec"' in body:
            syscalls[serial] = {k: v.strip('"') for k, v in re.findall(r'(\w+)=("[^"]*"|\S+)', body)}
        elif kind == "EXECVE":
            execves[serial].append(body)
        elif kind == "CWD":
            m = re.match(r'cwd=("[^"]*"|[0-9A-Fa-f]+)$', body)
            cwds[serial] = decode_arg(m.group(1)) if m else None
    events = []
    for serial in sorted(syscalls):
        f = syscalls[serial]
        if f.get("success") != "yes":
            continue  # a failed attempt executes nothing
        events.append(Exec(serial, f.get("pid", "?"), f.get("ppid", "?"), f.get("uid", "?"), f.get("exe", "?"),
                           execve_argv(execves.get(serial, [])), (f.get("arch"), f.get("syscall")) in EXEC_SYSCALLS,
                           cwds.get(serial)))
    return events


# The runner version of the image the lifetimes ran on; set by main.
active_runner: str | None = None


def matches(r: Rule, e: Exec, relations: set[str]) -> bool:
    if r.runner is not None and r.runner != active_runner:
        return False
    if e.uid != r.uid or e.exe != r.exe or e.argv is None or len(e.argv) != len(r.argv):
        return False
    if not all(re.fullmatch(p, a, re.S) for p, a in zip(r.argv, e.argv)):
        return False
    if r.cwd is not None and (e.cwd is None or not re.fullmatch(r.cwd, e.cwd)):
        return False
    # The archive is unpacked in its own action's staging directory.
    if r.name == "action-unpack-tar" and not e.argv[2].startswith(e.cwd.rsplit("/_staging", 1)[0] + "/"):
        return False
    return bool(r.parents & relations)


def classify(events: list[Exec]) -> list[Exec]:
    """Attach a rule (or none) and the Worker-subtree flag to every exec, in order."""
    latest: dict[str, Exec] = {}
    hook_seen = False
    for e in events:
        previous = latest.get(e.pid)
        relations: set[str] = set()
        if previous is not None and previous.ppid == e.ppid:
            parent = previous
            if previous.rule:
                relations.add(f"inplace:{previous.rule.name}")
        else:
            parent = latest.get(e.ppid)
            if e.ppid == "1":
                relations.add("PID1")
            elif parent is None:
                relations.add("UNRECORDED")
            elif parent.exe == WORKER_EXE:
                relations.add("WORKER")
            elif parent.rule:
                relations.add(parent.rule.name)
        if e.known_syscall and e.exe != WORKER_EXE:
            e.rule = next((r for r in RULES if matches(r, e, relations)), None)
        e.in_worker = e.exe == WORKER_EXE or bool(parent and (parent.in_worker or parent.exe == WORKER_EXE))
        if e.rule and e.rule.name == "hook":
            hook_seen = True
        e.after_hook = hook_seen
        latest[e.pid] = e
    return events


def job_controlled(events: list[Exec]) -> list[Exec]:
    found = []
    for e in events:
        if e.exe == WORKER_EXE and e.known_syscall:
            continue
        if e.in_worker and not (e.rule and e.rule.in_worker):
            found.append(e)
        elif e.after_hook and e.rule is None:
            found.append(e)
    return found


def evidence(archive: bytes, nonce: str) -> tuple[list[str], list[str]]:
    """(problems, record lines up to and including the end marker)."""
    lines = records(archive)
    end_at = []
    problems = []
    for i, (line, terminated) in enumerate(lines):
        if "tos-ci-audit-end" not in line or not line.startswith("type=USER"):
            continue
        body = line.split("\x1d")[0]
        if END_MARKER.fullmatch(body) and terminated:
            end_at.append(i)
        else:
            problems.append("a malformed or incomplete end marker")
    if problems:
        return problems, []
    if len(end_at) != 1:
        return [f"{len(end_at)} end markers in the archive"], []
    end = end_at[0]
    marker = END_MARKER.fullmatch(lines[end][0].split("\x1d")[0])
    if marker.group(2) != nonce:
        return ["the end marker carries another nonce"], []
    kept = [line for line, _ in lines[: end + 1]]
    serials = set()
    for line in kept:
        match = RECORD.match(line.split("\x1d")[0])
        if not match:
            problems.append(f"unparsable archive line: {line[:80]!r}")
            break
        # auditd numbers its own DAEMON_* records from a separate counter;
        # only kernel serials form the sequence that must have no gaps.
        if not match.group(1).startswith("DAEMON_"):
            serials.add(int(match.group(2)))
    last = int(marker.group(1))
    if serials:
        if max(serials) != last:
            problems.append("records after the end marker's serial precede it")
        missing = (last - min(serials) + 1) - len(serials)
        if missing:
            problems.append(f"{missing} audit serials missing between {min(serials)} and {last}")
    # Every kept line before the end marker is newline-terminated, so a status
    # marker needs no termination check of its own.
    status = [STATUS_MARKER.fullmatch(line.split("\x1d")[0]) for line in kept
              if "tos-ci-audit-status" in line and line.startswith("type=USER")]
    if len(status) != 1 or status[0] is None or status[0].group(2) != "0":
        problems.append("no single complete status marker reporting lost=0")
    if not any(e.rule and e.rule.name == "hook-python" for e in classify(exec_events(kept))):
        problems.append("the hook's execution is not in the audit stream")
    return problems, kept


def console_problems(console: str) -> list[str]:
    problems = [f"console reports '{failure}'" for failure in CONSOLE_FAILURES if failure in console]
    if "audit drained" not in console:
        problems.append("console never reports 'audit drained'")
    if "end-of-life" not in console:
        problems.append("no end-of-life record")
    return problems


def judge(verdict: str, kept: list[str]) -> tuple[bool, str]:
    """(passed, detail) for a valid lifetime."""
    events = classify(exec_events(kept))
    found = job_controlled(events)
    # Accepted exposure stays visible in every verdict.
    unpacks = sum(1 for e in events if e.rule and e.rule.name == "action-unpack-tar")
    if verdict == "denied":
        if found:
            return False, (f"job-controlled execution after a denial: {found[0].describe()} (+{len(found) - 1} more); "
                           f"action unpacks before the hook: {unpacks}")
        return True, f"denied, no job-controlled execution ({len(events)} execs explained; action unpacks before the hook: {unpacks})"
    if found:
        return True, f"allowed, job-controlled execution visible ({len(found)} execs; action unpacks: {unpacks})"
    return False, "allowed but no job-controlled execution was seen; the logger is blind"


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


def image_runner_version(images: Path = Path("/var/lib/tos-ci/images")) -> str | None:
    """The runner version recorded in the current image's manifest."""
    try:
        manifest = (images / f"{(images / 'current.qcow2').readlink()}.manifest").read_text()
    except OSError:
        return None
    m = re.search(r"^runner (v[0-9.]+) ", manifest, re.M)
    return m.group(1) if m else None


def parse_expect(values: list[str]) -> dict[str, dict[str, int]]:
    expected = {}
    for value in values:
        run, _, counts = value.partition("=")
        expected[run] = {}
        for part in counts.split(","):
            verdict, _, n = part.partition(":")
            if verdict not in ("allowed", "denied") or not n.isdigit():
                raise SystemExit(f"bad --expect {value!r}")
            expected[run][verdict] = int(n)
    return expected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--since", required=True)
    parser.add_argument("--expect", action="append", default=[], help="RUN_ID=allowed:N,denied:M")
    parser.add_argument("--as-denied", action="append", default=[], help="test only: judge this run's lifetimes as denied")
    parser.add_argument("--runner-version", help="the image's actions runner version (default: from the current image manifest)")
    args = parser.parse_args()
    global active_runner
    active_runner = args.runner_version or image_runner_version()
    print(f"image runner {active_runner}; version-scoped rules verified on {VERIFIED_RUNNER}"
          + ("" if active_runner == VERIFIED_RUNNER else ": NOT APPLIED, re-verify"))
    expected = parse_expect(args.expect)
    violations = checked = 0
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"allowed": 0, "denied": 0})
    for (slot, invocation), lines in sorted(consoles(args.since).items()):
        console = "\n".join(lines)
        verdicts = [json.loads(m.group(0)) for m in ADMISSION.finditer(console)]
        label = f"slot{slot} {invocation[:8]}"
        problems = console_problems(console)
        if not verdicts:
            failures = [f for f in CONSOLE_FAILURES if f in console]
            if failures:
                print(f"INVALID  {label} no verdict: console reports {failures}")
                violations += 1
            else:
                print(f"NO-JOB   {label}")
            continue
        run = str(verdicts[0].get("run_id"))
        verdict = verdicts[0]["tos_ci_admission"]
        if run in args.as_denied:
            verdict = "denied"
        label += f" run {run} {verdict}"
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
        checked += 1
        counts[run][verdict] += 1
        passed, detail = judge(verdict, kept)
        print(f"{'PASS' if passed else 'FAIL'}     {label}: {detail}")
        violations += not passed
    for run, want in expected.items():
        got = {k: counts[run][k] for k in want}
        if got != want:
            print(f"EXPECT   run {run}: wanted {want} valid verdicts, got {got}")
            violations += 1
    if checked == 0:
        print("no lifetime was checked")
        violations += 1
    print(f"checked {checked} lifetimes; violations: {violations}")
    return violations


if __name__ == "__main__":
    sys.exit(main())
