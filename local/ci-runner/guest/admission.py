"""Job-started admission check inside a CI VM.

Runs as the runner's ACTIONS_RUNNER_HOOK_JOB_STARTED hook, before any step of
the job. A job is admitted only when GitHub's event payload shows a trusted
event and the host acknowledges the request against its current allowlist.
Any other outcome exits non-zero, which fails the job before its first step.
"""

from __future__ import annotations

import hashlib
import json
import os
import select
import sys
import syslog
import time
from pathlib import Path

REPOSITORY = "tosnetwork/tos"
ALLOWLIST = Path("/etc/tos-ci/trusted-logins")
NONCE = Path("/etc/tos-ci/vm-nonce")
SLOT = Path("/etc/tos-ci/slot")
PORT = "/dev/virtio-ports/org.tosnetwork.admission"
ACK_DEADLINE = 20.0
MAX_REPLY = 4096


class Denied(Exception):
    pass


def read_allowlist(data: bytes) -> frozenset[str]:
    logins = [
        line.strip().lower()
        for line in data.decode("ascii").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not logins:
        raise Denied("allowlist is empty")
    return frozenset(logins)


def _get(payload: dict, *keys: str) -> str:
    value: object = payload
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            raise Denied(f"payload has no {'.'.join(keys)}")
        value = value[key]
    if not isinstance(value, str) or not value:
        raise Denied(f"payload {'.'.join(keys)} is not a string")
    return value


def evaluate(env: dict[str, str], payload: dict, logins: frozenset[str]) -> dict[str, str]:
    """The identities of an admissible event, or Denied."""
    event = env.get("GITHUB_EVENT_NAME", "")
    repository = env.get("GITHUB_REPOSITORY", "")
    triggering = env.get("GITHUB_TRIGGERING_ACTOR", "")
    if repository != REPOSITORY:
        raise Denied("repository is not the trusted repository")
    sender = _get(payload, "sender", "login")
    if event == "pull_request":
        base = _get(payload, "pull_request", "base", "repo", "full_name")
        head = _get(payload, "pull_request", "head", "repo", "full_name")
        if base != REPOSITORY or head != REPOSITORY:
            raise Denied("pull request head or base is outside the trusted repository")
        author = _get(payload, "pull_request", "user", "login")
    elif event == "push":
        if env.get("GITHUB_REF", "") != "refs/heads/main":
            raise Denied("push is not to main")
        author = sender
    else:
        raise Denied(f"event {event or '(none)'} is not admitted")
    identities = {"author": author, "triggering_actor": triggering, "sender": sender}
    for role, login in identities.items():
        if not login or login.lower() not in logins:
            raise Denied(f"{role} is not a trusted login")
    return {"event": event, "repository": repository, **identities}


def handshake(request: dict[str, object]) -> dict:
    """Send one request on the admission port and wait for the host's reply."""
    fd = os.open(PORT, os.O_RDWR | os.O_NONBLOCK | os.O_NOCTTY)
    try:
        frame = (json.dumps(request, sort_keys=True) + "\n").encode()
        deadline = time.monotonic() + ACK_DEADLINE
        sent = 0
        while sent < len(frame):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Denied("host did not accept the request in time")
            _, writable, _ = select.select([], [fd], [], remaining)
            if writable:
                try:
                    sent += os.write(fd, frame[sent:])
                except BlockingIOError:
                    continue
        reply = b""
        while not reply.endswith(b"\n"):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Denied("no acknowledgement from the host")
            readable, _, _ = select.select([fd], [], [], remaining)
            if not readable:
                continue
            try:
                chunk = os.read(fd, MAX_REPLY + 1 - len(reply))
            except BlockingIOError:
                continue
            if not chunk:
                time.sleep(0.05)
                continue
            reply += chunk
            if len(reply) > MAX_REPLY:
                raise Denied("acknowledgement too long")
    finally:
        os.close(fd)
    try:
        answer = json.loads(reply)
    except json.JSONDecodeError as error:
        raise Denied("unparsable acknowledgement") from error
    if not isinstance(answer, dict):
        raise Denied("acknowledgement is not an object")
    return answer


def check_ack(request: dict[str, object], answer: dict) -> None:
    if answer.get("verdict") != "allowed":
        raise Denied(f"host denied: {answer.get('reason', 'no reason')}")
    for key in ("vm_nonce", "run_id", "run_attempt", "job"):
        if answer.get(key) != request[key]:
            raise Denied(f"acknowledgement {key} does not match the request")


def record(verdict: str, **fields: object) -> None:
    line = json.dumps({"tos_ci_admission": verdict, **fields}, sort_keys=True)
    print(line, flush=True)
    syslog.openlog("tos-ci-admission")
    syslog.syslog(syslog.LOG_NOTICE, line)


def main() -> int:
    env = dict(os.environ)
    context = {
        "run_id": env.get("GITHUB_RUN_ID", ""),
        "run_attempt": env.get("GITHUB_RUN_ATTEMPT", ""),
        "job": env.get("GITHUB_JOB", ""),
    }
    try:
        allowlist_data = ALLOWLIST.read_bytes()
        logins = read_allowlist(allowlist_data)
        event_path = env.get("GITHUB_EVENT_PATH", "")
        if not event_path:
            raise Denied("no event payload")
        payload = json.loads(Path(event_path).read_text())
        if not isinstance(payload, dict):
            raise Denied("event payload is not an object")
        identities = evaluate(env, payload, logins)
        request = {
            "slot": int(SLOT.read_text().strip()),
            "vm_nonce": NONCE.read_text().strip(),
            **context,
            **identities,
            "allowlist_sha256": hashlib.sha256(allowlist_data).hexdigest(),
        }
        check_ack(request, handshake(request))
    except (Denied, OSError, ValueError) as error:
        record("denied", reason=str(error), **context)
        return 1
    record("allowed", **context, **identities)
    return 0


if __name__ == "__main__":
    sys.exit(main())
