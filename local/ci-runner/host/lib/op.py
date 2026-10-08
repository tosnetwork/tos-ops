"""One supervisor operation, run as a killable child process.

    op.py jit SLOT NONCE                  -> {"runner_id", "name", "encoded_jit_config"}
    op.py runner-status ID                -> {"status", "busy"} or {"missing": true}
    op.py runner-delete ID                -> {"ok": true}
    op.py reconcile                       -> {"deleted": [...]}   (stdin: {"keep": [names]})
    op.py seed SLOT                       -> {"ok": true}         (stdin: {"nonce", "jit", "allowlist", "audit"})
    op.py slot VERB SLOT [GEN]            -> {"reply": "..."}

Exactly one JSON object is printed on success. Any failure exits non-zero with
the error on stderr. Secrets travel on stdin and stdout pipes, never argv.
The supervisor kills the process at its deadline, so nothing here needs its
own retry or timeout beyond bounding single calls.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

CONFIG = json.loads(Path("/etc/tos-ci/config.json").read_text()) if Path("/etc/tos-ci/config.json").exists() else {}
REPOSITORY = CONFIG.get("repository", "tosnetwork/tos")
NAME_PREFIX = "tos-ci-s"


def github(method: str, path: str, body: object | None = None) -> object:
    token = Path(CONFIG["token"]).read_text().strip()
    req = urllib.request.Request(
        f"https://api.github.com/repos/{REPOSITORY}{path}",
        data=None if body is None else json.dumps(body).encode(),
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "tos-ci-supervisor",
        },
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = resp.read()
    return json.loads(raw) if raw else None


def all_runners() -> list[dict]:
    found, page = [], 1
    while True:
        result = github("GET", f"/actions/runners?per_page=100&page={page}")
        runners = result.get("runners", [])
        found += runners
        if len(runners) < 100:
            return found
        page += 1


def delete_runner(runner_id: int) -> None:
    try:
        github("DELETE", f"/actions/runners/{runner_id}")
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise


def cloud_config(files: dict[str, tuple[str, str, str]]) -> str:
    """A #cloud-config writing files (path -> (content, owner, mode)) and starting the job."""
    lines = ["#cloud-config", "write_files:"]
    for path, (content, owner, mode) in files.items():
        encoded = base64.b64encode(content.encode()).decode()
        lines += [
            f"  - path: {path}",
            "    encoding: b64",
            f"    content: {encoded}",
            f"    owner: {owner}",
            f"    permissions: '{mode}'",
        ]
    lines += ["runcmd:", "  - [/usr/lib/tos-ci-guest/start-job]"]
    return "\n".join(lines) + "\n"


def write_seed(slot: int, nonce: str, jit: str, allowlist: str, audit: bool) -> None:
    seed_dir = Path(CONFIG.get("store", "/var/lib/tos-ci")) / f"seed{slot}"
    user_data = cloud_config(
        {
            "/etc/tos-ci/jitconfig": (jit, "runner:runner", "0600"),
            "/etc/tos-ci/trusted-logins": (allowlist, "root:root", "0644"),
            "/etc/tos-ci/vm-nonce": (nonce + "\n", "root:root", "0644"),
            "/etc/tos-ci/slot": (f"{slot}\n", "root:root", "0644"),
            "/etc/tos-ci/audit": ("1\n" if audit else "0\n", "root:root", "0644"),
        }
    )
    meta_data = f"instance-id: tos-ci-{nonce[:16]}\nlocal-hostname: tos-ci-s{slot}\n"
    network = (
        "version: 2\nethernets:\n  nic:\n    match:\n      name: \"en*\"\n"
        "    dhcp4: true\n    dhcp6: false\n    accept-ra: false\n    link-local: []\n"
    )
    with tempfile.TemporaryDirectory(dir=seed_dir) as tmp:
        work = Path(tmp)
        for name, text in (("user-data", user_data), ("meta-data", meta_data), ("network-config", network)):
            (work / name).write_text(text)
        iso = work / "seed.iso"
        subprocess.run(
            ["xorriso", "-as", "mkisofs", "-quiet", "-output", str(iso), "-volid", "cidata",
             "-joliet", "-rock", str(work / "user-data"), str(work / "meta-data"), str(work / "network-config")],
            check=True, timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        os.chmod(iso, 0o640)
        os.replace(iso, seed_dir / "seed.iso")


def slotctl(request: str) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(200)
        conn.connect(CONFIG.get("slotctl_socket", "/run/tos-ci/slotctl.sock"))
        conn.sendall(request.encode())
        reply = b""
        while not reply.endswith(b"\n"):
            chunk = conn.recv(1024)
            if not chunk:
                break
            reply += chunk
    return reply.decode().strip()


def main(argv: list[str]) -> dict:
    verb = argv[0]
    if verb == "jit":
        slot, nonce = int(argv[1]), argv[2]
        name = f"{NAME_PREFIX}{slot}-{nonce[:8]}"
        result = github(
            "POST",
            "/actions/runners/generate-jitconfig",
            {"name": name, "runner_group_id": 1, "labels": CONFIG["labels"], "work_folder": "_work"},
        )
        return {"runner_id": int(result["runner"]["id"]), "name": name, "encoded_jit_config": result["encoded_jit_config"]}
    if verb == "runner-status":
        try:
            info = github("GET", f"/actions/runners/{int(argv[1])}")
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return {"missing": True}
            raise
        return {"status": info.get("status"), "busy": bool(info.get("busy"))}
    if verb == "runner-delete":
        delete_runner(int(argv[1]))
        return {"ok": True}
    if verb == "reconcile":
        keep = set(json.load(sys.stdin)["keep"])
        deleted = []
        for runner in all_runners():
            name = runner.get("name", "")
            if name.startswith(NAME_PREFIX) and name not in keep:
                delete_runner(runner["id"])
                deleted.append(name)
        return {"deleted": deleted}
    if verb == "seed":
        args = json.load(sys.stdin)
        write_seed(int(argv[1]), args["nonce"], args["jit"], args["allowlist"], bool(args["audit"]))
        return {"ok": True}
    if verb == "slot":
        request = f"{argv[1]} {argv[2]}" + (f" {argv[3]}" if len(argv) > 3 else "") + "\n"
        reply = slotctl(request)
        if argv[1] == "status":
            status = json.loads(reply)  # a non-JSON answer fails this op
            if not isinstance(status, dict) or not {"active", "pid", "latest", "desired"} <= set(status):
                raise SystemExit(f"malformed status reply: {reply[:120]}")
            return status
        return {"reply": reply}
    raise SystemExit(f"unknown verb {verb}")


if __name__ == "__main__":
    print(json.dumps(main(sys.argv[1:])), flush=True)
