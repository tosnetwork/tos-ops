#!/usr/bin/env python3
"""Install a reviewed root snapshot and enable existing contact units without restarts."""

import argparse
import hashlib
import os
import pwd
import stat
import subprocess
from pathlib import Path


def run(*args):
    subprocess.run(list(args), check=True)


def verified_bytes(path, expected):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        assert stat.S_ISREG(info.st_mode) and info.st_size <= 1024 * 1024
        data = os.read(fd, 1024 * 1024 + 1)
    finally:
        os.close(fd)
    assert hashlib.sha256(data).hexdigest() == expected, "reviewed source SHA mismatch"
    return data


def secure_directory(path, uid):
    path.mkdir(mode=0o755, exist_ok=True)
    info = path.lstat()
    assert (
        stat.S_ISDIR(info.st_mode) and info.st_uid == uid and not info.st_mode & 0o022
    ), "unsafe deployment directory"


def install_bytes(path, data, mode):
    fd = os.open(
        path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode
    )
    try:
        info = os.fstat(fd)
        assert (
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid()
            and info.st_nlink == 1
        )
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            assert written > 0
            view = view[written:]
        os.fsync(fd)
        assert os.pread(fd, len(data) + 1, 0) == data, "installed bytes differ"
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--user", required=True)
    p.add_argument("--source-sha256", required=True)
    p.add_argument("--unit-sha256", required=True)
    a = p.parse_args()
    assert os.geteuid() == 0, "root installer required"
    account = pwd.getpwnam(a.user)
    assert account.pw_uid > 0 and a.user.replace("-", "").replace("_", "").isalnum()
    root = Path(__file__).resolve().parent
    source = verified_bytes(root / "host-monitor.py", a.source_sha256)
    unit = verified_bytes(root / "tos-host-monitor.service", a.unit_sha256)
    target = Path("/usr/local/lib/tos-host-monitor")
    secure_directory(target, 0)
    installed = target / "host-monitor.py"
    system_unit = Path("/etc/systemd/system/tos-host-monitor.service")
    assert not installed.exists() and not system_unit.exists(), (
        "existing deployment: review upgrade separately"
    )
    secure_directory(system_unit.parent, 0)
    state = Path("/var/lib/tos-host-monitor")
    secure_directory(state, 0)
    install_bytes(installed, source, 0o755)
    install_bytes(system_unit, unit.replace(b"@USER@", a.user.encode()), 0o644)
    run("loginctl", "enable-linger", a.user)
    run(
        "systemctl",
        "enable",
        "ssh.service",
        "tailscaled.service",
        "systemd-networkd.service",
        "systemd-resolved.service",
        "tos-nic-watchdog.service",
    )
    runtime = f"/run/user/{account.pw_uid}"
    user = [
        "runuser",
        "-u",
        a.user,
        "--",
        "env",
        f"XDG_RUNTIME_DIR={runtime}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus",
        "systemctl",
        "--user",
    ]
    run(
        *user,
        "enable",
        "con01-tun-node1.service",
        "con01-tun-node3.service",
        "con01-tun-node5-8081.service",
        "e6-br1-proof-tunnel.service",
    )
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", "--now", "tos-host-monitor.service")


if __name__ == "__main__":
    main()
