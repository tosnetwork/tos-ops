"""Build a CI VM base image generation. Run as root on the CI host.

1. Download the Ubuntu 24.04 cloud image and verify it against Ubuntu's signed
   SHA256SUMS.
2. Pin the actions runner and uv to GitHub's latest releases, with the
   SHA-256 digests GitHub publishes for their assets.
3. Boot a one-time builder VM on the isolated bridge, with cloud-init
   installing everything and the guest files, then power off.
4. Flatten the result into images/gen-<UTC timestamp>.qcow2 with a manifest,
   point images/current.qcow2 at it, and keep at most two generations.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

STORE = Path("/var/lib/tos-ci")
IMAGES = STORE / "images"
GUEST = Path("/usr/lib/tos-ci/guest")
CLOUD = "https://cloud-images.ubuntu.com/noble/current"
CLOUD_IMAGE = "noble-server-cloudimg-amd64.img"
KEYRING = "/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg"
LLVM_KEY_FINGERPRINT = "6084F3CF814B57C1CF12EFD515CF4D18AF4F7421"
BUILD_USER = "tos-ci-build"
TAP = "tcib"
BUILD_TIMEOUT = 45 * 60
KEEP = 2


def fetch(url: str, dest: Path | None = None) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "tos-ci-image-build"})
    with urllib.request.urlopen(req, timeout=600) as resp:
        if dest is None:
            return resp.read()
        with open(dest, "wb") as out:
            shutil.copyfileobj(resp, out, 1 << 20)
    return b""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def cloud_image(work: Path) -> Path:
    sums, sig = work / "SHA256SUMS", work / "SHA256SUMS.gpg"
    fetch(f"{CLOUD}/SHA256SUMS", sums)
    fetch(f"{CLOUD}/SHA256SUMS.gpg", sig)
    subprocess.run(["gpgv", "--keyring", KEYRING, str(sig), str(sums)], check=True)
    expected = next(
        line.split()[0]
        for line in sums.read_text().splitlines()
        if line.split()[-1].lstrip("*") == CLOUD_IMAGE
    )
    image = work / CLOUD_IMAGE
    fetch(f"{CLOUD}/{CLOUD_IMAGE}", image)
    if sha256_file(image) != expected:
        raise SystemExit("cloud image digest mismatch")
    return image


def release_asset(repo: str, pattern: str) -> tuple[str, str, str]:
    """(tag, download URL, sha256) of the latest release asset matching pattern."""
    release = json.loads(fetch(f"https://api.github.com/repos/{repo}/releases/latest"))
    for asset in release["assets"]:
        if re.fullmatch(pattern, asset["name"]):
            digest = asset.get("digest") or ""
            if not digest.startswith("sha256:"):
                raise SystemExit(f"{repo} asset {asset['name']} has no published sha256")
            return release["tag_name"], asset["browser_download_url"], digest[len("sha256:") :]
    raise SystemExit(f"{repo}: no asset matching {pattern}")


def guest_file(path: str, source: str, owner: str, mode: str) -> list[str]:
    content = base64.b64encode((GUEST / source).read_bytes()).decode()
    return [
        f"  - path: {path}",
        "    encoding: b64",
        f"    content: {content}",
        f"    owner: {owner}",
        f"    permissions: '{mode}'",
    ]


def user_data(runner: tuple[str, str, str], uv: tuple[str, str, str]) -> str:
    runner_tag, runner_url, runner_sha = runner
    uv_tag, uv_url, uv_sha = uv
    files = []
    files += guest_file("/usr/lib/tos-ci-guest/admission.py", "admission.py", "root:root", "0644")
    files += guest_file("/usr/lib/tos-ci-guest/admission-hook", "admission-hook", "root:root", "0755")
    files += guest_file("/usr/lib/tos-ci-guest/start-job", "start-job", "root:root", "0755")
    files += guest_file("/usr/lib/tos-ci-guest/end-job", "end-job", "root:root", "0755")
    files += guest_file("/etc/systemd/system/tos-ci-runner.service", "tos-ci-runner.service", "root:root", "0644")
    files += guest_file("/etc/udev/rules.d/90-tos-ci-admission.rules", "90-tos-ci-admission.rules", "root:root", "0644")
    files += guest_file("/etc/systemd/journald.conf.d/90-tos-ci-console.conf", "90-tos-ci-console.conf", "root:root", "0644")
    files += guest_file("/etc/sysctl.d/90-tos-ci-noipv6.conf", "90-tos-ci-noipv6.conf", "root:root", "0644")
    files += guest_file("/usr/lib/tos-ci-guest/runner.env", "runner.env", "root:root", "0644")
    install = f"""#!/bin/bash
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
# clang-21 from apt.llvm.org, key pinned by fingerprint.
curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key -o /tmp/llvm.asc
gpg --show-keys --with-colons /tmp/llvm.asc | grep -q '^fpr:::::::::{LLVM_KEY_FINGERPRINT}:$'
gpg --dearmor -o /usr/share/keyrings/llvm.gpg /tmp/llvm.asc
echo 'deb [signed-by=/usr/share/keyrings/llvm.gpg] https://apt.llvm.org/noble/ llvm-toolchain-noble-21 main' > /etc/apt/sources.list.d/llvm.list
apt-get update -q
apt-get install -y -q clang-21 lld-21 llvm-21
# Actions runner {runner_tag}, verified against GitHub's published digest.
curl -fsSL -o /tmp/runner.tgz '{runner_url}'
echo '{runner_sha}  /tmp/runner.tgz' | sha256sum -c -
install -d -o runner -g runner /opt/actions-runner /opt/hostedtoolcache
tar -xzf /tmp/runner.tgz -C /opt/actions-runner
/opt/actions-runner/bin/installdependencies.sh
chown -R runner:runner /opt/actions-runner
install -m 0644 -o root -g root /usr/lib/tos-ci-guest/runner.env /opt/actions-runner/.env
# uv {uv_tag}, verified against GitHub's published digest.
curl -fsSL -o /tmp/uv.tgz '{uv_url}'
echo '{uv_sha}  /tmp/uv.tgz' | sha256sum -c -
tar -xzf /tmp/uv.tgz -C /tmp
install -m 0755 /tmp/uv-x86_64-unknown-linux-gnu/uv /tmp/uv-x86_64-unknown-linux-gnu/uvx /usr/local/bin/
# A single-use VM needs no inbound shell, no background upgrades.
systemctl disable --now ssh.service ssh.socket unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer motd-news.timer || true
systemctl mask ssh.service ssh.socket || true
systemctl enable auditd
sed -i 's/^active = .*/active = no/' /etc/audit/plugins.d/syslog.conf
echo "TOS-CI-MANIFEST-BEGIN"
echo "runner {runner_tag} sha256 {runner_sha}"
echo "uv {uv_tag} sha256 {uv_sha}"
dpkg-query -W -f='${{Package}} ${{Version}}\\n'
echo "TOS-CI-MANIFEST-END"
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/*
cloud-init clean --logs --machine-id
echo "TOS-CI-BUILD-OK"
"""
    files += [
        "  - path: /root/tos-ci-install",
        "    encoding: b64",
        f"    content: {base64.b64encode(install.encode()).decode()}",
        "    owner: root:root",
        "    permissions: '0700'",
    ]
    return "\n".join(
        [
            "#cloud-config",
            "users:",
            "  - name: runner",
            "    shell: /bin/bash",
            "    groups: [docker]",
            "    sudo: 'ALL=(ALL) NOPASSWD:ALL'",
            "    lock_passwd: true",
            "package_update: true",
            "packages: [docker.io, git, curl, ca-certificates, gnupg, python3, build-essential,"
            " cmake, ninja-build, ccache, auditd, jq, unzip, zstd, xz-utils, sudo]",
            "write_files:",
            *files,
            "runcmd:",
            "  - [sh, -c, '/root/tos-ci-install > /dev/ttyS0 2>&1 && rm -f /root/tos-ci-install && poweroff"
            " || (echo TOS-CI-BUILD-FAILED > /dev/ttyS0; poweroff)']",
            "",
        ]
    )


def run_builder(work: Path, base: Path, seed: Path, log_path: Path) -> None:
    disk = work / "build.qcow2"
    subprocess.run(
        ["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", str(base), str(disk), "40G"],
        check=True,
    )
    for path in (work, disk, seed, log_path):
        shutil.chown(path, BUILD_USER, BUILD_USER)
    subprocess.run(["ip", "link", "del", TAP], stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "tuntap", "add", "dev", TAP, "mode", "tap", "user", BUILD_USER], check=True)
    subprocess.run(["ip", "link", "set", TAP, "master", "tosci0"], check=True)
    subprocess.run(["bridge", "link", "set", "dev", TAP, "isolated", "on"], check=True)
    subprocess.run(["ip", "link", "set", TAP, "up"], check=True)
    try:
        subprocess.run(
            [
                "systemd-run", "--wait", "--collect", "--quiet",
                "--unit=tos-ci-image-build", "--slice=tos-ci.slice",
                f"--uid={BUILD_USER}", f"--gid={BUILD_USER}",
                "-p", "SupplementaryGroups=kvm", "-p", "MemoryMax=17G",
                "-p", "AllowedCPUs=72-79,168-175", "-p", f"RuntimeMaxSec={BUILD_TIMEOUT}",
                "-p", "NoNewPrivileges=yes", "-p", "ProtectHome=yes",
                "/usr/bin/qemu-system-x86_64", "-no-user-config", "-nodefaults",
                "-machine", "q35,accel=kvm", "-cpu", "host", "-smp", "16", "-m", "16G",
                "-display", "none", "-vga", "none", "-monitor", "none",
                "-serial", f"file:{log_path}",
                "-drive", f"file={disk},if=virtio,format=qcow2,cache=none",
                "-drive", f"file={seed},if=virtio,format=raw,readonly=on",
                "-netdev", f"tap,id=n0,ifname={TAP},script=no,downscript=no",
                "-device", "virtio-net-pci,netdev=n0,mac=52:54:00:7c:00:20",
                "-device", "virtio-rng-pci",
                "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
            ],
            check=True,
        )
    finally:
        subprocess.run(["ip", "link", "del", TAP], stderr=subprocess.DEVNULL)


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("run as root")
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    work = IMAGES / f"build-{stamp}"
    work.mkdir(parents=True)
    try:
        base = cloud_image(work)
        runner = release_asset("actions/runner", r"actions-runner-linux-x64-[0-9.]+\.tar\.gz")
        uv = release_asset("astral-sh/uv", r"uv-x86_64-unknown-linux-gnu\.tar\.gz")
        cfg = work / "seed"
        cfg.mkdir()
        (cfg / "user-data").write_text(user_data(runner, uv))
        (cfg / "meta-data").write_text(f"instance-id: tos-ci-build-{stamp}\nlocal-hostname: tos-ci-build\n")
        seed = work / "seed.iso"
        subprocess.run(
            ["xorriso", "-as", "mkisofs", "-quiet", "-output", str(seed), "-volid", "cidata",
             "-joliet", "-rock", str(cfg / "user-data"), str(cfg / "meta-data")],
            check=True,
        )
        log_path = work / "console.log"
        log_path.touch()
        run_builder(work, base, seed, log_path)
        console = log_path.read_text(errors="replace")
        if "TOS-CI-BUILD-OK" not in console:
            tail = "\n".join(console.splitlines()[-40:])
            raise SystemExit(f"image build failed; console tail:\n{tail}")
        manifest = console.split("TOS-CI-MANIFEST-BEGIN", 1)[1].split("TOS-CI-MANIFEST-END", 1)[0]
        image = IMAGES / f"gen-{stamp}.qcow2"
        subprocess.run(["qemu-img", "convert", "-O", "qcow2", str(work / "build.qcow2"), str(image)], check=True)
        os.chmod(image, 0o644)
        shutil.chown(image, "root", "root")
        digest = sha256_file(image)
        Path(f"{image}.manifest").write_text(
            f"image {image.name}\nsha256 {digest}\nbase {CLOUD_IMAGE} {sha256_file(base)}\n"
            + "\n".join(l.strip() for l in manifest.strip().splitlines() if l.strip())
            + "\n"
        )
        link = IMAGES / "current.qcow2.new"
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(image.name)
        os.replace(link, IMAGES / "current.qcow2")
        print(f"image {image.name} sha256 {digest} runner {runner[0]} uv {uv[0]}")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    # Keep the newest generations; never one that a running overlay may use.
    generations = sorted(IMAGES.glob("gen-*.qcow2"))
    in_use = subprocess.run(["pgrep", "-c", "-f", "qemu-system-x86_64 -name tos-ci-vm"], capture_output=True, text=True).stdout.strip()
    for old in generations[:-KEEP]:
        if in_use not in ("", "0"):
            print(f"keeping {old.name}: CI VMs are running")
            continue
        old.unlink()
        Path(f"{old}.manifest").unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
