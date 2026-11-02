#!/usr/bin/env python3
"""Render or install the read-only coordinator user timer; never touches validator units."""

import argparse
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc", action="append", required=True)
    parser.add_argument("--wallets", type=Path, required=True)
    parser.add_argument("--genesis", type=Path, required=True)
    parser.add_argument("--status", type=Path, required=True)
    parser.add_argument("--render-dir", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if (
        len(args.rpc) != 2
        or len(set(args.rpc)) != 2
        or not all(re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}/jsonRPC", url) for url in args.rpc)
    ):
        parser.error("two explicit distinct loopback RPC origins required")
    paths = [ROOT, args.wallets, args.genesis, args.status]
    if not all(
        path.is_absolute() and re.fullmatch(r"/[A-Za-z0-9_./-]+", str(path)) for path in paths
    ):
        parser.error("absolute simple paths required by systemd template")
    if not args.wallets.is_file() or not args.genesis.is_file() or not args.status.parent.is_dir():
        parser.error("existing public manifests and private status directory required")
    if args.apply and args.render_dir:
        parser.error("choose render or apply")
    if not args.apply and not args.render_dir:
        parser.error("render-dir required unless apply is explicit")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    subprocess.run(
        ["git", "ls-files", "--error-unmatch", "production/con01_history/election_fees.py"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        check=True,
    )
    subprocess.run(
        [
            "git",
            "diff",
            "--exit-code",
            revision,
            "--",
            "production/con01_history",
            "testnet/systemd",
            "testnet/scripts/install-election-fee-watch.py",
        ],
        cwd=ROOT,
        check=True,
    )
    destination = Path.home() / ".config/systemd/user" if args.apply else args.render_dir
    destination.mkdir(parents=True, exist_ok=True)
    values = dict(
        CHECKOUT=str(ROOT),
        REVISION=revision,
        RPC_A=args.rpc[0],
        RPC_B=args.rpc[1],
        WALLETS=str(args.wallets),
        GENESIS=str(args.genesis),
        STATUS=str(args.status),
    )
    source = (ROOT / "testnet/systemd/tos-election-fee-watch.service.in").read_text()
    for name, value in values.items():
        source = source.replace("@" + name + "@", value)
    if re.search(r"@[A-Z_]+@", source):
        raise RuntimeError("unrendered unit variable")
    service = destination / "tos-election-fee-watch.service"
    timer = destination / "tos-election-fee-watch.timer"
    service.write_text(source)
    timer.write_bytes((ROOT / "testnet/systemd/tos-election-fee-watch.timer").read_bytes())
    subprocess.run(["systemd-analyze", "--user", "verify", str(service), str(timer)], check=True)
    if args.apply:
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "--user", "enable", "--now", timer.name], check=True)
    print("INSTALLED" if args.apply else "RENDERED", revision)


if __name__ == "__main__":
    main()
