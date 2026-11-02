"""Freeze worker inputs and refuse a changed configuration/revision before resuming."""

import argparse
import json
import os
from pathlib import Path
import sys

from .certificate import require
from .qualify import WORKER_MODULES, sha
from ._replay import snapshot


INPUT_FILES = {
    "APPROVED-CONFIG.json",
    "REPLAY-CONFIG.json",
    "SNAPSHOT.json",
    "SEALS.jsonl",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "config", "out", "verifier"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--verifier-sha256", required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    require(not sys.flags.optimize, "optimized Python cannot verify evidence")
    package = Path(__file__).parent
    approved = args.out / "APPROVED-CONFIG.json"
    manifest = args.out / "REPLAY-INPUTS.json"
    if not args.resume:
        snapshot(args.source, args.out)
        approved.write_bytes(args.config.read_bytes())
        cfg = json.loads(approved.read_bytes())
        cfg["evidence"] = str(args.out)
        cfg["cpu_fraction"] = 0.5
        (args.out / "REPLAY-CONFIG.json").write_text(json.dumps(cfg, indent=2) + "\n")
        (args.out / "REPLAY-PROVENANCE.json").write_text(
            json.dumps(
                dict(
                    source_sha256={
                        name: sha(package / name) for name in WORKER_MODULES
                    },
                    positive_crypto_cache_entries=0,
                ),
                indent=2,
            )
            + "\n"
        )
        manifest.write_text(
            json.dumps(
                dict(
                    files={name: sha(args.out / name) for name in INPUT_FILES},
                    verifier_sha256=args.verifier_sha256,
                ),
                indent=2,
            )
            + "\n"
        )
    pins = json.loads(manifest.read_bytes())
    require(
        set(pins["files"]) == INPUT_FILES, "complete frozen input inventory required"
    )
    require(
        pins["verifier_sha256"] == args.verifier_sha256,
        "resume verifier digest changed",
    )
    for name, digest in pins["files"].items():
        require(
            sha(args.out / name) == digest,
            "frozen input changed before resume: " + name,
        )
    require(
        sha(approved) == sha(args.config),
        "approved configuration changed before resume",
    )
    inventory = json.loads((args.out / "SNAPSHOT.json").read_bytes())
    require(
        Path(inventory["original"]).resolve() == args.source.resolve(),
        "resume source changed",
    )
    provenance = json.loads((args.out / "REPLAY-PROVENANCE.json").read_bytes())
    worker_files = {
        name: ("_replay.py" if name == "rejudge.py" else name)
        for name in provenance["source_sha256"]
    }
    require(
        len(worker_files) == len(WORKER_MODULES)
        and set(worker_files.values()) == WORKER_MODULES,
        "complete worker revision inventory required",
    )
    for name, digest in provenance["source_sha256"].items():
        require(
            sha(package / worker_files[name]) == digest,
            "worker revision changed before resume: " + name,
        )
    worker_config = json.loads(approved.read_bytes())
    worker_config["evidence"] = str(args.out)
    worker_config["cpu_fraction"] = 0.5
    expected_worker_config = (json.dumps(worker_config, indent=2) + "\n").encode()
    require(
        expected_worker_config == (args.out / "REPLAY-CONFIG.json").read_bytes(),
        "resume config representation changed before worker invocation",
    )
    os.execv(
        sys.executable,
        [
            sys.executable,
            "-B",
            "-m",
            "con01_history._replay",
            "--resume",
            "--source",
            str(args.source),
            "--config",
            str(approved),
            "--out",
            str(args.out),
            "--verifier",
            str(args.verifier),
            "--verifier-sha256",
            args.verifier_sha256,
        ],
    )


if __name__ == "__main__":
    main()
