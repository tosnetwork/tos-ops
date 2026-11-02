"""Replay a frozen copy of original streams; never rewrite original qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import time
from pathlib import Path

from . import observer
from .certificate import SignatureVerifier, require


class CachedSignatures:
    """Persistent positive-only memo; exact public input and backend digest are bound."""

    def __init__(self, path, verifier, digest):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA page_size=4096")
        self.db.execute("PRAGMA max_page_count=131072")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS verified (digest BLOB PRIMARY KEY) WITHOUT ROWID"
        )
        self.verifier = verifier
        self.prefix = bytes.fromhex(digest)
        self.pending = 0

    def __call__(self, public, signature, message):
        require(
            len(public) == 1312 and len(signature) == 2420 and len(message) <= 4096,
            "cached signature input bound",
        )
        digest = hashlib.sha256(self.prefix + public + signature + message).digest()
        if self.db.execute(
            "SELECT 1 FROM verified WHERE digest=?", (digest,)
        ).fetchone():
            return
        self.verifier(public, signature, message)
        self.db.execute("INSERT OR IGNORE INTO verified VALUES (?)", (digest,))
        self.pending += 1
        if self.pending >= 1000:
            self.db.commit()
            self.pending = 0

    def close(self):
        self.db.commit()
        self.db.close()


def snapshot(source, out):
    require(not out.exists(), "new snapshot directory required")
    out.mkdir(mode=0o700)
    inventory = []
    for folder in sorted(source.glob("src-*")):
        require(
            folder.name in {"src-node1", "src-node3", "src-node5"},
            "unexpected observer",
        )
        target = out / folder.name
        target.mkdir()
        segments = sorted(folder.glob("seg-*.jsonl"))
        for i, segment in enumerate(segments):
            dest = target / segment.name
            if i + 1 < len(segments):
                os.link(segment, dest)
            else:
                # Copy only the committed complete-line prefix of the open segment.
                length = segment.stat().st_size
                with segment.open("rb") as src, dest.open("xb") as dst:
                    while length:
                        raw = src.readline(min(length, 2 * 1024 * 1024 + 1))
                        require(
                            len(raw) <= 2 * 1024 * 1024, "snapshot record byte bound"
                        )
                        if not raw or not raw.endswith(b"\n"):
                            break
                        dst.write(raw)
                        length -= len(raw)
            inventory.append(
                dict(path=str(dest.relative_to(out)), bytes=dest.stat().st_size)
            )
    require(
        len(list(out.glob("src-*"))) == 3, "three original observer streams required"
    )
    with (
        (source / "SEALS.jsonl").open("rb") as src,
        (out / "SEALS.jsonl").open("xb") as dst,
    ):
        shutil.copyfileobj(src, dst, 1024 * 1024)
    (out / "SNAPSHOT.json").write_text(
        json.dumps(
            dict(original=str(source), created=time.time(), segments=inventory),
            indent=2,
        )
        + "\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--verifier-sha256", required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if not args.resume:
        snapshot(args.source, args.out)
    cfg = json.loads(args.config.read_bytes())
    cfg["evidence"] = str(args.out)
    cfg["cpu_fraction"] = 0.5
    (args.out / "REPLAY-CONFIG.json").write_text(json.dumps(cfg, indent=2) + "\n")
    backend = SignatureVerifier(args.verifier, args.verifier_sha256)
    cache = CachedSignatures(
        args.out / "signature-cache.sqlite", backend, args.verifier_sha256
    )
    observer.SIGNATURE_BACKEND = cache
    try:
        stage = observer.StageA(args.out, cfg)
        stage.run()
        cfg["_genesis_set"] = stage.st.get("genesis_set")
        verdict = observer.judge(observer.load_results(args.out), cfg)
        verdict["seals"] = observer.seals_check(args.out)
        if verdict["seals"]["mismatches"]:
            verdict["inconclusive"].append("sealed segment hash mismatch")
            if verdict["verdict"] == "PASS":
                verdict["verdict"] = "INCONCLUSIVE"
        # A successful judge alone is never final acceptance without revision-bound controls.
        verdict["judge_result_before_controls"] = verdict["verdict"]
        verdict["verdict"] = "INCONCLUSIVE"
        verdict["inconclusive"].append(
            "new revision requires completed independent acceptance controls"
        )
        verdict["original_unchanged"] = True
        verdict["judged_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        (args.out / "VERDICT.json").write_text(json.dumps(verdict, indent=1) + "\n")
        print(
            json.dumps(
                {
                    k: verdict[k]
                    for k in [
                        "verdict",
                        "judge_result_before_controls",
                        "rejected_count",
                        "conflicts",
                        "parent_breaks",
                        "trust_chain",
                    ]
                },
                indent=2,
            ),
            flush=True,
        )
    finally:
        cache.close()
        backend.close()


if __name__ == "__main__":
    main()
