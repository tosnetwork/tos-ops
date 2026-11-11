#!/usr/bin/env python3
"""Freeze producer samples for the T1 judge's fixture from a live observer and load directory.

    python testnet/tests/capture_t1_samples.py OBSERVE_DIR [LOAD_DIR] --producers JSON --out SAMPLES.json

For every schema in t1_evidence.SCHEMAS, the first row of a live file that classifies to it and satisfies it is
kept verbatim, with its provenance (file, line, sha256 of the exact line bytes). Schemas with no live row are
listed as not captured. Public data only: the observer's host series, chain ids and operator balances, the load
supervisor's lifecycle rows, the ramp journal (public transactions and addresses) and the read client's records.
Not collected by pytest.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import t1_evidence as E  # noqa: E402


def lines(path: Path):
    for i, raw in enumerate(path.read_bytes().split(b"\n")):
        if raw.strip():
            try:
                yield i + 1, raw, E.parse(raw)
            except ValueError:
                continue


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("observe", type=Path)
    ap.add_argument("load", type=Path, nargs="?")
    ap.add_argument("--producers", required=True, help="JSON {producer: commit} the live run used")
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    samples = {}

    def take(name, r, file, line, raw):
        if name == "cache/read" and r.get("baseline") is not False:
            return  # the fixture clones a steady read; the baseline is the same row with baseline set
        if name and name not in samples and all(k in r and c(r[k]) for k, c in E.SCHEMAS[name].items()):
            samples[name] = {"record": r, "file": file, "line": line, "sha256": hashlib.sha256(raw).hexdigest()}

    for file in E.OBSERVER_FILES:
        p = a.observe / f"{file}.jsonl"
        if p.exists():
            for line, raw, r in lines(p):
                take(E.classify(file, r), r, str(p), line, raw)
    if a.load:
        p = a.load / "load.jsonl"
        if p.exists():
            for line, raw, r in lines(p):
                take(E.classify("load", r), r, str(p), line, raw)
        p = a.load / "ramp" / "journal.jsonl"
        if p.exists():
            rows = list(lines(p))
            roles = {r.get("id"): r.get("role") for _, _, r in rows if r.get("type") == "attempt"}
            for line, raw, r in rows:
                t = r.get("type")
                name = (f"journal/attempt/{r.get('role')}" if t == "attempt"
                        else f"journal/observed/{roles.get(r.get('id'))}" if t == "observed"
                        else f"journal/{t}")
                take(name if name in E.SCHEMAS else None, r, str(p), line, raw)
        reads = a.load / "reads"
        for fname, name in (("CONTEXT.json", "reads/context"), ("RESULT.json", "reads/result")):
            p = reads / fname
            if p.exists():
                raw = p.read_bytes()
                take(name, E.parse(raw), str(p), 1, raw)
        p = reads / "requests.jsonl"
        if p.exists():
            for line, raw, r in lines(p):
                take("reads/request", r, str(p), line, raw)
    out = {"producers": json.loads(a.producers), "samples": samples,
           "not_captured": sorted(set(E.SCHEMAS) - set(samples))}
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    print(f"captured {len(samples)} of {len(E.SCHEMAS)} schemas; not captured: {out['not_captured']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
