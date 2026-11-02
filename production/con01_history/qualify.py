"""Produce a separate qualification after a frozen replay and revision-bound controls.

Never overwrite the original observer verdict or the replay's provisional verdict.
This is a technical evidence gate, not approval to enable a public service.
"""

import argparse
import hashlib
import json
from pathlib import Path

from . import observer
from .certificate import require


CONTROL_GUARDS = 18


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for part in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(part)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replay", type=Path, required=True)
    parser.add_argument("--controls", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    require(not args.out.exists(), "new qualification output required")
    root = Path(__file__).resolve().parents[2]
    control = json.loads(args.controls.read_bytes())
    require(control["result"] == "PASS", "completed controls required")
    rows = control["rows"]
    require(
        len(rows) == CONTROL_GUARDS + 2,
        "complete guard controls plus baseline/restoration required",
    )
    require(
        rows[0]["name"] == "baseline"
        and rows[0]["exit"] == 0
        and rows[-1]["name"] == "restored"
        and rows[-1]["exit"] == 0,
        "green baseline and restoration required",
    )
    require(
        all(row["exit"] == 1 and row["test"] for row in rows[1:-1]),
        "runtime guard removals required",
    )
    for name, digest in control["files"].items():
        path = root / name
        require(
            path.resolve().is_relative_to(root.resolve()),
            "control file outside checkout",
        )
        require(sha(path) == digest, "control revision changed: " + name)
    provenance = json.loads((args.replay / "REPLAY-PROVENANCE.json").read_bytes())
    for name, digest in provenance["source_sha256"].items():
        require(
            sha(Path(__file__).with_name(name)) == digest,
            "replay source revision changed: " + name,
        )
    require(
        (args.replay / "VERDICT.json").exists(),
        "replay must finish before qualification",
    )
    snapshot = json.loads((args.replay / "SNAPSHOT.json").read_bytes())
    state = json.loads((args.replay / "verified/state.json").read_bytes())
    require(
        {Path(segment["path"]).parts[0] for segment in snapshot["segments"]}
        == {"src-node1", "src-node3", "src-node5"},
        "three frozen original source inventories required",
    )
    for segment in snapshot["segments"]:
        path = args.replay / segment["path"]
        require(
            path.resolve().is_relative_to(args.replay.resolve()),
            "snapshot path outside replay",
        )
        require(path.stat().st_size == segment["bytes"], "frozen segment size changed")
        require(
            state["offsets"].get(segment["path"]) == segment["bytes"],
            "incomplete frozen replay: " + segment["path"],
        )
    cfg = json.loads((args.replay / "REPLAY-CONFIG.json").read_bytes())
    cfg["_genesis_set"] = state.get("genesis_set")
    verdict = observer.judge(observer.load_results(args.replay), cfg)
    verdict["seals"] = observer.seals_check(args.replay)
    if verdict["seals"]["mismatches"]:
        verdict["inconclusive"].append("sealed segment hash mismatch")
        verdict["verdict"] = "INCONCLUSIVE" if verdict["verdict"] != "FAIL" else "FAIL"
    verdict["controls_sha256"] = sha(args.controls)
    verdict["replay_provenance_sha256"] = sha(args.replay / "REPLAY-PROVENANCE.json")
    verdict["verified_result_files"] = {
        path.name: sha(path)
        for path in sorted((args.replay / "verified").glob("results-*.jsonl"))
    }
    verdict["scope"] = (
        "Historical evidence qualification only; no deployment approval or repair of missing observations."
    )
    with args.out.open("x") as destination:
        json.dump(verdict, destination, indent=2)
        destination.write("\n")
    print(
        json.dumps(
            {key: verdict[key] for key in ("verdict", "rejected_count", "trust_chain")}
        )
    )


if __name__ == "__main__":
    main()
