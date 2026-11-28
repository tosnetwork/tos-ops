"""Copy the public acceptance evidence into the repository, byte for byte, with an index.

Only public data is copied: step results, archived TOS transaction cells and block
headers, source receipts and finality, monitor reports and resolution records. The
private journal (state.json: signed messages) and keys are never copied."""
import hashlib, json, shutil, sys
from pathlib import Path

src = Path("/data/stablecoin-acceptance")
dst = Path(sys.argv[1])
PUBLIC = ("evidence", "archive/sends", "archive/monitor", "source-transactions", "source-finality", "incident-resolution")
files = []
for top in PUBLIC:
    base = src / top
    if not base.exists():
        continue
    for path in sorted(p for p in base.rglob("*") if p.is_file()):
        rel = path.relative_to(src)
        if path.name.endswith((".pending", ".lock")):
            continue
        data = path.read_bytes()
        out = dst / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        files.append({"file": str(rel), "original_sha256": digest, "sha256": digest, "removed_fields": []})
# The token-actor driver's public records of the fee cases: archived transaction
# graphs and the second resolver's outputs. Its send receipts are not copied.
actor = Path("/data/service-token-usdt-t18")
for top in ("archive/call-fee-nominal-1001001", "archive/call-fee-minted-1000000",
            "archive/send-fee-minted-expire", "archive/send-fee-minted-refund"):
    for path in sorted(p for p in (actor / top).rglob("*") if p.is_file()):
        rel = Path("actor-usdt") / path.relative_to(actor)
        data = path.read_bytes(); out = dst / rel
        out.parent.mkdir(parents=True, exist_ok=True); out.write_bytes(data)
        d = hashlib.sha256(data).hexdigest()
        files.append({"file": str(rel), "original_sha256": d, "sha256": d, "removed_fields": []})
for path in sorted((actor / "archive/verifiers").glob("verify-fee-*")) + sorted((actor / "evidence").glob("verify-fee-*")):
    rel = Path("actor-usdt") / path.relative_to(actor)
    data = path.read_bytes(); out = dst / rel
    out.parent.mkdir(parents=True, exist_ok=True); out.write_bytes(data)
    d = hashlib.sha256(data).hexdigest()
    files.append({"file": str(rel), "original_sha256": d, "sha256": d, "removed_fields": []})
for path in sorted(Path("/data/stablecoin-acceptance/provider-actions").rglob("*.json")):
    rel = Path("provider-actions") / path.relative_to("/data/stablecoin-acceptance/provider-actions")
    data = path.read_bytes(); out = dst / rel
    out.parent.mkdir(parents=True, exist_ok=True); out.write_bytes(data)
    d = hashlib.sha256(data).hexdigest()
    files.append({"file": str(rel), "original_sha256": d, "sha256": d, "removed_fields": []})
# The monitor's gap reconciliation after its 2026-11-27 23:57 failure: every
# batch, the gap-including tick and the post-restart provider check.
for base, prefix in ((Path("/data/usdt-t15-monitor-gap-20261128"), "monitor-recovery/gap-batches"),
                     (Path("/tos/stablecoin-acceptance-logs/gap-reconciliation"), "monitor-recovery")):
    for path in sorted(p for p in base.iterdir() if p.is_file()):
        rel = Path(prefix) / path.name
        data = path.read_bytes(); out = dst / rel
        out.parent.mkdir(parents=True, exist_ok=True); out.write_bytes(data)
        d = hashlib.sha256(data).hexdigest()
        files.append({"file": str(rel), "original_sha256": d, "sha256": d, "removed_fields": []})
index = {"schema": "local-stablecoin-acceptance-evidence/1", "files": files}
(dst / "INDEX.json").write_text(json.dumps(index, indent=1, sort_keys=True) + "\n")
print(len(files), "files")
