#!/usr/bin/env python3
"""Pinned-key four-signer certificate gate for the epoch-6 public testnet (read-only).

For one recent masterchain block H that the named sources agree on, it proves:

  * H's header and finality certificate arrive in one forward BlockLink from H's governing key block
    (liteServer.getBlockProof). con01_history.certificate.verify_link checks the link:
    - the key block's config proof root and H's header proof root against their block ids;
    - prev_key_block_seqno, catchain seqno and validator-list hash against the certificate;
    - the session id;
    - every ML-DSA-44 signature against the key block's ConfigParam 34.
  * That ConfigParam 34 has exactly the four genesis members: validator id -> public key, read from the epoch-6
    zero state, whose root and file hash are pinned in this file and must also match the given global config.
    All weights are equal.
  * All four members signed.
  * H is fresh. Its proven gen_utime is at or after --since, at most --max-age seconds old, not more than
    --future-tolerance seconds ahead, and inside the set's term.

Sources are named hosts, resolved through the tunnel units: each unit's -L port:127.0.0.1:8081 root@address
must name that host's inventory address. The host under test (--exclude) is never a source.

It is not a proof chain from genesis to H. The pin is the key set; that the sources report the same chain is
detection.

Exit 0 PASS, 1 FAIL (terminal: bad evidence, signature, binding, identity or pin), 2 INCONCLUSIVE (a source
unreachable, or --wait expired while only "no eligible block yet" or "fewer than four signers" held).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import re
import struct
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / "production"))

import testnet_lib as lib  # noqa: E402
import network_check as shared  # noqa: E402
from con01_history import formats as f  # noqa: E402
from con01_history.certificate import Refused, identity, source_params, verify_link  # noqa: E402

# The approved epoch-6 zero state (global config "validator.zero_state", published 2026-10). A substituted
# global config and zerostate pair fails here.
EPOCH6_ZERO_STATE = {
    "workchain": -1,
    "shard": -9223372036854775808,
    "seqno": 0,
    "root_hash": "/2BFnLilFwhUgpCvoW/U34DRZ3W/PBM5IUam0bVmLVc=",
    "file_hash": "OzdN9evRg2jUvw6zdHBHcdr42s2FF1YF87/Rx6kioDk=",
}
EPOCH6_GLOBAL_ID = 2
MEMBERS = 4
TUNNEL_UNITS = ("e6-tun-n1", "e6-tun-n2", "e6-tun-n3", "e6-tun-n4")
FORWARD = re.compile(r"\s-L\s+(\d+):127\.0\.0\.1:8081\s+root@([0-9.]+)\s*$")
SHARD = "-9223372036854775808"


class Fail(Exception):
    """Terminal: the evidence is wrong."""


class Retry(Exception):
    """Retryable within --wait: no eligible block yet, or fewer than four signers yet."""


class Unreachable(Exception):
    pass


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise Fail(reason)


# ---------------------------------------------------------------- pins and sources


def genesis_members(global_config: dict[str, Any], zerostate: bytes) -> dict[bytes, bytes]:
    """Genesis validator id -> ML-DSA-44 public key, from the pinned epoch-6 zero state."""
    zs = global_config.get("validator", {}).get("zero_state", {})
    need(
        {k: zs.get(k) for k in EPOCH6_ZERO_STATE} == EPOCH6_ZERO_STATE,
        "global config zero_state is not the pinned epoch-6 zero state",
    )
    need(
        hashlib.sha256(zerostate).digest() == base64.b64decode(EPOCH6_ZERO_STATE["file_hash"]),
        "zerostate file hash is not the pinned epoch-6 file hash",
    )
    root, global_id, params = lib.zero_state_config(zerostate)
    need(root.hash() == base64.b64decode(EPOCH6_ZERO_STATE["root_hash"]), "zerostate root hash mismatch")
    need(global_id == EPOCH6_GLOBAL_ID, f"zero state global id {global_id} is not {EPOCH6_GLOBAL_ID}")
    need(34 in params, "zero state has no ConfigParam 34")
    vset = shared.decode_set(params[34])
    members = {}
    for row in vset["validators"]:
        need(row["algorithm"] == 1, "genesis member is not ML-DSA-44")
        vid, pk = bytes.fromhex(row["id"]), bytes.fromhex(row["public_key"])
        need(vid not in members, "duplicate genesis validator id")
        members[vid] = pk
    need(len(members) == MEMBERS, f"genesis set has {len(members)} members, not {MEMBERS}")
    need(len(set(members.values())) == MEMBERS, "genesis public keys are not distinct")
    return members


def tunnel_inventory(unit_dir: Path, inventory: dict[str, Any]) -> dict[str, str]:
    """Approved host -> loopback RPC URL, from the tunnel units checked against the host inventory."""
    address = {h["name"]: h["address"] for h in inventory["hosts"]}
    by_address = {v: k for k, v in address.items()}
    need(len(by_address) == len(address), "inventory addresses are not distinct")
    out: dict[str, str] = {}
    for unit in TUNNEL_UNITS:
        text = (unit_dir / f"{unit}.service").read_text()
        lines = [l for l in text.splitlines() if l.startswith("ExecStart=")]
        need(len(lines) == 1, f"{unit}: expected one ExecStart")
        m = FORWARD.search(lines[0])
        need(m is not None, f"{unit}: no -L port:127.0.0.1:8081 root@address forward")
        port, addr = m.group(1), m.group(2)
        need(addr in by_address, f"{unit}: {addr} is not an inventory host")
        host = by_address[addr]
        need(host not in out, f"{unit}: {host} has more than one tunnel")
        out[host] = f"http://127.0.0.1:{port}/jsonRPC"
    need(len(set(out.values())) == len(out), "two tunnels share one port")
    return out


def choose_sources(requested: list[str], exclude: str | None, approved: dict[str, str]) -> dict[str, str]:
    need(len(requested) == len(set(requested)), "duplicate source host")
    need(len(requested) >= 3, "at least three source hosts required")
    for host in requested:
        need(host in approved, f"{host} has no approved tunnel")
        need(host != exclude, f"{host} is the host under test and cannot be a source")
    if exclude is not None:
        need(exclude in approved, f"--exclude {exclude} is not an approved host")
    return {h: approved[h] for h in requested}


# ---------------------------------------------------------------- reads


class Rpc:
    def __init__(self, url: str):
        self.url = url
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, method: str, **params: Any) -> Any:
        if method not in {"getMasterchainInfo", "getBlockHeader", "getProofQuery"}:
            raise Fail(f"method {method} is not in the read-only allowlist")
        body = json.dumps(dict(jsonrpc="2.0", id=1, method=method, params=params)).encode()
        req = urllib.request.Request(self.url, body, {"Content-Type": "application/json"})
        try:
            with self.opener.open(req, timeout=20) as reply:
                answer = json.loads(reply.read(8 * 1024 * 1024 + 1))
        except OSError as exc:
            raise Unreachable(f"{self.url}: {exc}") from exc
        if not isinstance(answer, dict) or "result" not in answer:
            raise Unreachable(f"{self.url} {method}: {str(answer.get('error'))[:160]}")
        time.sleep(0.25)
        return answer["result"]


WINDOW = 8  # consecutive blocks whose certificates together must carry all four signers


def capture(rpcs: dict[str, Rpc], back: int = 3, window: int = WINDOW) -> dict[str, Any]:
    """One attempt's raw evidence from every source, for `window` consecutive common blocks ending at head-back.

    A simplex finality certificate carries a quorum (3 of 4 here), not necessarily every member, so the
    four-signer requirement is over consecutive recent certificates, each fully verified.
    """
    heads = {h: r.call("getMasterchainInfo")["last"] for h, r in rpcs.items()}
    top = min(b["seqno"] for b in heads.values()) - back
    out: dict[str, Any] = {"seqnos": list(range(top - window + 1, top + 1)), "sources": {}}
    for host, r in rpcs.items():
        blocks, configs = {}, {}
        for seqno in out["seqnos"]:
            hdr = r.call("getBlockHeader", workchain=-1, shard=SHARD, seqno=seqno)
            k = hdr["prev_key_block_seqno"]
            if k not in configs:
                # Only the key block's id is needed, to ask for the forward link from it. The link's own config
                # proof, which verify_link checks against this id, is the set the gate trusts.
                configs[k] = {"key_header": r.call("getBlockHeader", workchain=-1, shard=SHARD, seqno=k)}
            key = configs[k]["key_header"]
            proof_q = f.B(f.T("proof") + struct.pack("<I", 1) + f.bid(key["id"])[4:] + f.bid(hdr["id"])[4:])
            blocks[seqno] = {"header": hdr, "proof_reply": r.call("getProofQuery", query=proof_q)["reply"]}
        out["sources"][host] = {"head": heads[host], "blocks": blocks, "configs": configs}
    return out


# ---------------------------------------------------------------- evaluation


def governing_set(link: dict[str, Any]) -> tuple[dict[bytes, bytes], set[int]]:
    """The governing key block's members (validator id -> public key) and the set of their weights, from the
    config proof that verify_link has already checked against the key block."""
    params = source_params(link["config"], link["src"])
    vset = f.validators(params[34].c.slice().ref())
    return {vid: m["pk"] for vid, m in vset["members"].items()}, {m["weight"] for m in vset["members"].values()}


def evaluate(
    cap: dict[str, Any],
    pinned: dict[bytes, bytes],
    verify_signature: Callable[[bytes, bytes, bytes], None],
    since: int,
    now: float,
    max_age: int,
    future: int,
) -> dict[str, Any]:
    """PASS facts, or raise Fail (terminal) / Retry (retryable).

    Every block of the window, from every source, is verified in full before any retry decision, so a
    retryable condition can never hide an invalid signature or conflicting evidence."""
    seqnos = cap["seqnos"]
    need(len(seqnos) >= 1 and seqnos == list(range(seqnos[0], seqnos[0] + len(seqnos))), "window is not consecutive")
    hosts = list(cap["sources"])
    for seqno in seqnos:
        ids = {identity(cap["sources"][h]["blocks"][seqno]["header"]["id"]) for h in hosts}
        need(len(ids) == 1, f"sources disagree on block {seqno}'s full id")
    retry: list[str] = []
    per_source: dict[str, Any] = {}
    for host in hosts:
        s = cap["sources"][host]
        signers: set[bytes] = set()
        gens = []
        for seqno in seqnos:
            jh = s["blocks"][seqno]["header"]
            need(identity(jh["id"])[2] == seqno, f"{host}: header is not block {seqno}")
            k = jh["prev_key_block_seqno"]
            c = s["configs"].get(k)
            need(c is not None, f"{host}: no key block header for key block {k}")
            try:
                _start, end, links = f.forward_proof(f.D(s["blocks"][seqno]["proof_reply"]))
                need(len(links) == 1, f"{host}: expected one forward link key block {k} -> {seqno}")
                link = links[0]
                need(identity(end) == identity(jh["id"]), f"{host}: proof does not end at block {seqno}")
                result = verify_link(link, verify_signature, expected_source=c["key_header"]["id"])
                members, weights = governing_set(link)
            except (AssertionError, Refused, KeyError, ValueError, IndexError, struct.error) as exc:
                raise Fail(f"{host}: block {seqno}: {type(exc).__name__}: {exc}") from exc
            need(members == pinned, f"{host}: block {seqno}: governing set is not the four pinned genesis keys")
            need(len(weights) == 1, f"{host}: governing set weights are not equal")
            header = result["header"]
            # The JSON header only chose the query; the proven header must agree with it.
            need(
                (header["gen_utime"], header["prevkey"], header["cc"], header["vhash"])
                == (jh["gen_utime"], jh["prev_key_block_seqno"], jh["catchain_seqno"], jh["validator_list_hash_short"]),
                f"{host}: block {seqno}: JSON header disagrees with the proven header",
            )
            need(result["term_schedule"] == "within_schedule", f"{host}: block {seqno} is outside its set's term")
            gen = header["gen_utime"]
            need(gen <= now + future, f"{host}: block {seqno} gen_utime {gen} is in the future")
            need(now - gen <= max_age, f"{host}: block {seqno} is {int(now - gen)} s old (max {max_age})")
            if gen < since:
                retry.append(f"block {seqno} predates --since ({gen} < {since})")
            signers |= {f.D(x["validator_id"]) for x in link["cert"]["signatures"]}
            gens.append(gen)
        need(signers <= set(pinned), f"{host}: a signer outside the pinned set")
        if signers != set(pinned):
            retry.append(f"{host}: {len(signers)} of {MEMBERS} signers across blocks {seqnos[0]}..{seqnos[-1]}")
        head_age = now - s["head"].get("gen_utime", gens[-1]) if isinstance(s["head"], dict) else 0
        per_source[host] = {"signers": len(signers), "first_gen_utime": gens[0], "last_gen_utime": gens[-1]}
    if retry:
        raise Retry("; ".join(retry[:3]))
    return {
        "verdict": "PASS-FOUR-SIGNER-PINNED-KEYS",
        "seqnos": [seqnos[0], seqnos[-1]],
        "last_id": cap["sources"][hosts[0]]["blocks"][seqnos[-1]]["header"]["id"],
        "sources": per_source,
    }


def mldsa_raising() -> Callable[[bytes, bytes, bytes], None]:
    spec = importlib.util.spec_from_file_location("check_handover", HERE / "check-handover.py")
    ch = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ch)
    verify = ch.mldsa44_verifier()

    def check(pk: bytes, sig: bytes, msg: bytes) -> None:
        if not verify(pk, msg, sig):
            raise Refused("ML-DSA-44 signature does not verify")

    return check


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--global-config", type=Path, required=True)
    ap.add_argument("--zerostate", type=Path, required=True)
    ap.add_argument("--inventory", type=Path, required=True)
    ap.add_argument("--unit-dir", type=Path, default=Path.home() / ".config/systemd/user")
    ap.add_argument("--source", action="append", default=[], help="source host name, e.g. node-1 (≥ 3)")
    ap.add_argument("--exclude", default=None, help="the host under test; never a source")
    ap.add_argument("--since", type=int, required=True, help="unix time the block must not predate")
    ap.add_argument("--max-age", type=int, default=60)
    ap.add_argument("--future-tolerance", type=int, default=5)
    ap.add_argument("--wait", type=int, default=0, help="seconds to retry retryable conditions")
    ap.add_argument("--out", type=Path, default=None, help="write the verdict and raw evidence here")
    a = ap.parse_args()
    try:
        pinned = genesis_members(json.loads(a.global_config.read_text()), a.zerostate.read_bytes())
        sources = choose_sources(a.source, a.exclude, tunnel_inventory(a.unit_dir, json.loads(a.inventory.read_text())))
        rpcs = {h: Rpc(u) for h, u in sources.items()}
        verify_signature = mldsa_raising()
        deadline = time.monotonic() + a.wait
        attempts = []
        while True:
            try:
                cap = capture(rpcs)
                verdict = evaluate(cap, pinned, verify_signature, a.since, time.time(), a.max_age, a.future_tolerance)
                code = 0
                break
            except Retry as exc:
                attempts.append({"at": time.time(), "retry": str(exc)})
                if time.monotonic() >= deadline:
                    verdict, code = {"verdict": "INCONCLUSIVE", "reason": f"wait expired: {exc}"}, 2
                    break
                time.sleep(10)
    except Fail as exc:
        verdict, code, cap = {"verdict": "FAIL", "reason": str(exc)}, 1, None
    except Unreachable as exc:
        verdict, code, cap = {"verdict": "INCONCLUSIVE", "reason": f"source unreachable: {exc}"}, 2, None
    verdict["checked_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if a.out is not None:
        a.out.mkdir(parents=True, exist_ok=True)
        (a.out / "VERDICT.json").write_text(json.dumps(verdict, indent=1) + "\n")
        if code != 1 and "cap" in dir() and cap is not None:
            (a.out / "evidence.json").write_text(json.dumps(cap) + "\n")
    print(json.dumps(verdict))
    return code


if __name__ == "__main__":
    sys.exit(main())
