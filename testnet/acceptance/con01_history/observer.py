#!/usr/bin/env python3
"""CON-01 live verifier (offline; no network).

Stage A (`--incremental`): reads each source's hash-chained evidence stream from the last
processed byte, checks stream integrity, independently verifies every finality certificate
(`verify.verify_link`, pinned), key-block configs, shard inclusion proofs, and appends compact
results to verified/results-<src>.jsonl.  Stage B (`--verdict`): judges the pre-declared rules
of PLAN.md section 7 over those results.  `--controls` runs the red controls on scratch copies.
"""

import collections
import hashlib
import json
import os
import sys
import time

from . import formats
from .certificate import Refused, identity, source_params
from .certificate import verify_link as verify_certificate
from .formats import (
    TL,
    Cell,
    D,
    block_header,
    dictionary,
    forward_proof,
    key_config_reply,
    validators,
    virtual,
)

SIGNATURE_BACKEND = None


def verify_link(link, params):
    try:
        actual = source_params(link["config"], link["src"])
        assert (
            validators(actual[34].c.slice().ref())["cell_hash"]
            == validators(params[34].c.slice().ref())["cell_hash"]
        ), "validator set differs from trusted source"
        return verify_certificate(link, SIGNATURE_BACKEND)
    except Refused as error:
        raise AssertionError(str(error)) from error


class _Param:
    """ConfigParam 19 stand-in for genesis-sourced links: the zerostate config proof prunes
    CP19; global id 2 is instead authenticated by every proved block header (block_header)."""

    def __init__(self, gid=2):
        self.c = Cell(0, 0, b"", [Cell(0, 8, gid.to_bytes(4, "big"), [])])


def zerostate_params(cfg_root):
    assert cfg_root.data[:8] == bytes.fromhex("9023afe200000002"), (
        "not a zerostate root"
    )
    mc = cfg_root.refs[3]
    s = mc.slice()
    assert s.u(16) == 0xCC26
    if s.u(1):
        s.ref()
    s.raw(32)
    params = dictionary(s.ref(), 32)
    assert 19 not in params
    params[19] = _Param()
    return params


def set_summary(params, n):
    if n not in params:
        return None
    v = validators(params[n].c.slice().ref())
    return dict(
        hash=v["cell_hash"].hex(),
        since=v["since"],
        until=v["until"],
        weight=v["weight"],
        members=sorted(k.hex() for k in v["members"]),
        keys=sorted(
            (k.hex(), m["key_id"].hex(), m["weight"]) for k, m in v["members"].items()
        ),
    )


def ids(b):
    return [b["root_hash"], b["file_hash"]]


BACK = "liteServer.blockLinkBack to_key_block:Bool from:tosNode.blockIdExt to:tosNode.blockIdExt dest_proof:bytes proof:bytes state_proof:bytes = liteServer.BlockLink"
UNSUPPORTED = "unsupported proof shape (no own certificate)"


def routed_proof(data):
    """partialBlockProof of exactly [forward S->k, backward k->n]: returns (forward link, n id, n header root)."""
    t = TL(data)
    assert t.take(4) == formats.tag(formats.PARTIAL) and t.take(4) == bytes.fromhex(
        "b5757299"
    )
    _start, end = t.blockid(), t.blockid()
    assert t.u() == 2, "routed proof must have two links"
    head = t.p
    assert t.take(4) == formats.tag(formats.FORWARD)
    t.take(4)
    t.blockid()
    t.blockid()
    t.bytes()
    t.bytes()
    assert t.take(4) == formats.tag(formats.PQSET)
    t.u()
    t.u()
    n = t.u()
    assert 0 < n <= 100
    for _ in range(n):
        t.take(32)
        t.u()
        t.bytes()
    t.take(32)
    t.u()
    t.bytes()
    fwd_end = t.p
    # re-parse the forward link with the pinned parser by framing it as a one-link proof
    one = (
        formats.tag(formats.PARTIAL)
        + bytes.fromhex("b5757299")
        + data[8 : 8 + 160]
        + (1).to_bytes(4, "little")
        + data[head:fwd_end]
    )
    _, _, links = forward_proof(one)
    assert t.take(4) == formats.tag(BACK), "second link is not a backward link"
    t.take(4)
    src, dst = t.blockid(), t.blockid()
    dest = t.bytes()
    t.bytes()
    t.bytes()
    assert t.p == len(data)
    assert identity(src) == identity(links[0]["dst"]), (
        "backward link does not start at the certified key block"
    )
    assert identity(dst) == identity(end)
    return links[0], dst, virtual(dest)


class CertificateUnavailable(ValueError):
    """An explicit missing RPC response supplies no certificate to reject."""


MISSING_CERTIFICATE = {
    "code": -32004,
    "message": "BLOCK_UNAVAILABLE",
    "data": {"schema_version": 1, "reason": "BLOCK_UNAVAILABLE", "retryable": False},
}


def cert_from_sigs(raw):
    r = json.loads(raw)
    error = r.get("error")
    if (
        "result" not in r
        and error == MISSING_CERTIFICATE
        and type(error["code"]) is int
        and type(error["data"]["schema_version"]) is int
        and error["data"]["retryable"] is False
    ):
        raise CertificateUnavailable("BLOCK_UNAVAILABLE")
    assert "result" in r, "signature set error " + json.dumps(r.get("error"))[:200]
    r = r["result"]
    return dict(
        id=r["id"],
        cc_seqno=r["cc_seqno"],
        validator_set_hash=r["validator_set_hash"],
        session_id=r["session_id"],
        slot=r["slot"],
        candidate=r["candidate"],
        signatures=[
            dict(
                validator_id=x["validator_id"],
                algorithm_id=x["algorithm_id"],
                signature=x["signature"],
            )
            for x in r["signatures"]
        ],
    )


# ---- stage A ------------------------------------------------------------------------
class StageA:
    def __init__(self, evidence, cfg):
        self.ev, self.cfg = evidence, cfg
        self.out = evidence / "verified"
        self.out.mkdir(exist_ok=True)
        self.state_path = self.out / "state.json"
        self.st = (
            json.loads(self.state_path.read_text())
            if self.state_path.exists()
            else dict(offsets={}, chain={}, keys_raw={}, key_roots={})
        )
        self.keys = {}  # key seqno -> params (decoded, trusted only)
        for k, raws in self.st["keys_raw"].items():
            for raw in raws:
                try:
                    b, params, root = key_config_reply(D(raw))
                    if self.st["key_roots"].get(k) == b["root_hash"]:
                        self.keys[int(k)] = params
                except AssertionError:
                    pass
        formats.Cell.hd.cache_clear()
        self.init = cfg["init"]

    def throttle(self):
        """Self-imposed CPU ceiling: user units on this host have no cpu controller delegated,
        so systemd CPUQuota is not enforced. Keep (own + children) CPU / wall <= cpu_fraction."""
        frac = float(self.cfg.get("cpu_fraction", 0.2))
        t = os.times()
        cpu = t.user + t.system + t.children_user + t.children_system
        if not hasattr(self, "_t0"):
            self._t0, self._c0 = time.monotonic(), cpu
            return
        need = (cpu - self._c0) / frac - (time.monotonic() - self._t0)
        if need > 0:
            time.sleep(min(need, 5.0))

    def save(self):
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.st))
        with open(tmp) as f:
            os.fsync(f.fileno())
        os.replace(tmp, self.state_path)
        d = os.open(self.state_path.parent, os.O_RDONLY)
        try:
            os.fsync(d)
        finally:
            os.close(d)

    def verify_block(self, rec, params_for=None, init=None, sigs_override=None):
        """Return a result dict for one `block` record. Never raises."""
        init = init or self.init
        res = dict(
            t="blk",
            src=rec["src"],
            seq=rec["seqno"],
            utc=rec["utc"],
            mode=rec.get("mode"),
            ok=False,
        )
        try:
            h = json.loads(rec["hdr"])["result"]
            res.update(
                rid=ids(h["id"]),
                prevkey=h["prev_key_block_seqno"],
                gu_claim=h["gen_utime"],
                key_claim=bool(h.get("is_key_block")),
            )
            assert (
                h["id"]["seqno"] == rec["seqno"] and int(h["id"]["workchain"]) == -1
            ), "header seqno/workchain mismatch"
            p = json.loads(rec["proof"])
            assert "result" in p, "proof error " + json.dumps(p.get("error"))[:200]
            raw = D(p["result"]["reply"])
            try:
                a, b, links = forward_proof(raw)
                assert len(links) == 1, "expected one forward link"
                link = links[0]
                res["path"] = "forward"
            except AssertionError as e:
                if str(e) != "expected forward-only proof":
                    raise
                fwd, dst, dest = routed_proof(raw)
                assert identity(dst) == identity(h["id"]), (
                    "routed proof target differs from header id"
                )
                sigs = rec.get("sigs") or (sigs_override or {}).get(rec["seqno"])
                if not sigs:
                    raise AssertionError(UNSUPPORTED)
                cert = cert_from_sigs(sigs)
                link = dict(
                    src=fwd["src"], dst=dst, dest=dest, config=fwd["config"], cert=cert
                )
                res["path"] = "routed+signature-set"
            assert identity(link["dst"]) == identity(h["id"]), (
                "proof target differs from header id"
            )
            pk = h["prev_key_block_seqno"]
            if pk == 0:
                assert identity(link["src"]) == (
                    -1,
                    -9223372036854775808,
                    0,
                    D(init["root_hash"]),
                    D(init["file_hash"]),
                ), "source is not the pinned genesis"
                params = zerostate_params(link["config"])
            else:
                certified = self.st.get("certified_keys", {}).get(str(pk))
                assert certified is not None and ids(link["src"]) == certified, (
                    "source is not the previously certified full key-block id"
                )
                params = (params_for or self.keys).get(pk)
                assert params is not None, (
                    f"no trusted config for source key block {pk}"
                )
            r = verify_link(link, params)
            hh = block_header(link["dest"])
            v = validators(params[34].c.slice().ref())
            res.update(
                ok=True,
                cid=ids(link["dst"]),
                parent=[hh["parent"]["root_hash"], hh["parent"]["file_hash"]],
                parent_seq=hh["parent"]["seqno"],
                gu=hh["gen_utime"],
                key=hh["key"],
                prevkey=hh["prevkey"],
                cc=hh["cc"],
                signers=r["signers"],
                w=r["signed_weight"],
                tw=r["total_weight"],
                set=v["cell_hash"].hex(),
                since=v["since"],
                until=v["until"],
            )
            if pk == 0 and not self.st.get("genesis_set"):
                self.st["genesis_set"] = set_summary(params, 34)
        except CertificateUnavailable as e:
            res.update(
                unsupported=True,
                availability=str(e),
                reason="certificate unavailable: " + str(e),
            )
        except AssertionError as e:
            res["reason"] = str(e) or "assertion"
        except Exception as e:
            res["reason"] = f"undecodable: {type(e).__name__}: {e}"[:300]
        finally:
            formats.Cell.hd.cache_clear()
        if res.get("reason") == UNSUPPORTED:
            res["unsupported"] = True
        return res

    def keyconfig(self, rec, accepted_roots):
        res = dict(
            t="key", src=rec["src"], seq=rec["seqno"], utc=rec["utc"], trusted=False
        )
        try:
            p = json.loads(rec["resp"])
            assert "result" in p, "keyconfig error " + json.dumps(p.get("error"))[:200]
            raw = p["result"]["reply"]
            b, params, root = key_config_reply(D(raw))
            assert b["seqno"] == rec["seqno"], "keyconfig for another block"
            res.update(
                root=b["root_hash"],
                cp34=set_summary(params, 34),
                cp32=set_summary(params, 32),
                cp36=set_summary(params, 36),
            )
            cert_root = accepted_roots.get(str(rec["seqno"]))
            assert cert_root is not None, "key block not certified (yet)"
            assert cert_root == b["root_hash"], (
                "keyconfig root differs from certified key block"
            )
            res["trusted"] = True
            self.keys[rec["seqno"]] = params
            self.st["keys_raw"].setdefault(str(rec["seqno"]), [])
            if raw not in self.st["keys_raw"][str(rec["seqno"])]:
                self.st["keys_raw"][str(rec["seqno"])].append(raw)
        except AssertionError as e:
            res["reason"] = str(e) or "assertion"
        except Exception as e:
            res["reason"] = f"undecodable: {type(e).__name__}: {e}"[:300]
        finally:
            formats.Cell.hd.cache_clear()
        return res

    def shardproof(self, rec, certified):
        res = dict(
            t="shp", src=rec["src"], seq=rec["seqno"], ok=False, shard=rec.get("params")
        )
        try:
            r = json.loads(rec["resp"])["result"]
            sh = rec["params"]
            mc = certified.get(str(rec["seqno"]))
            assert mc is not None, "masterchain block not certified"
            assert ids(r["masterchain_id"]) == mc, (
                "shard proof anchored to a different masterchain id"
            )
            assert len(r["links"]) == 1
            link = r["links"][0]
            assert link["id"]["seqno"] == sh["seqno"]
            root = virtual(D(link["proof"]))
            assert root.hash() == D(mc[0]), "proof does not hash to certified root"
            m = root.refs[3].refs[3]
            x = m.slice()
            assert x.u(16) == 0xCCA5
            x.u(1)
            assert x.u(1) == 1
            shards = dictionary(x.ref(), 32)
            v = shards[sh["workchain"]].ref().slice()
            assert int(sh["shard"]) == -9223372036854775808 and v.u(1) == 0, (
                "split shard unsupported"
            )
            assert v.u(4) in (0xA, 0xB)
            seqno = v.u(32)
            v.u(32)
            v.u(64)
            v.u(64)
            assert (
                seqno == sh["seqno"]
                and v.raw(32) == D(link["id"]["root_hash"])
                and v.raw(32) == D(link["id"]["file_hash"])
            )
            res.update(
                ok=True,
                top=[
                    sh["workchain"],
                    sh["shard"],
                    seqno,
                    link["id"]["root_hash"],
                    link["id"]["file_hash"],
                ],
            )
        except AssertionError as e:
            res["reason"] = str(e) or "assertion"
        except Exception as e:
            res["reason"] = f"undecodable: {type(e).__name__}: {e}"[:300]
        finally:
            formats.Cell.hd.cache_clear()
        return res

    def run(self, max_seconds=None):
        t0 = time.monotonic()
        roots = self.st["key_roots"]
        certified = self.st.setdefault("certified_keys", {})
        for srcdir in sorted(self.ev.glob("src-*")):
            src = srcdir.name[4:]
            out = open(self.out / f"results-{src}.jsonl", "a")
            ch = self.st["chain"].setdefault(src, dict(prev="0" * 64, i=0, torn=None))
            segs = sorted(srcdir.glob("seg-*.jsonl"))
            for si, seg in enumerate(segs):
                key = f"{srcdir.name}/{seg.name}"
                pos = self.st["offsets"].get(key, 0)
                f = open(seg, "rb")
                f.seek(pos)
                tail = b""

                def lines_of(f):
                    nonlocal tail
                    while True:
                        line = f.readline(2 * 1024 * 1024 + 1)
                        if not line:
                            return
                        assert len(line) <= 2 * 1024 * 1024, (
                            "evidence record byte bound"
                        )
                        if not line.endswith(b"\n"):
                            tail = line
                            return
                        yield line[:-1]

                for raw in lines_of(f):
                    self.throttle()
                    pos += len(raw) + 1
                    try:
                        rec = json.loads(raw)
                    except ValueError:
                        out.write(
                            json.dumps(
                                dict(
                                    t="chain",
                                    src=src,
                                    seg=key,
                                    ok=False,
                                    reason="invalid JSON line",
                                )
                            )
                            + "\n"
                        )
                        continue
                    ok = rec.get("prev") == ch["prev"] and rec.get("i") == ch["i"] + 1
                    if not ok:
                        out.write(
                            json.dumps(
                                dict(
                                    t="chain",
                                    src=src,
                                    seg=key,
                                    i=rec.get("i"),
                                    ok=False,
                                    reason="hash chain or index break",
                                    expected_i=ch["i"] + 1,
                                )
                            )
                            + "\n"
                        )
                    ch["prev"], ch["i"] = (
                        hashlib.sha256(raw).hexdigest(),
                        rec.get("i", ch["i"]),
                    )
                    k = rec["kind"]
                    if k == "sigs":
                        pend = self.st.setdefault("pending", {})
                        pr = pend.pop(f"{src}:{rec['seqno']}", None)
                        if pr is None:
                            out.write(
                                json.dumps(
                                    dict(
                                        t="note",
                                        src=src,
                                        seq=rec["seqno"],
                                        note="signature set without a pending routed block",
                                    )
                                )
                                + "\n"
                            )
                            continue
                        r = self.verify_block(
                            pr, sigs_override={rec["seqno"]: rec["resp"]}
                        )
                        r["supplement_utc"] = rec["utc"]
                        out.write(json.dumps(r) + "\n")
                        continue
                    if k == "block":
                        r = self.verify_block(rec)
                        if r.get("unsupported"):
                            pend = self.st.setdefault("pending", {})
                            pend[f"{src}:{rec['seqno']}"] = rec
                            while len(pend) > 200:
                                pend.pop(next(iter(pend)))
                        if r["ok"] and r.get("key"):
                            roots.setdefault(str(r["seq"]), r["cid"][0])
                            certified[str(r["seq"])] = r["cid"]
                        out.write(json.dumps(r) + "\n")
                    elif k == "keyconfig":
                        out.write(json.dumps(self.keyconfig(rec, roots)) + "\n")
                    elif k == "shardproof":
                        out.write(json.dumps(self.shardproof(rec, certified)) + "\n")
                    elif k == "shards":
                        try:
                            tops = sorted(
                                [
                                    s["workchain"],
                                    s["shard"],
                                    s["seqno"],
                                    s["root_hash"],
                                    s["file_hash"],
                                ]
                                for s in json.loads(rec["resp"])["result"]["shards"]
                            )
                        except Exception:
                            tops = None
                        out.write(
                            json.dumps(
                                dict(t="shards", src=src, seq=rec["seqno"], tops=tops)
                            )
                            + "\n"
                        )
                    elif k == "head":
                        try:
                            hd = json.loads(rec["resp"])["result"]["last"]["seqno"]
                        except Exception:
                            hd = None
                        out.write(
                            json.dumps(dict(t="head", src=src, utc=rec["utc"], head=hd))
                            + "\n"
                        )
                    elif k == "gap":
                        out.write(
                            json.dumps(
                                dict(
                                    t="gap",
                                    src=src,
                                    lo=rec["seqno"],
                                    hi=rec["seqno_hi"],
                                    stage=rec.get("stage"),
                                    utc=rec["utc"],
                                    err=(rec.get("errors") or [""])[0][:300],
                                )
                            )
                            + "\n"
                        )
                    elif k in ("start", "stop", "heartbeat", "refuse", "keyhdr"):
                        out.write(
                            json.dumps(
                                dict(
                                    t=k,
                                    src=src,
                                    utc=rec["utc"],
                                    outage_s=rec.get("outage_s"),
                                    resume_after=rec.get("resume_after"),
                                    torn=rec.get("torn_tail"),
                                    err=rec.get("error"),
                                    boot=rec.get("boot"),
                                )
                            )
                            + "\n"
                        )
                        if k == "start" and rec.get("torn_tail"):
                            ch["torn"] = rec["torn_tail"]
                f.close()
                if tail and si + 1 < len(segs):
                    out.write(
                        json.dumps(
                            dict(t="torn", src=src, seg=key, partial_bytes=len(tail))
                        )
                        + "\n"
                    )
                    pos += len(tail)
                # results must be durable before the offset that skips their input is persisted
                out.flush()
                os.fsync(out.fileno())
                self.st["offsets"][key] = pos
                self.save()
                if max_seconds and time.monotonic() - t0 > max_seconds:
                    break
            out.close()
        self.save()


# ---- stage B ------------------------------------------------------------------------
BOUNDS = dict(
    window_s=600,  # W(b) = gen_utime in [b-600, b+600]
    max_block_gap_s=10,  # 25 x the 0.4 s target interval
    min_rate_bps=1.5,  # 60 % of the 2.5 blocks/s target (observed 2.3-2.46)
    live_lag_s=30,  # a block counts as live-observed if collected <= 30 s after gen_utime
    min_live_fraction=0.99,  # per counted source, over the window
    max_head_record_gap_s=30,  # head observations from a counted source
    max_head_staleness_s=15,  # head record utc - gen_utime(head) at every observation
    min_sources_cert=2,
    all_sources=3,
    min_handovers=3,
)


BLK_KEEP = (
    "t",
    "src",
    "seq",
    "ok",
    "reason",
    "unsupported",
    "rid",
    "cid",
    "parent",
    "parent_seq",
    "gu",
    "key",
    "prevkey",
    "set",
    "utc",
    "supplement_utc",
    "path",
)


def load_results(evidence):
    """Compact in-memory form: unused block fields dropped, repeated strings interned."""
    res, intern = [], sys.intern
    for p in sorted((evidence / "verified").glob("results-*.jsonl")):
        for line in open(p):
            r = json.loads(line)
            if r["t"] == "blk":
                r = {k: r[k] for k in BLK_KEEP if k in r}
                for k in ("rid", "cid", "parent"):
                    if k in r:
                        r[k] = tuple(r[k])
                if "set" in r:
                    r["set"] = intern(r["set"])
            elif r["t"] == "head":
                r = dict(t="head", src=r["src"], utc=r["utc"], head=r["head"])
            r["t"] = intern(r["t"])
            r["src"] = intern(r["src"])
            res.append(r)
    return res


def judge(results, cfg, bounds=BOUNDS, sources=None):
    sources = sources or sorted(cfg["sources"])
    blk = collections.defaultdict(
        list
    )  # (src, seq) -> every result, in order (nothing is overwritten)
    gaps, heads, keys, shp, shards, events, chain = (
        [],
        collections.defaultdict(list),
        {},
        collections.defaultdict(list),
        {},
        [],
        [],
    )
    for r in results:
        t = r["t"]
        if t == "blk":
            blk[(r["src"], r["seq"])].append(r)
        elif t == "gap":
            gaps.append(r)
        elif t == "head":
            heads[r["src"]].append(r)
        elif t == "key":
            if r.get("trusted") or (r["seq"] not in keys):
                keys[r["seq"]] = r
        elif t == "shp":
            shp[r["seq"]].append(r)
        elif t == "shards":
            shards[(r["src"], r["seq"])] = r["tops"]
        elif t in ("chain", "torn"):
            chain.append(r)
        elif t in ("start", "stop", "heartbeat", "refuse"):
            events.append(r)
    out = dict(bounds=bounds, sources=sources, fail=[], inconclusive=[], notes=[])
    accepted = collections.defaultdict(dict)  # seq -> src -> result
    rejected = []
    unsupported = []
    self_conflicts = []
    for (src, seq), rs in blk.items():
        oks = [r for r in rs if r["ok"]]
        # every rejection is permanent; identical re-processing duplicates count once
        for reason in sorted(
            {r.get("reason") for r in rs if not r["ok"] and not r.get("unsupported")}
        ):
            rejected.append(dict(src=src, seq=seq, reason=reason))
        cids = {tuple(r["cid"]) for r in oks}
        if len(cids) > 1:
            self_conflicts.append(dict(src=src, seq=seq, ids=sorted(cids)))
        if oks:
            # an unsupported-shape hole may be filled only by a later accepted result for the same block
            for r in oks:
                r["rcpt"] = r.get("supplement_utc") or r["utc"]
                r["lag"] = round(r["rcpt"] - r["gu"], 3)
            accepted[seq][src] = min(oks, key=lambda r: r["rcpt"])
        elif any(r.get("unsupported") for r in rs):
            unsupported.append(dict(src=src, seq=seq))
    if self_conflicts:
        out["fail"].append(
            f"{len(self_conflicts)} (source, seqno) pairs with two different certified ids"
        )
    out["self_conflicts"] = self_conflicts[:20]
    out["unsupported_shape"] = unsupported[:50]
    out["unsupported_count"] = len(unsupported)
    # integrity
    breaks = [c for c in chain if c["t"] == "chain" and not c["ok"]]
    if breaks:
        out["inconclusive"].append(f"{len(breaks)} evidence-stream integrity breaks")
    out["integrity"] = dict(
        breaks=breaks[:20], torn=[c for c in chain if c["t"] == "torn"]
    )
    # rejections never overridden: unresolved -> INCONCLUSIVE pending defect analysis
    out["rejected"] = rejected[:50]
    out["rejected_count"] = len(rejected)
    if rejected:
        out["inconclusive"].append(
            f"{len(rejected)} rejected certificates: unresolved (FAIL unless a collector defect is demonstrated and fixed)"
        )
    # conflicts and parent continuity
    seqs = sorted(accepted)
    canon = {}
    conflicts = []
    for s in seqs:
        cids = {tuple(r["cid"]) for r in accepted[s].values()}
        if len(cids) > 1:
            conflicts.append(dict(seq=s, ids=sorted(cids)))
        canon[s] = next(iter(cids))
    parent_breaks, runs, run = [], [], None
    for s in seqs:
        r = next(iter(accepted[s].values()))
        if s - 1 in canon:
            if tuple(r["parent"]) != tuple(canon[s - 1]) or r["parent_seq"] != s - 1:
                parent_breaks.append(s)
            else:
                run[1] = s
                continue
        run = [s, s]
        runs.append(run)
    if conflicts:
        out["fail"].append(
            f"{len(conflicts)} seqnos with conflicting certified full ids"
        )
    if parent_breaks:
        out["fail"].append(
            f"{len(parent_breaks)} parent-link breaks between certified blocks"
        )
    out["conflicts"], out["parent_breaks"] = conflicts[:20], parent_breaks[:20]
    out["continuously_verified_runs"] = [
        dict(lo=a, hi=b, blocks=b - a + 1) for a, b in runs
    ]
    # coverage and gaps
    hdr = collections.defaultdict(
        lambda: collections.defaultdict(set)
    )  # seq -> src -> every claimed id
    for (src, seq), rs in blk.items():
        for r in rs:
            if "rid" in r:
                hdr[seq][src].add(tuple(r["rid"]))
    all_seqs = sorted(set(hdr) | set(accepted))
    lo_seq = min(all_seqs) if all_seqs else None
    hi_seq = max(all_seqs) if all_seqs else None
    uncovered = (
        [s for s in range(lo_seq, hi_seq + 1) if s not in accepted] if all_seqs else []
    )
    explained = set()
    for g in gaps:
        explained.update(range(g["lo"], g["hi"] + 1))
    for (src, seq), rs in blk.items():
        if any(not r["ok"] for r in rs):
            explained.add(seq)
    unexplained = [s for s in uncovered if s not in explained]
    out["coverage"] = dict(
        lo=lo_seq,
        hi=hi_seq,
        certified=len(accepted),
        uncovered=len(uncovered),
        uncovered_sample=uncovered[:50],
        unexplained=unexplained[:50],
        unexplained_count=len(unexplained),
        gaps=[
            dict(
                src=g["src"], lo=g["lo"], hi=g["hi"], stage=g["stage"], err=g.get("err")
            )
            for g in gaps
        ][:50],
    )
    if unexplained:
        out["inconclusive"].append(
            f"{len(unexplained)} uncovered seqnos with no recorded reason"
        )
    out["outages"] = [
        dict(
            src=e["src"],
            utc=e["utc"],
            outage_s=e.get("outage_s"),
            resume_after=e.get("resume_after"),
            torn=e.get("torn"),
        )
        for e in events
        if e["t"] == "start"
    ]
    # key-block trust chain
    key_seqs = sorted(
        {s for s in accepted if any(r.get("key") for r in accepted[s].values())}
    )
    chain_issues = []
    for s in seqs:
        pk = next(iter(accepted[s].values()))["prevkey"]
        if pk != 0 and not (pk in accepted and keys.get(pk, {}).get("trusted")):
            chain_issues.append(dict(seq=s, prevkey=pk))
    for k in key_seqs:
        if not keys.get(k, {}).get("trusted"):
            chain_issues.append(dict(key=k, reason="key-block config not trusted"))
    first = cfg.get("start_seqno", 1)
    out["trust_chain"] = dict(
        key_blocks=key_seqs,
        issues=chain_issues[:20],
        issue_count=len(chain_issues),
        from_genesis=(first <= 1),
        note=None
        if first <= 1
        else f"collection armed at seqno {first}; blocks before it are not covered",
    )
    if chain_issues:
        out["inconclusive"].append(
            f"key-block trust chain incomplete ({len(chain_issues)} issues)"
        )
    # handovers
    gu = {s: next(iter(accepted[s].values()))["gu"] for s in seqs}
    genesis_set = cfg.get("_genesis_set") or next(
        (
            r.get("genesis_set")
            for s in seqs
            for r in accepted[s].values()
            if r.get("genesis_set")
        ),
        None,
    )
    windows = []
    for b in key_seqs:
        k = keys.get(b)
        if not (k and k.get("trusted") and k.get("cp34")):
            continue
        if k["cp34"]["since"] != gu[b]:
            continue  # key block that is not a set change
        windows.append(
            handover(
                b,
                k,
                keys,
                accepted,
                hdr,
                gu,
                heads,
                shp,
                shards,
                genesis_set,
                sources,
                bounds,
                cfg,
            )
        )
    out["handovers"] = windows
    good = [w for w in windows if w["status"] == "PASS"]
    for w in windows:
        if w["status"] == "FAIL":
            out["fail"].append(f"handover {w['boundary']}: " + "; ".join(w["fail"]))
    if out["fail"]:
        out["verdict"] = "FAIL"
    elif len(good) >= bounds["min_handovers"] and not out["inconclusive"]:
        out["verdict"] = "PASS"
    else:
        if len(good) < bounds["min_handovers"]:
            out["inconclusive"].append(
                f"{len(good)} of {bounds['min_handovers']} required handover windows qualify"
            )
        out["verdict"] = "INCONCLUSIVE"
    out["claim_limit"] = (
        "PASS covers the qualifying handover windows and the key-block trust chain; history outside "
        "continuously_verified_runs is not claimed as continuously verified."
    )
    return out


def handover(
    b, k, keys, accepted, hdr, gu, heads, shp, shards, genesis_set, sources, bounds, cfg
):
    w = dict(boundary=b, utime=gu[b], fail=[], short=[], status=None)
    acc_b = accepted[b]
    rb = next(iter(acc_b.values()))
    pk = rb["prevkey"]
    outgoing = genesis_set if pk == 0 else (keys.get(pk) or {}).get("cp34")
    announced = None if pk == 0 else (keys.get(pk) or {}).get("cp36")
    inc, prev = k["cp34"], k["cp32"]
    # configuration checks (section 1.4)
    if not outgoing:
        w["short"].append("outgoing set unavailable")
    else:
        if inc["since"] != gu[b] or outgoing["until"] != gu[b]:
            w["fail"].append("term boundary times inconsistent")
        if prev is None or prev["hash"] != outgoing["hash"]:
            w["fail"].append("CP32(b) != outgoing CP34")
        if rb["set"] != outgoing["hash"]:
            w["fail"].append("boundary not certified by the outgoing set")
    if announced is not None and announced["hash"] != inc["hash"]:
        w["fail"].append("CP36(prev key) != CP34(b)")
    if inc["until"] - inc["since"] not in cfg.get("term_lengths", [7200]):
        w["fail"].append(f"incoming term length {inc['until'] - inc['since']}")
    nxt = accepted.get(b + 1, {})
    if nxt and any(r["set"] != inc["hash"] or r["prevkey"] != b for r in nxt.values()):
        w["fail"].append("b+1 not certified by the incoming set")
    # window
    lo_t, hi_t = gu[b] - bounds["window_s"], gu[b] + bounds["window_s"]
    last_t = max(gu.values())
    if last_t <= hi_t:
        w["status"] = "OPEN"
        w["short"].append("window not yet complete")
    # Strict outer brackets: a proved block with gen_utime < start and one with gen_utime > end;
    # then every seqno between the two brackets is required (so blocks sharing the endpoint
    # timestamps are inside the required range).
    proved = sorted(gu)
    before = [s for s in proved if gu[s] < lo_t]
    after = [s for s in proved if gu[s] > hi_t]
    start_seq = before[-1] if before else None
    end_seq = after[0] if after else None
    if start_seq is None:
        w["short"].append("window start not bracketed by a proved block")
        start_seq = min((s for s in proved if gu[s] >= lo_t), default=b)
    if end_seq is None:
        if w["status"] != "OPEN":
            w["short"].append("window end not bracketed by a proved block")
        end_seq = max((s for s in proved if gu[s] <= hi_t), default=b)
    w["brackets"] = [before[-1] if before else None, after[0] if after else None]
    full = list(range(start_seq, end_seq + 1))
    missing = [s for s in full if s not in accepted]
    if missing:
        w["short"].append(
            f"{len(missing)} window seqnos without any accepted certificate"
        )
    weak = [s for s in full if len(accepted.get(s, {})) < bounds["min_sources_cert"]]
    if weak:
        w["short"].append(
            f"{len(weak)} window seqnos certified by < {bounds['min_sources_cert']} sources"
        )
    edge = [
        s for s in (b - 1, b, b + 1) if len(accepted.get(s, {})) < bounds["all_sources"]
    ]
    if edge:
        w["short"].append(
            f"boundary blocks {edge} not certified by all {bounds['all_sources']} sources"
        )
    noid = [s for s in full if len(hdr.get(s, {})) < bounds["all_sources"]]
    if noid:
        w["short"].append(
            f"{len(noid)} window seqnos lack a full id from all {bounds['all_sources']} sources"
        )
    iddis = [s for s in full if len(set().union(*hdr[s].values())) > 1] if full else []
    if iddis:
        w["fail"].append(
            f"{len(iddis)} window seqnos with differing full ids across sources"
        )
    # shards
    okp = {r["src"] for r in shp.get(b, []) if r["ok"]}
    if len(okp) < bounds["min_sources_cert"]:
        w["short"].append(f"shard inclusion verified from {len(okp)} sources")
    badp = [r for r in shp.get(b, []) if not r["ok"]]
    if badp:
        w["short"].append(f"{len(badp)} shard proofs rejected (unresolved)")
    for s in (b - 1, b):
        tops = {
            json.dumps(shards.get((src, s))) for src in sources if (src, s) in shards
        }
        if len(tops) > 1:
            w["fail"].append(f"shard anchors disagree at {s}")
        if len([src for src in sources if (src, s) in shards]) < bounds["all_sources"]:
            w["short"].append(f"shard anchors at {s} not from all sources")
    # liveness (chain side)
    times = [gu[s] for s in full if s in gu]
    gaps_t = [b2 - a for a, b2 in zip(times, times[1:])]
    w["max_block_gap_s"] = max(gaps_t) if gaps_t else None
    span = (times[-1] - times[0]) if len(times) > 1 else 0
    w["rate_bps"] = round(len(full) / span, 3) if span else None
    live_ok_sources = []
    w["live"] = {}
    for src in sources:
        rs = [accepted.get(s, {}).get(src) for s in full]
        live = sum(
            1
            for r in rs
            if r and r.get("lag") is not None and r["lag"] <= bounds["live_lag_s"]
        )
        # only head observations whose reported head is a proved block count (unknown time never satisfies freshness)
        hs = sorted(
            h["utc"]
            for h in heads.get(src, [])
            if lo_t <= h["utc"] <= hi_t + 60 and h.get("head") in gu
        )
        hgap = (
            max([b2 - a for a, b2 in zip([lo_t] + hs, hs + [min(hi_t, last_t)])])
            if hs
            else None
        )
        stale = [
            round(h["utc"] - gu[h["head"]], 1)
            for h in heads.get(src, [])
            if lo_t <= h["utc"] <= hi_t and h.get("head") in gu
        ]
        frac = live / len(full) if full else 0
        w["live"][src] = dict(
            live_fraction=round(frac, 4),
            head_records=len(hs),
            max_head_record_gap_s=round(hgap, 1) if hgap is not None else None,
            max_staleness_s=max(stale) if stale else None,
        )
        observed = (
            frac >= bounds["min_live_fraction"]
            and hgap is not None
            and hgap <= bounds["max_head_record_gap_s"]
        )
        if observed:
            live_ok_sources.append(src)
            if stale and max(stale) > bounds["max_head_staleness_s"]:
                w["fail"].append(
                    f"{src}: head stale {max(stale)} s while observed live (stall)"
                )
    if len(live_ok_sources) < bounds["min_sources_cert"]:
        w["short"].append(
            f"live observation through the window from {len(live_ok_sources)} sources"
        )
    elif w["status"] != "OPEN":
        if (
            w["max_block_gap_s"] is not None
            and w["max_block_gap_s"] > bounds["max_block_gap_s"]
        ):
            w["fail"].append(
                f"block gap {w['max_block_gap_s']} s > {bounds['max_block_gap_s']} s (stall)"
            )
        if w["rate_bps"] is not None and w["rate_bps"] < bounds["min_rate_bps"]:
            w["fail"].append(
                f"rate {w['rate_bps']} blocks/s < {bounds['min_rate_bps']}"
            )
    w["blocks"] = len(full)
    w["window_seqnos"] = [full[0], full[-1]] if full else None
    if w["fail"]:
        w["status"] = "FAIL"
    elif w["status"] != "OPEN":
        w["status"] = "PASS" if not w["short"] else "INCONCLUSIVE"
    return w


def seals_check(evidence):
    """Hash each sealed segment once (chunked); later runs re-hash only if size or mtime changed."""
    bad, n = [], 0
    p = evidence / "SEALS.jsonl"
    if not p.exists():
        return dict(sealed=0, mismatches=[])
    cache_p = evidence / "verified" / "seals-checked.json"
    cache = json.loads(cache_p.read_text()) if cache_p.exists() else {}
    for line in open(p):
        e = json.loads(line)
        n += 1
        f = evidence / e["segment"]
        if not f.exists():
            bad.append(dict(segment=e["segment"], sealed=e["sha256"], now=None))
            continue
        st = f.stat()
        sig = [st.st_size, st.st_mtime_ns, e["sha256"]]
        c = cache.get(e["segment"])
        if c and c[:3] == sig:
            h = c[3]
        else:
            hh = hashlib.sha256()
            with open(f, "rb") as fh:
                for block in iter(lambda: fh.read(1 << 20), b""):
                    hh.update(block)
            h = hh.hexdigest()
            cache[e["segment"]] = sig + [h]
        if h != e["sha256"]:
            bad.append(dict(segment=e["segment"], sealed=e["sha256"], now=h))
    if cache_p.parent.exists():
        cache_p.write_text(json.dumps(cache))
    return dict(sealed=n, mismatches=bad)
