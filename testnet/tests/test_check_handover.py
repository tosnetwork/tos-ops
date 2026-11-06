"""check-handover.py against a recorded public-testnet fixture.

The fixture (data/handover/epoch5-handovers.json) holds two epoch-5 handovers cut
to three blocks each side of the boundary block: a normal one (`normal`) and one
after a postponed election, where the outgoing set kept signing past its
utime_until (`extended_term`). Each distinct answer is stored once by the sha256
of its canonical JSON. `verdicts` lists sha256(pk || msg || sig) of every
signature in it that ML-DSA-44 accepted; the recorded verifier accepts exactly
those, so a tampered signature is refused without the crypto package. The tests
marked `mldsa` run the real verifier and are skipped when dilithium-py is not
installed.
"""

import argparse
import copy
import hashlib
import importlib.util
import json

import pytest
from conftest import DATA, SCRIPTS

spec = importlib.util.spec_from_file_location("check_handover", SCRIPTS / "check-handover.py")
ch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ch)

FIXTURE = json.loads((DATA / "handover" / "epoch5-handovers.json").read_text())
GLOBAL_ID = 2
HAS_MLDSA = importlib.util.find_spec("dilithium_py") is not None
mldsa = pytest.mark.skipif(not HAS_MLDSA, reason="dilithium-py (ML-DSA-44) is not installed")


def expand(value):
    if isinstance(value, dict) and "answer_sha256" in value and "method" in value:
        out = {k: v for k, v in value.items() if k != "answer_sha256"}
        out["answer"] = copy.deepcopy(FIXTURE["answers"][value["answer_sha256"]])
        return out
    if isinstance(value, dict):
        return {k: expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand(v) for v in value]
    return value


def collection(name):
    return expand(FIXTURE["collections"][name])


VERDICTS = frozenset(FIXTURE["verdicts"])


def recorded(pk, msg, sig):
    return hashlib.sha256(pk + msg + sig).hexdigest() in VERDICTS


def run(c, verify_fn=recorded):
    return ch.verify(c, FIXTURE["global_config"], verify_fn, GLOBAL_ID)


def result(entry):
    return entry["answer"]["result"]


def block(c, node, seqno, kind):
    return result(c["blocks"][node][str(seqno)][kind])


def has(report, text):
    return any(text in f for f in report["failures"])


NODES = ["node-1", "node-2", "node-3", "node-4"]


# ---------------------------------------------------------------- passing handovers


def test_normal_handover_passes():
    report = run(collection("normal"))
    assert report["result"] == "PASS", report["failures"]
    assert report["boundary"]["last_outgoing"] == 230378
    assert report["boundary"]["first_incoming"] == 230379
    assert report["extended_term"] == []
    assert {b["term"] for b in report["blocks"]} == {"in_term"}
    assert report["counts"] == {
        "outgoing_blocks": 4,
        "incoming_blocks": 3,
        "certificates_expected": 28,
        "certificates_verified": 28,
    }
    assert all(x["rejected"] for x in report["controls"]) and len(report["controls"]) == 3
    assert report["wrong_term_coverage"] == {
        "outgoing_rejected": 16,
        "incoming_rejected": 12,
        "accepted": [],
    }
    # Identical keys in both terms: only the header binding tells them apart.
    assert [
        x["membership_and_signature_only"] for x in report["bare_verifier_wrong_set_probe"]
    ] == [
        "accept",
        "accept",
    ]
    assert len(report["certificate_controls"]["results"]) == 12


def test_extended_term_passes_and_is_reported():
    report = run(collection("extended_term"))
    assert report["result"] == "PASS", report["failures"]
    assert report["extended_term"] == [
        {
            "set_source": 248300,
            "role": "outgoing",
            "utime_until": 1792940400,
            "first": 250343,
            "last": 250344,
            "blocks": 2,
            "first_gen_utime": 1792941316,
            "last_gen_utime": 1792941317,
            "seconds_past_until": 917,
        }
    ]
    terms = {b["seqno"]: b["term"] for b in report["blocks"]}
    assert terms[250344] == "extended_term" and terms[250345] == "in_term"


@mldsa
def test_real_mldsa_verifier_passes_both_and_agrees_with_the_verdicts():
    real = ch.mldsa44_verifier()
    seen = []

    def checked(pk, msg, sig):
        ok = real(pk, msg, sig)
        assert ok == recorded(pk, msg, sig)
        seen.append(ok)
        return ok

    for name in ("normal", "extended_term"):
        assert run(collection(name), checked)["result"] == "PASS"
    assert True in seen and False in seen


# ---------------------------------------------------------------- the term rule


def test_extended_term_block_with_another_set_source_fails():
    c = collection("extended_term")
    cert = block(c, "node-2", 250343, "signatures")
    cert["verification"]["validator_set_source"]["seqno"] = 250344
    report = run(c)
    assert report["result"] == "FAIL"
    assert has(report, "block 250343: extended-term block is not signed by the chain-selected set")
    assert has(report, "node-2/250343: certificate set source 250344 differs")


def test_extended_term_block_with_the_incoming_session_commitment_fails():
    c = collection("extended_term")
    incoming = block(c, "node-1", 250345, "signatures")
    cert = block(c, "node-3", 250344, "signatures")
    cert["cc_seqno"], cert["validator_set_hash"] = (
        incoming["cc_seqno"],
        incoming["validator_set_hash"],
    )
    report = run(c)
    assert has(report, "block 250344: extended-term block is not signed by the chain-selected set")
    assert has(report, "node-3/250344: certificate session commitment differs from the header")


def test_block_before_its_term_fails():
    c = collection("normal")
    for n in NODES:
        block(c, n, 230380, "header")["gen_utime"] = 1792933199
    report = run(c)
    assert has(report, "block 230380: generated at 1792933199, before its set's term begins")


# ---------------------------------------------------------------- tampering and wrong sets


def flip(cert, index=0):
    raw = bytearray(ch.b64(cert["signatures"][index]["signature"]))
    raw[100] ^= 0x01
    cert["signatures"][index]["signature"] = ch.lib.b64(bytes(raw))


def test_tampered_signature_fails():
    c = collection("normal")
    flip(block(c, "node-3", 230380, "signatures"))
    report = run(c)
    assert report["result"] == "FAIL"
    assert has(report, "node-3/230380: certificate rejected: ML-DSA-44 signature")


@mldsa
def test_tampered_signature_fails_with_real_mldsa():
    c = collection("extended_term")
    flip(block(c, "node-1", 250344, "signatures"), 1)
    report = run(c, ch.mldsa44_verifier())
    assert has(report, "node-1/250344: certificate rejected: ML-DSA-44 signature")
    assert has(report, "block 250344: extended-term block is not signed by the chain-selected set")


def test_header_selecting_the_other_set_fails():
    c = collection("normal")
    for n in NODES:
        block(c, n, 230380, "header")["prev_key_block_seqno"] = 228172
    report = run(c)
    assert has(
        report,
        "node-1/230380: certificate set source 230378 differs from the header-selected set 228172",
    )
    assert has(report, "handover roles are not contiguous")


def test_set_that_is_neither_post_handover_set_fails():
    c = collection("normal")
    for n in NODES:
        c["post_handover"][n]["34"] = copy.deepcopy(c["post_handover"][n]["32"])
    report = run(c)
    assert has(report, "block 230379: its set is neither post-handover ConfigParam 32 nor 34")
    assert has(report, "the range does not cross a handover")


def test_last_outgoing_block_must_install_the_incoming_set():
    c = collection("normal")
    for n in NODES:
        block(c, n, 230378, "header")["is_key_block"] = False
    report = run(c)
    assert has(
        report, "the last outgoing block is not the key block that installs the incoming set"
    )


def test_a_verifier_that_accepts_everything_is_caught_by_the_controls():
    report = run(collection("normal"), lambda pk, msg, sig: True)
    assert report["result"] == "FAIL"
    assert has(report, "certificate control failed: flip one byte of a signature")
    assert has(report, "control accepted: pre-boundary signature spliced")


def test_two_session_ids_for_one_catchain_seqno_fail():
    c = collection("normal")
    cert = block(c, "node-2", 230376, "signatures")
    raw = bytearray(ch.b64(cert["session_id"]))
    raw[0] ^= 1
    cert["session_id"] = ch.lib.b64(bytes(raw))
    report = run(c)
    assert has(report, "catchain seqno 384 has more than one session id")


def test_wrong_term_binding_control_is_effective():
    report = run(collection("extended_term"))
    assert report["wrong_term_coverage"]["accepted"] == []
    assert report["wrong_term_coverage"]["outgoing_rejected"] == 8
    assert {x["reason"] for x in report["controls"][:2]} == {
        "supplied validator set differs from the chain-selected ConfigParam 34"
    }
    assert report["controls"][2]["reason"].startswith("ML-DSA-44 signature")


# ---------------------------------------------------------------- disagreement and identity


def test_node_serving_another_block_id_fails():
    c = collection("normal")
    look = block(c, "node-4", 230377, "lookup")
    look["root_hash"] = ch.lib.b64(b"\x01" * 32)
    report = run(c)
    assert has(report, "block 230377: full ids differ across nodes")


def test_node_serving_other_header_fields_fails():
    c = collection("normal")
    block(c, "node-2", 230376, "header")["catchain_seqno"] = 999
    report = run(c)
    assert has(report, "block 230376: header fields differ across nodes")


def test_node_serving_other_set_bytes_fails():
    c = collection("normal")
    other = result(c["post_handover"]["node-1"]["34"])["config"]["bytes"]
    result(c["config34"]["node-3"]["228172"])["config"]["bytes"] = other
    report = run(c)
    assert has(report, "ConfigParam 34 at source 228172 differs or is missing across nodes")


def test_node_serving_other_shard_tops_fails():
    c = collection("normal")
    block(c, "node-1", 230379, "shards")["shards"][0]["seqno"] += 1
    report = run(c)
    assert has(report, "block 230379: shard tops differ across nodes")


def test_nodes_disagreeing_on_the_boundary_block_fail():
    c = collection("normal")
    result(c["boundary_lookups"]["node-3"])["seqno"] += 1
    report = run(c)
    assert has(report, "nodes disagree on the block at the boundary time")


def test_other_zero_state_fails():
    c = collection("normal")
    result(c["heads"]["node-2"])["init"]["root_hash"] = ch.lib.b64(b"\x02" * 32)
    report = run(c)
    assert has(report, "node-2: zero state differs from the global config")


def test_other_global_id_fails():
    report = ch.verify(collection("normal"), FIXTURE["global_config"], recorded, 7)
    assert has(report, "header global id 2, expected 7")


def test_missing_answer_fails():
    c = collection("normal")
    c["blocks"]["node-1"]["230381"]["signatures"]["answer"] = {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32004, "message": "not found"},
    }
    report = run(c)
    assert report["result"] == "FAIL"
    assert has(report, "node-1/230381 getMasterchainBlockSignatures")


def test_verify_refuses_without_the_mldsa_package(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "dilithium_py", None)
    monkeypatch.setitem(sys.modules, "dilithium_py.ml_dsa", None)
    with pytest.raises(ch.HandoverError, match="dilithium-py"):
        ch.mldsa44_verifier()


def test_verify_cli_writes_report(tmp_path, monkeypatch):
    (tmp_path / "collection.json").write_text(json.dumps(collection("extended_term")))
    config = tmp_path / "global.config.json"
    config.write_text(json.dumps(FIXTURE["global_config"]))
    monkeypatch.setattr(ch, "mldsa44_verifier", lambda: recorded)
    code = ch.main(["verify", "--genesis-config", str(config), "--out", str(tmp_path)])
    assert code == 0
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["result"] == "PASS" and report["extended_term"][0]["first"] == 250343


# ---------------------------------------------------------------- collection, with fakes


class Clock:
    def __init__(self, t=0.0):
        self.t = t

    def __call__(self):
        return self.t

    def sleep(self, seconds):
        assert seconds >= 0
        self.t += seconds


def canon(params):
    return json.dumps(params, sort_keys=True)


class FakeNodes:
    """Answers recorded requests from the fixture, per node URL, and records the
    per-node clock at every request start."""

    def __init__(self, name="normal", gc=()):
        self.c = collection(name)
        self.urls = {f"http://{n}.invalid/jsonRPC": n for n in self.c["nodes"]}
        self.clocks = {n: Clock(1000.0) for n in self.c["nodes"]}
        self.starts = {n: [] for n in self.c["nodes"]}
        self.calls = []
        self.gc = set(gc)
        self.index = {}
        for n in self.c["nodes"]:
            entries = [self.c["heads"][n], self.c["boundary_lookups"][n]]
            for b in self.c["blocks"][n].values():
                entries += list(b.values())
            entries += list(self.c["config34"][n].values())
            for e in entries:
                self.index[(n, e["method"], canon(e["params"]))] = e["answer"]

    def __call__(self, url, method, params):
        n = self.urls[url]
        self.starts[n].append(self.clocks[n]())
        self.calls.append((n, method, params))
        self.clocks[n].t += 0.25  # time spent answering
        if method == "getConfigParam" and params["param"] in (32, 34):
            if params["param"] == 34 and params["seqno"] in self.gc:
                return {
                    "http": 200,
                    "answer": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "error": {
                            "code": -32004,
                            "message": "cannot load state: state already gc'd",
                        },
                    },
                }
            key = (n, method, canon(params))
            if key in self.index:
                return {"http": 200, "answer": self.index[key]}
            if params["param"] == 34 and params["seqno"] > self.c["range"][1]:
                return {"http": 200, "answer": self.c["post_handover"][n]["34"]["answer"]}
            if params["param"] == 34:
                # Inside the range ConfigParam 34 is the set its header's source selected.
                header = block(self.c, n, params["seqno"], "header")
                source = str(header["prev_key_block_seqno"])
                return {"http": 200, "answer": self.c["config34"][n][source]["answer"]}
            return {"http": 200, "answer": self.c["post_handover"][n]["32"]["answer"]}
        return {"http": 200, "answer": self.index[(n, method, canon(params))]}

    def pacer(self, index):
        n = self.c["nodes"][index]
        return ch.Pacer(0.6, clock=self.clocks[n], sleep=self.clocks[n].sleep)


def collect_args(tmp_path, fake, **extra):
    config = tmp_path / "global.config.json"
    config.write_text(json.dumps(FIXTURE["global_config"]))
    values = {
        "boundary": fake.c["boundary"],
        "rpc": list(fake.urls),
        "genesis_config": config,
        "span": 3,
        "out": tmp_path / "run",
        "interval": 0.6,
        "max_wait": 900,
        "lock_dir": None,
    }
    values.update(extra)
    return argparse.Namespace(**values)


def run_collect(tmp_path, fake, wall=None, transport=None, **extra):
    wall = wall or Clock(fake.c["boundary"] + 60.0)
    args = collect_args(tmp_path, fake, **extra)
    summary = ch.collect(
        args,
        transport=transport or fake,
        clock=wall,
        sleep=wall.sleep,
        now=wall,
        pacer_factory=fake.pacer,
    )
    return args, summary


def test_collect_is_paced_journaled_and_verifies(tmp_path):
    fake = FakeNodes()
    args, summary = run_collect(tmp_path, fake)
    assert summary["range"] == [230375, 230381] and summary["center"] == 230378
    for n, starts in fake.starts.items():
        assert len(starts) == summary["requests"][n] > 30
        assert all(b - a >= 0.6 - 1e-9 for a, b in zip(starts, starts[1:])), n
    lines = [json.loads(x) for x in (args.out / "journal.jsonl").read_text().splitlines()]
    assert len(lines) == len(fake.calls)
    assert sorted((x["node"], x["method"], canon(x["params"])) for x in lines) == sorted(
        (n, m, canon(p)) for n, m, p in fake.calls
    )
    assert {x["outcome"] for x in lines} == {"result"}
    assert {x["method"] for x in lines} <= ch.READ_ONLY_METHODS
    collected = json.loads((args.out / "collection.json").read_text())
    sample = collected["blocks"]["node-2"]["230379"]["signatures"]["answer"]
    digest = hashlib.sha256(json.dumps(sample, sort_keys=True).encode()).hexdigest()
    assert digest in {x["answer_sha256"] for x in lines}
    report = run(collected)
    assert report["result"] == "PASS", report["failures"]


def test_collect_waits_for_the_boundary(tmp_path):
    fake = FakeNodes()
    wall = Clock(fake.c["boundary"] - 100.0)
    run_collect(tmp_path, fake, wall=wall)
    assert wall.t >= fake.c["boundary"] + 1


def test_collect_gives_up_after_max_wait(tmp_path):
    fake = FakeNodes()
    wall = Clock(fake.c["boundary"] - 5000.0)
    with pytest.raises(ch.HandoverError, match="boundary time was not reached"):
        run_collect(tmp_path, fake, wall=wall, max_wait=60)
    assert fake.calls == []


def test_collect_supplements_a_garbage_collected_source(tmp_path):
    fake = FakeNodes(gc={228172})
    args, summary = run_collect(tmp_path, fake)
    assert summary["substitutions"] == [{"source": 228172, "read_at": 230375}]
    collected = json.loads((args.out / "collection.json").read_text())
    entry = collected["config34"]["node-4"]["228172"]
    assert entry["params"] == {"param": 34, "seqno": 230375} and entry["substituted_for"] == 228172
    original = collected["substitutions"][0]["original"]["node-4"]
    assert "gc'd" in original["answer"]["error"]["message"]
    report = run(collected)
    assert report["result"] == "PASS", report["failures"]
    assert report["sets"]["228172"]["read_at"] == 230375

    # A substitution read at a block that does not name the source is refused.
    moved = copy.deepcopy(collected)
    for n in NODES:
        moved["config34"][n]["228172"]["params"]["seqno"] = 230376
    moved["substitutions"][0]["read_at"] = 230376
    assert has(run(moved), "substitute block 230376 is not the first agreed non-key block")

    # Without the substitution the garbage-collected source is unavailable.
    bare = copy.deepcopy(collected)
    for n in NODES:
        bare["config34"][n]["228172"] = bare["substitutions"][0]["original"][n]
    bare["substitutions"] = []
    assert has(run(bare), "ConfigParam 34 at 228172")


def test_collect_refuses_disagreeing_boundary_blocks(tmp_path):
    fake = FakeNodes()
    key = ("node-3", "lookupBlock", canon(fake.c["boundary_lookups"]["node-3"]["params"]))
    fake.index[key] = copy.deepcopy(fake.index[key])
    fake.index[key]["result"]["seqno"] += 1
    with pytest.raises(ch.HandoverError, match="disagree on the block at the boundary"):
        run_collect(tmp_path, fake)


def lagging_transport(fake, wall, node, until, behind=1, error=False):
    """While wall() < until, `node` has not received the blocks after the boundary:
    its head and its time lookup name a block `behind` seqnos before the others'
    (or, with error=True, the time lookup fails outright)."""
    boundary = fake.c["boundary_lookups"][node]["answer"]["result"]["seqno"]

    def transport(url, method, params):
        out = fake(url, method, params)
        if fake.urls[url] != node or wall() >= until:
            return out
        out = copy.deepcopy(out)
        if method == "lookupBlock" and "unixtime" in params:
            if error:
                out["answer"] = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": {"code": -32004, "message": "block not found"},
                }
            else:
                out["answer"]["result"]["seqno"] = boundary - behind
        elif method == "getMasterchainInfo":
            out["answer"]["result"]["last"]["seqno"] = boundary - behind
        return out

    return transport


def time_lookups(fake, node):
    return [c for c in fake.calls if c[0] == node and c[1] == "lookupBlock" and "unixtime" in c[2]]


def test_collect_waits_for_a_head_that_lags_at_the_boundary(tmp_path):
    fake = FakeNodes()
    wall = Clock(fake.c["boundary"] + 1.0)
    until = fake.c["boundary"] + 40.0
    lagging = lagging_transport(fake, wall, "node-3", until)
    args, summary = run_collect(tmp_path, fake, wall=wall, transport=lagging)
    assert summary["center"] == 230378 and wall.t >= until
    assert len(time_lookups(fake, "node-3")) > 1
    collected = json.loads((args.out / "collection.json").read_text())
    assert collected["boundary_lookups"]["node-3"]["answer"]["result"]["seqno"] == 230378
    assert collected["heads"]["node-3"]["answer"]["result"]["last"]["seqno"] == 230598
    report = run(collected)
    assert report["result"] == "PASS", report["failures"]


def test_collect_gives_up_on_a_head_that_never_passes_the_boundary(tmp_path):
    fake = FakeNodes()
    wall = Clock(fake.c["boundary"] + 1.0)
    lagging = lagging_transport(fake, wall, "node-3", float("inf"))
    with pytest.raises(ch.HandoverError, match="did not pass the block at the boundary"):
        run_collect(tmp_path, fake, wall=wall, max_wait=60, transport=lagging)
    assert not (tmp_path / "run" / "collection.json").exists()
    assert wall.t > fake.c["boundary"] + 61


def test_collect_gives_up_on_a_boundary_lookup_that_keeps_failing(tmp_path):
    fake = FakeNodes()
    wall = Clock(fake.c["boundary"] + 1.0)
    failing = lagging_transport(fake, wall, "node-3", float("inf"), error=True)
    with pytest.raises(ch.HandoverError, match="block at the boundary time is unavailable"):
        run_collect(tmp_path, fake, wall=wall, max_wait=60, transport=failing)
    assert not (tmp_path / "run" / "collection.json").exists()
    # The failing lookup was retried, not refused on first sight, until --max-wait passed.
    assert len(time_lookups(fake, "node-3")) > 1 and wall.t > fake.c["boundary"] + 61


def test_collect_recovers_from_a_boundary_lookup_that_fails_at_first(tmp_path):
    fake = FakeNodes()
    wall = Clock(fake.c["boundary"] + 1.0)
    until = fake.c["boundary"] + 20.0
    failing = lagging_transport(fake, wall, "node-3", until, error=True)
    args, summary = run_collect(tmp_path, fake, wall=wall, transport=failing)
    assert summary["center"] == 230378 and len(time_lookups(fake, "node-3")) > 1
    collected = json.loads((args.out / "collection.json").read_text())
    assert "error" not in collected["boundary_lookups"]["node-3"]["answer"]
    assert run(collected)["result"] == "PASS"


def test_collect_refuses_another_zero_state(tmp_path):
    fake = FakeNodes()
    key = ("node-1", "getMasterchainInfo", canon({}))
    fake.index[key] = copy.deepcopy(fake.index[key])
    fake.index[key]["result"]["init"]["file_hash"] = ch.lib.b64(b"\x05" * 32)
    with pytest.raises(ch.HandoverError, match="node-1 has another zero state"):
        run_collect(tmp_path, fake)


def test_collect_refuses_bad_arguments(tmp_path):
    fake = FakeNodes()
    with pytest.raises(ch.HandoverError, match="at least two distinct"):
        run_collect(tmp_path, fake, rpc=[next(iter(fake.urls))])
    (tmp_path / "used").mkdir()
    (tmp_path / "used" / "x").write_text("")
    with pytest.raises(ch.HandoverError, match="not empty"):
        run_collect(tmp_path, fake, out=tmp_path / "used")
    with pytest.raises(ch.HandoverError, match="--span"):
        run_collect(tmp_path, fake, span=0)
    assert fake.calls == []


def test_node_refuses_a_write_method(tmp_path):
    clock = Clock()
    calls = []
    node = ch.Node(
        "node-1",
        "http://node-1.invalid/jsonRPC",
        ch.Pacer(0.6, clock=clock, sleep=clock.sleep),
        ch.Journal(tmp_path / "journal.jsonl"),
        transport=lambda *a: calls.append(a),
    )
    with pytest.raises(ch.HandoverError, match="not a read-only method"):
        node.call("sendBoc", boc="")
    assert calls == [] and not (tmp_path / "journal.jsonl").exists()


def test_pacer_spacing_and_floor(tmp_path):
    with pytest.raises(ch.HandoverError, match="at least 0.6"):
        ch.Pacer(0.5)
    clock = Clock(10.0)
    pacer = ch.Pacer(0.6, clock=clock, sleep=clock.sleep)
    starts = [pacer.wait() for _ in range(4)]
    assert starts == pytest.approx([10.0, 10.6, 11.2, 11.8])
    # Two pacers sharing a lock file space their starts together.
    lock = tmp_path / "node.lock"
    a = ch.Pacer(0.6, clock=clock, sleep=clock.sleep, lock=lock)
    b = ch.Pacer(0.6, clock=clock, sleep=clock.sleep, lock=lock)
    shared = [a.wait(), b.wait(), a.wait(), b.wait()]
    assert all(y - x >= 0.6 - 1e-9 for x, y in zip(shared, shared[1:]))
