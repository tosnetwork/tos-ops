"""The T1 evidence contract (t1_evidence.py): generic sweeps over every schema and field, and the file-level
rules (missing files, unknown types, torn or duplicate-key lines, duplicates), each checked end to end through the
judge where it matters. The semantic controls (thresholds, chronology, ordering, coverage) stay in
test_t1_judge.py."""

import importlib.util
import json
import math
import shutil

import pytest
import t1_fixture
from conftest import SCRIPTS
from test_t1_judge import JUDGE, READ, RATE, T0, edit, reseal

spec = importlib.util.spec_from_file_location("t1_judge_ev", SCRIPTS / "t1-judge.py")
tj = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tj)
E = tj.E  # the contract module exactly as the judge imports it

SAMPLES = t1_fixture.samples()
# The fields each producer may write as null (from the producer inventory cited in t1_evidence.py). Any other
# field set to null is a violation; this list must change only together with its producer.
NULLABLE = {
    "cache/coverage_gap": {"name", "bytes"},
    "clock": {"best"},
    "boundaries/planned": {"term"},
    "journal/attempt/transfer": {"prior"},
    "journal/sent": {"reason"},
    "journal/observed/transfer": {"fee"},
    "journal/observed/funding": {"fee"},
    "journal/delivered": {"receipt_failure"},
    "journal/unknown": {"reason"},
    "reads/request": {"error"},
}


def test_every_schema_has_a_sample_and_every_sample_satisfies_its_schema():
    assert set(SAMPLES) <= set(E.SCHEMAS)
    for name, s in SAMPLES.items():
        r = s["record"]
        bad = [k for k, c in E.SCHEMAS[name].items() if k not in r or not c(r[k])]
        assert not bad, f"{name}: the sample violates the schema at {bad}"
    # Schemas without a sample are the producers' rare paths; each is listed so that a new one is a decision.
    assert set(E.SCHEMAS) - set(SAMPLES) == {
        "boundaries/interrupted", "boundaries/missed", "boundaries/planned", "boundaries/schedule_mismatch",
        "boundaries/term_error", "cache/coverage_gap", "cache/error", "chain/cadence_miss", "chain/head_error",
        "chain/regression", "fees/error", "journal/expired", "journal/unknown", "load/alarm", "load/refused",
        "load/stop", "resources/complete-inactive", "resources/error", "resources/incomplete",
        "safety/safety_line"}


def test_the_nullable_fields_are_exactly_the_producers():
    for name, fields in E.SCHEMAS.items():
        nullable = {k for k, c in fields.items() if c(None)}
        assert nullable == NULLABLE.get(name, set()), name


SWEEP = [(name, field) for name in sorted(SAMPLES) for field in sorted(E.SCHEMAS[name])]


def accepts(name: str, r: dict) -> bool:
    return all(k in r and c(r[k]) for k, c in E.SCHEMAS[name].items())


@pytest.mark.parametrize("name,field", SWEEP)
def test_dropping_any_field_violates_its_schema(name, field):
    r = dict(SAMPLES[name]["record"])
    assert accepts(name, r)
    del r[field]
    assert not accepts(name, r)


@pytest.mark.parametrize("name,field", SWEEP)
def test_a_wrong_type_in_any_field_violates_its_schema(name, field):
    r = dict(SAMPLES[name]["record"], **{field: math.nan})
    assert not accepts(name, r)


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_booleans_never_stand_in_for_integers(name):
    r = SAMPLES[name]["record"]
    for field, v in r.items():
        if type(v) is int and field in E.SCHEMAS[name]:
            assert not accepts(name, dict(r, **{field: True})), f"{name}.{field} accepts a bool"


# ---------------------------------------------------------------- end to end through the judge


@pytest.fixture(scope="module")
def green(tmp_path_factory):
    from test_t1_judge import build
    root = tmp_path_factory.mktemp("green-ev")
    build(root)
    return root


@pytest.fixture()
def run(green, tmp_path, monkeypatch):
    monkeypatch.setattr(tj, "DECLARED_RATE", RATE)
    monkeypatch.setattr(tj, "READ_RATE", READ)
    root = tmp_path / "ev"
    shutil.copytree(green, root)

    def judge():
        return tj.verdict(JUDGE, root / "observe", root / "load")
    judge.root = root
    return judge


FILES = {"resources": "observe/resources.jsonl", "cache": "observe/cache.jsonl", "chain": "observe/chain.jsonl",
         "clock": "observe/clock.jsonl", "fees": "observe/fees.jsonl", "boundaries": "observe/boundaries.jsonl",
         "journal": "load/ramp/journal.jsonl", "reads/requests.jsonl": "load/reads/requests.jsonl",
         "reads/CONTEXT.json": "load/reads/CONTEXT.json", "reads/RESULT.json": "load/reads/RESULT.json"}


def dependents(file: str) -> list[str]:
    return [c for c, fs in tj.CRITERION_FILES.items() if file in fs or file.split("/")[0] in fs]


def test_the_green_run_passes_on_producer_shaped_evidence(run):
    v = run()
    assert v["verdict"] == "PASS", {k: c for k, c in v["criteria"].items() if c["status"] != "PASS"}


@pytest.mark.parametrize("file", sorted(FILES))
def test_a_missing_file_is_never_a_pass(run, file):
    (run.root / FILES[file]).unlink()
    v = run()
    assert v["verdict"] != "PASS"
    for c in dependents(file):
        assert v["criteria"][c]["status"] != "PASS", c
        # the absence itself is reported, not only its consequences
        assert file in v["criteria"][c]["contract_violations"].get("missing_files", []), c


def test_a_missing_load_log_refuses(run):
    (run.root / "load/load.jsonl").unlink()
    with pytest.raises(tj.Refuse, match="never started"):
        run()


@pytest.mark.parametrize("file", ["resources", "cache", "chain", "clock", "fees", "boundaries", "journal"])
def test_an_unknown_record_type_is_a_violation(run, file):
    p = run.root / FILES[file]
    key = "type" if file == "journal" else "outcome" if file == "boundaries" else "kind"
    with p.open("a") as fh:
        fh.write(json.dumps({"ts": T0 + 10, "host": "node-1", key: "mystery", "id": "transfer:0:0",
                             "sent": T0, "received": T0}) + "\n")
    v = run()
    for c in dependents(file):
        assert v["criteria"][c]["status"] != "PASS", c
        assert file in v["criteria"][c].get("contract_violations", {}) or v["criteria"][c]["status"] == "FAIL"


@pytest.mark.parametrize("file", ["resources", "chain", "journal", "fees"])
def test_a_torn_line_inside_a_file_is_a_violation(run, file):
    p = run.root / FILES[file]
    lines = p.read_bytes().split(b"\n")
    lines[3] = lines[3][: len(lines[3]) // 2]
    p.write_bytes(b"\n".join(lines))
    v = run()
    for c in dependents(file):
        assert v["criteria"][c]["status"] != "PASS", c


def test_a_torn_last_line_is_dropped(run):
    p = run.root / FILES["fees"]
    with p.open("a") as fh:
        fh.write('{"ts": 1')
    assert run()["verdict"] == "PASS"


def test_duplicate_json_member_names_are_a_violation(run):
    p = run.root / FILES["fees"]
    lines = p.read_text().splitlines()
    lines[5] = lines[5][:-1] + ', "balance_nano": 1}'
    p.write_text("\n".join(lines) + "\n")
    f = run()["criteria"]["5.8 operators"]
    assert f["status"] != "PASS" and "fees" in f["contract_violations"]


def test_a_record_dropped_from_every_row_of_a_type_is_never_a_pass(run):
    edit(run.root / FILES["journal"],
         lambda rs: [{k: v for k, v in r.items() if k != "tx_mc"} if r["type"] == "observed" and
                     r["id"].startswith("transfer") else r for r in rs])
    assert run()["criteria"]["5.7 writes"]["status"] != "PASS"


def test_an_identical_repeated_journal_record_is_one_record(run):
    edit(run.root / FILES["journal"], lambda rs: rs[:20] + rs[10:20] + rs[20:])
    assert run()["criteria"]["5.7 writes"]["status"] == "PASS"


def test_a_different_record_under_the_same_key_is_not_a_pass(run):
    def twist(rs):
        obs = next(r for r in rs if r["type"] == "observed" and r["id"].startswith("transfer"))
        return rs + [dict(obs, utime=obs["utime"] + 1)]
    edit(run.root / FILES["journal"], twist)
    w = run()["criteria"]["5.7 writes"]
    assert w["status"] != "PASS" and "journal" in w["contract_violations"]


def test_a_journal_event_of_no_attempt_is_a_violation(run):
    edit(run.root / FILES["journal"], lambda rs: rs + [dict(next(r for r in rs if r["type"] == "delivered"),
                                                           id="transfer:9:999999")])
    w = run()["criteria"]["5.7 writes"]
    assert w["status"] != "PASS" and "journal" in w["contract_violations"]


def test_an_unknown_attempt_role_is_a_violation(run):
    edit(run.root / FILES["journal"], lambda rs: rs + [dict(next(r for r in rs if r["type"] == "attempt"),
                                                           id="deployment:0:0", role="deployment")])
    assert "journal" in run()["criteria"]["5.7 writes"]["contract_violations"]


def test_a_duplicated_read_record_is_not_a_pass_even_when_resealed(run):
    p = run.root / FILES["reads/requests.jsonl"]
    lines = p.read_bytes().splitlines(keepends=True)
    p.write_bytes(b"".join(lines[:100] + lines[50:100] + lines[100:]))
    reseal(run.root)
    r = run()["criteria"]["5.6 reads"]
    assert r["status"] != "PASS" and "reads" in r["contract_violations"]


def test_a_read_journal_that_does_not_match_its_result_is_not_a_pass(run):
    p = run.root / FILES["reads/requests.jsonl"]
    lines = p.read_bytes().splitlines(keepends=True)
    p.write_bytes(b"".join(lines[:-1]))
    r = run()["criteria"]["5.6 reads"]
    assert r["status"] != "PASS" and "reads" in r["contract_violations"]


def test_a_read_record_without_its_error_field_is_not_a_pass(run):
    edit(run.root / FILES["reads/requests.jsonl"], lambda rs: [{k: v for k, v in r.items() if k != "error"}
                                                               for r in rs])
    reseal(run.root)
    assert run()["criteria"]["5.6 reads"]["status"] != "PASS"


def test_a_calibration_run_is_not_judged_as_t1(run):
    edit(run.root / "load/load.jsonl", lambda rs: [dict(r, mode="calibration") if r["kind"] == "start" else r
                                                   for r in rs])
    with pytest.raises(tj.Refuse, match="calibration"):
        run()


def test_a_fee_the_node_did_not_report_leaves_the_cap_unproven(run):
    edit(run.root / FILES["journal"], lambda rs: [dict(r, fee=None) if r["type"] == "observed" and
                                                  r["id"].startswith("funding") else r for r in rs])
    w = run()["criteria"]["5.7 writes"]
    assert w["status"] == "INCONCLUSIVE" and w["fee_unknown"] == 1


def test_funding_records_in_their_producer_shape_pass(run):
    # the funding observed record has `problems`, not `failure` (codex r3 #1): its own schema applies
    rs = [json.loads(x) for x in (run.root / FILES["journal"]).read_text().splitlines()]
    fund = [r for r in rs if r["type"] == "observed" and r["id"].startswith("funding")]
    assert fund and "failure" not in fund[0] and "problems" in fund[0]
    assert run()["criteria"]["5.7 writes"]["status"] == "PASS"


def test_an_observed_record_of_no_attempt_is_a_violation(run):
    edit(run.root / FILES["journal"], lambda rs: rs + [dict(next(r for r in rs if r["type"] == "observed" and
                                                                r["id"].startswith("transfer")),
                                                           id="transfer:9:999999")])
    w = run()["criteria"]["5.7 writes"]
    assert w["status"] != "PASS" and any("no attempt" in x for x in w["contract_violations"]["journal"])


def test_a_read_record_changed_after_the_result_is_a_violation(run):
    # same row count, one value changed: only the hash can tell
    p = run.root / FILES["reads/requests.jsonl"]
    lines = p.read_bytes().splitlines(keepends=True)
    lines[7] = lines[7].replace(b'"latency_seconds": 0.05', b'"latency_seconds": 0.06')
    p.write_bytes(b"".join(lines))
    r = run()["criteria"]["5.6 reads"]
    assert r["status"] != "PASS" and any("hash" in x for x in r["contract_violations"]["reads"])


def test_a_result_count_that_does_not_match_the_journal_is_a_violation(run):
    # the hash is right, the count is not: only the count check can tell
    p = run.root / FILES["reads/RESULT.json"]
    p.write_text(json.dumps(dict(json.loads(p.read_text()), completed=1)))
    r = run()["criteria"]["5.6 reads"]
    assert r["status"] != "PASS" and any("completed" in x for x in r["contract_violations"]["reads"])


# ---------------------------------------------------------------- codex contract review r1


def test_the_contract_constants_are_the_observers():
    s = importlib.util.spec_from_file_location("t1_observe_consts", SCRIPTS / "t1-observe.py")
    obs = importlib.util.module_from_spec(s)
    s.loader.exec_module(obs)
    assert (E.SHARD, E.BALANCE_QUORUM, E.CLOCK_LIMIT, E.UUID.pattern, E.UNIT_STATES) == \
        (obs.SHARD, obs.BALANCE_QUORUM, obs.CLOCK_LIMIT, obs.UUID.pattern, obs.UNIT_STATES)


def test_a_duplicate_key_record_on_the_last_line_is_a_violation_not_a_torn_write(run):
    row = ('{"ts": %s, "host": "node-2", "sent": %s, "received": %s, "kind": "safety_line", "file": "node.log", '
           '"line": "ok", "line": "MISBEHAVIOR"}' % (T0 + 50, T0 + 49, T0 + 50))
    (run.root / "observe/safety.jsonl").write_text(row)  # no trailing newline
    s = run()["criteria"]["5.5 no safety line"]
    assert s["status"] != "PASS" and "safety" in s["contract_violations"]


def test_an_inactive_unit_is_a_valid_observation_and_fails(run):
    def stop(r):
        if r["host"] != "node-2" or not T0 + 50_000 <= r["ts"] <= T0 + 50_600:
            return r
        return dict(r, unit=dict(r["unit"], active_state="inactive", main_pid=0), proc="no main pid")
    edit(run.root / FILES["resources"], lambda rs: [stop(r) for r in rs])
    v = run()
    c = v["criteria"]["5.2 no restart, OOM or divergence"]
    assert c["status"] == "FAIL" and "contract_violations" not in c
    assert "contract_violations" not in v["criteria"]["5.3 bounded memory"]


def test_a_clock_verdict_its_measurements_contradict_is_a_violation(run):
    edit(run.root / FILES["clock"], lambda rs: [dict(r, best={"offset": 1000.0, "bound": 0.1},
                                                     tries=[{"offset": 1000.0, "bound": 0.1}]) for r in rs])
    c = run()["criteria"]["collector clock"]
    assert c["status"] != "PASS" and "clock" in c["contract_violations"]


def test_a_balance_its_source_answers_contradict_is_a_violation(run):
    edit(run.root / FILES["fees"], lambda rs: [dict(r, answers={h: 1 for h in r["answers"]}) for r in rs])
    c = run()["criteria"]["5.8 operators"]
    assert c["status"] != "PASS" and "fees" in c["contract_violations"]


def test_a_reading_of_another_wallet_does_not_count_for_the_operator(run):
    edit(run.root / FILES["fees"], lambda rs: [dict(r, address="-1:" + "f" * 64) if r["operator"] == "node-3" else r
                                               for r in rs])
    c = run()["criteria"]["5.8 operators"]
    assert c["status"] == "INCONCLUSIVE" and "node-3" in c["operators_without_readings"] \
        and "contract_violations" not in c


def test_block_ids_with_invalid_hashes_are_a_violation(run):
    edit(run.root / FILES["chain"], lambda rs: [dict(r, id=r["id"][:3] + ["not-a-hash", "not-a-hash"])
                                                if r["kind"] == "head" else r for r in rs])
    c = run()["criteria"]["5.1 no stall"]
    assert c["status"] != "PASS" and "chain" in c["contract_violations"]


def test_ids_off_the_common_height_are_a_violation(run):
    def shift(r):
        if r["kind"] != "ids":
            return r
        ids = dict(r["ids"])
        ids["node-4"] = ids["node-4"][:2] + [r["seqno"] + 1] + ids["node-4"][3:]
        return dict(r, ids=ids)
    edit(run.root / FILES["chain"], lambda rs: [shift(r) for r in rs])
    assert "chain" in run()["criteria"]["5.2 no restart, OOM or divergence"]["contract_violations"]


def test_a_disagree_flag_its_answers_contradict_is_a_violation(run):
    edit(run.root / FILES["fees"], lambda rs: [dict(r, disagree=True) for r in rs])
    assert "fees" in run()["criteria"]["5.8 operators"]["contract_violations"]


def test_an_answer_from_a_host_that_is_not_a_validator_is_a_violation(run):
    edit(run.root / FILES["fees"], lambda rs: [dict(r, answers={**r["answers"], "node-dht": r["balance_nano"]})
                                               for r in rs])
    assert "fees" in run()["criteria"]["5.8 operators"]["contract_violations"]


def test_a_balance_from_a_single_source_is_a_violation(run):
    # consistent with its one answer, so only the quorum rule can catch it
    edit(run.root / FILES["fees"], lambda rs: [dict(r, answers={"node-1": r["balance_nano"]}) for r in rs])
    c = run()["criteria"]["5.8 operators"]
    assert c["status"] != "PASS" and any("quorum" in x for x in c["contract_violations"]["fees"])



# ---------------------------------------------------------------- codex contract review r2


def test_a_negative_clock_bound_is_a_violation(run):
    hidden = {"offset": 1000.0, "bound": -1001.0}
    edit(run.root / FILES["clock"], lambda rs: [dict(r, best=hidden, tries=[hidden]) for r in rs])
    c = run()["criteria"]["collector clock"]
    assert c["status"] != "PASS" and "clock" in c["contract_violations"]


@pytest.mark.parametrize("sources", [[], ["node-1", "node-2", "node-3"], ["node-1", "node-1", "node-2", "node-3"]])
def test_a_checked_boundary_must_name_the_four_validators(run, sources):
    edit(run.root / FILES["boundaries"], lambda rs: [dict(r, sources=sources) for r in rs])
    b = run()["criteria"]["5.1 handovers and key gate"]
    assert b["status"] != "PASS" and "boundaries" in b["contract_violations"]
