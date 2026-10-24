"""Crash-boundary tests for the real candidate driver, with a fake transport.

The stake body comes from tosctl's production builder, which is replaced here by
a stand-in of the same order layout. Wallet/TL-B correlation is covered separately
by test_local_pq_transactions and test_local_pq_election_evidence, not mocked here
and misrepresented as a live chain.
"""

import asyncio
import base64
import importlib.util
from pathlib import Path
from types import SimpleNamespace as Obj

import pytest
from local_pq_test_wire import address
from local_pq_transactions import read_json
from pytosiq_core import Builder, Cell

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
SPEC = importlib.util.spec_from_file_location(
    "resume_elections", SCRIPTS.joinpath("local-pq-elections.py")
)
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)
NANO = 10**9
ELECTION = 1791257021
NETWORK = dict(global_id=3, zerostate_root="aa" * 32)
WALLET = address(3)
CANDIDATE = dict(
    node=1,
    wallet=WALLET.to_str(is_user_friendly=False),
    adnl_id="04" * 32,
    key_id="05" * 32,
    public_key="06" * 1312,
)
ACCEPTED = dict(kind="accepted", reply=[0xF374484C, 0])
FULL = driver.STAKE + driver.STAKE_FEE + driver.WALLET_RESERVE


class Transport:
    """Plays the chain client, the faucet and the candidate wallet's sender."""

    def __init__(self, directory, wallet_balance=FULL):
        self.directory = directory
        self.wallet_balance = wallet_balance
        self.records = {}
        self.payments = []
        self.crash_after = None
        self.wallet = Obj(address=address(1))

    async def raw_get_account_state(self, account):
        return Obj(balance=self.wallet_balance, last_transaction_id=Obj(lt=0, hash=bytes(32)))

    def record(self, label):
        return self.records.get(label)

    async def transfer(self, label, dest, amount, body=None, init=None, bounce=False):
        # Even the first capital send must be preceded by durable business intent.
        intent = read_json(self.directory / "candidate-intent-1.json")
        assert intent["state"] == "prepared"
        if label not in self.records:
            self.payments.append((label, dest, amount, body.hash if body else None, bounce))
            self.records[label] = dict(label=label, ok=True, exit_code=0, action_code=None)
        if self.crash_after == label:
            self.crash_after = None
            raise OSError("crash after payment inclusion")
        return self.records[label]


@pytest.fixture
def harness(tmp_path, monkeypatch):
    monkeypatch.setattr(driver, "OUT", tmp_path)
    transport = Transport(tmp_path)
    observed = dict(wallet=0, authorization=0, evidence=0, builder=0, fail_evidence=False)

    async def ensure(*args, **kwargs):
        observed["wallet"] += 1

    async def history(*args, **kwargs):
        return []

    def result(*args, **kwargs):
        observed["evidence"] += 1
        if observed["fail_evidence"]:
            observed["fail_evidence"] = False
            raise OSError("crash before business receipt persistence")
        return ACCEPTED.copy()

    def builder(executable, **fields):
        # The production builder's own output is checked in tos; here only its
        # inputs and the driver's handling of the order matter.
        observed["builder"] += 1
        assert fields["stake_amount"] == driver.STAKE and fields["algorithm_id"] == 1
        return (
            Builder()
            .store_uint(0x4E73744B, 32)
            .store_uint(fields["query_id"], 64)
            .store_coins(fields["stake_amount"])
            .store_uint(fields["stake_at"], 32)
            .end_cell()
        )

    class Request:
        def __init__(self, **kwargs):
            assert kwargs["stake_owner"] == WALLET.hash_part
            self.kwargs = kwargs

        def parse_result(self, response):
            return response

    class Console:
        async def request_with_raw(self, request):
            observed["authorization"] += 1
            auth = Obj(
                validator_id=WALLET.hash_part,
                key_id=bytes.fromhex("05" * 32),
                public_key=bytes.fromhex("06" * 1312),
                algorithm_id=1,
                signature=b"\x07" * 2420,
            )
            return auth, b"", b"{}"

    monkeypatch.setattr(driver, "ensure_wallet", ensure)
    monkeypatch.setattr(driver, "history_since", history)
    monkeypatch.setattr(driver, "election_result", result)
    monkeypatch.setattr(driver, "build_production_pool_stake_order", builder)
    monkeypatch.setattr(driver.local, "require_installed_executable", lambda path: path)
    monkeypatch.setattr(
        driver.tos_api, "Engine_validator_createPqStakeAuthorizationRequest", Request
    )

    def run(election=ELECTION, network=NETWORK, console=None):
        return asyncio.run(
            driver.submit_candidate(
                transport,
                transport,
                transport,
                console or Console(),
                CANDIDATE,
                election,
                1,
                network,
            )
        )

    return transport, observed, run


def test_completed_candidate_is_not_paid_again_after_partial_round(harness):
    transport, observed, run = harness
    assert run() == run() == ACCEPTED
    assert len(transport.payments) == 1
    assert observed == dict(wallet=1, authorization=1, evidence=1, builder=1, fail_evidence=False)


def test_the_stake_goes_from_the_wallet_to_the_elector_without_an_amount_field(harness):
    transport, _, run = harness
    run()
    [(label, dest, amount, body_hash, bounce)] = transport.payments
    assert label == f"stake-{ELECTION}-1" and dest == driver.ELECTOR and bounce is True
    assert amount == driver.STAKE + driver.STAKE_FEE == 11_001_200_000_000
    intent = read_json(transport.directory / "candidate-intent-1.json")
    body = Cell.one_from_boc(base64.b64decode(intent["body"])).begin_parse()
    assert body.load_uint(32) == 0x4E73744B and body.load_uint(64) == intent["query"]
    assert body.load_uint(32) == ELECTION  # the amount the pool order carried is gone
    assert intent["query"] == driver.stake_query(ELECTION, 1)


@pytest.mark.parametrize("boundary", ["capital", "stake", "receipt"])
def test_crash_never_adds_another_payment_or_authorization(harness, boundary):
    transport, observed, run = harness
    transport.wallet_balance = FULL - 20 * NANO
    if boundary == "receipt":
        observed["fail_evidence"] = True
    else:
        label = "wallet-capital" if boundary == "capital" else "stake"
        transport.crash_after = f"{label}-{ELECTION}-1"
    with pytest.raises(OSError):
        run()
    assert run() == ACCEPTED
    assert len(transport.payments) == 2
    assert transport.payments[0][2] == 20 * NANO  # only the deficit
    assert observed["wallet"] == observed["authorization"] == observed["builder"] == 1


def test_old_broadcast_is_reconciled_before_the_next_round(harness):
    transport, observed, run = harness
    observed["fail_evidence"] = True
    with pytest.raises(OSError):
        run()
    assert run(ELECTION + 600) == ACCEPTED
    assert observed["evidence"] == 3
    assert len(transport.payments) == 2
    assert (transport.directory / f"intent-history-{ELECTION}-1.json").exists()


def test_chain_identity_mismatch_never_sends(harness):
    transport, _, run = harness
    run()
    with pytest.raises(ValueError, match="different chain"):
        run(network=dict(NETWORK, zerostate_root="bb" * 32))
    assert len(transport.payments) == 1


def test_persisted_refusal_is_not_repaid(harness, monkeypatch):
    transport, _, run = harness
    refusal = dict(kind="elector_bounced", returned_nano=1, wallet_bounce_applied=True)
    monkeypatch.setattr(driver, "election_result", lambda *args, **kwargs: refusal.copy())
    assert run() == run() == refusal
    assert len(transport.payments) == 1


def test_a_failed_elector_transaction_is_final_for_the_election(harness):
    transport, _, run = harness
    transport.records[f"stake-{ELECTION}-1"] = dict(ok=False, exit_code=5, action_code=None)
    assert run() == dict(kind="elector_failed", exit_code=5, action_code=None)
    assert run()["kind"] == "elector_failed"


def test_a_node_signing_for_another_account_is_refused_before_any_send(harness):
    transport, _, run = harness

    class Foreign:
        async def request_with_raw(self, request):
            auth = Obj(
                validator_id=address(9).hash_part,
                key_id=bytes.fromhex("05" * 32),
                public_key=bytes.fromhex("06" * 1312),
                algorithm_id=1,
                signature=b"\x07" * 2420,
            )
            return auth, b"", b"{}"

    with pytest.raises(ValueError, match="differs from candidate"):
        run(console=Foreign())
    assert transport.payments == []


def test_one_member_fault_does_not_stop_the_rest_of_the_round(monkeypatch):
    # Elections must keep producing key blocks; a member that fails or is refused
    # is recorded as degraded while the other members still stake.
    monkeypatch.setattr(driver, "event", lambda *args, **kwargs: None)
    outcomes = {
        1: ACCEPTED,
        2: TimeoutError("unresolved stake"),
        3: dict(kind="elector_bounced", returned_nano=1),
        7: ACCEPTED,
    }

    async def submit(i):
        outcome = outcomes[i]
        if isinstance(outcome, Exception):
            raise outcome
        return dict(outcome)

    degraded = {9: dict(at=0, error="old")}
    accepted, settled = asyncio.run(driver.run_round(submit, (1, 2, 3, 7), ELECTION, degraded))
    assert accepted == [1, 7]
    assert settled is False  # node 2 is retried on the next pass
    assert set(degraded) == {2, 3, 9}
    outcomes[2] = ACCEPTED
    accepted, settled = asyncio.run(driver.run_round(submit, (1, 2, 3, 7), ELECTION, degraded))
    assert settled is True and 2 not in degraded


def test_a_closed_election_stops_the_round(monkeypatch):
    monkeypatch.setattr(driver, "event", lambda *args, **kwargs: None)

    async def submit(i):
        return dict(kind="refused", reply=[0xEE6F454C, 0])

    accepted, settled = asyncio.run(driver.run_round(submit, (1, 2), ELECTION, {}))
    assert accepted == [] and settled is True


def test_a_transiently_degraded_member_is_cleared_once_it_checks_out(monkeypatch):
    monkeypatch.setattr(driver, "event", lambda *args, **kwargs: None)
    healthy = {7}

    async def ensure(client, faucet, candidate, index):
        if index not in healthy:
            raise RuntimeError("LITE_SERVER_NOTREADY")

    monkeypatch.setattr(driver, "ensure_wallet", ensure)
    old = driver.time.time() - 120
    degraded = {
        7: dict(at=old, kind="not_ready", error="x"),
        4: dict(at=old, kind="failed", error="x"),
        3: dict(at=old, kind="refused", error="x"),
        2: dict(at=driver.time.time(), kind="not_ready", error="x"),
    }
    candidates = {i: CANDIDATE for i in (2, 3, 4, 7)}
    asyncio.run(driver.reprobe(degraded, candidates, None, None))
    assert 7 not in degraded  # checked out: cleared
    assert degraded[4]["at"] > old  # still failing: kept, retried later
    assert 3 in degraded  # a stake refusal is the election's outcome
    assert 2 in degraded  # too recent to probe again


class RecoveryChain:
    def __init__(self, returned):
        self.returned = returned
        self.sent = []
        self.recovered = 0

    async def raw_get_account_state(self, account):
        return Obj(balance=5 * NANO, code=b"x", last_transaction_id=Obj(lt=77, hash=bytes(32)))

    async def recover(self):
        self.recovered += 1

    async def transfer(self, label, dest, amount, body=None, init=None, bounce=False):
        self.sent.append((label, dest, amount, body, bounce))
        return dict(label=label, ok=True, exit_code=0, action_code=None)


@pytest.fixture
def recovery(tmp_path, monkeypatch):
    monkeypatch.setattr(driver, "OUT", tmp_path)
    events = []
    monkeypatch.setattr(driver, "event", lambda kind, **fields: events.append((kind, fields)))

    def run(returned, outcome=None):
        chain = RecoveryChain(returned)
        asked = []

        async def lite(method, *args, **kwargs):
            asked.append((method, args))
            return chain.returned

        async def history(*args, **kwargs):
            return []

        monkeypatch.setattr(driver, "lite_int", lite)
        monkeypatch.setattr(driver, "history_since", history)
        monkeypatch.setattr(
            driver, "recovery_result", lambda *a, **k: outcome or dict(kind="recovered")
        )
        result = asyncio.run(driver.recover_candidate(chain, chain, CANDIDATE, 1))
        return chain, asked, result

    return run, events, tmp_path


def test_nothing_returned_sends_nothing_but_records_the_wallet(recovery):
    run, events, directory = recovery
    chain, asked, result = run(0)
    assert result is None and chain.sent == [] and events == []
    assert asked == [("compute_returned_stake", (str(int.from_bytes(WALLET.hash_part, "big")),))]
    row = read_json(directory / "wallet-1.json")
    assert row["deployed"] and row["returned_stake"] == 0 and row["wallet"] == CANDIDATE["wallet"]
    assert chain.recovered == 1  # an uncertain earlier send is settled first


def test_a_returned_stake_is_requested_from_the_wallet(recovery):
    run, events, _ = recovery
    chain, _, result = run(11 * NANO)
    [(label, dest, amount, body, bounce)] = chain.sent
    assert label == "recover-1-77" and dest == driver.ELECTOR and bounce is True
    assert amount == driver.RECOVER_FEE == 200_000_000
    fields = body.begin_parse()
    assert fields.load_uint(32) == 0x47657424 and fields.load_uint(64) == 77
    assert not fields.remaining_bits and not fields.remaining_refs
    assert result == dict(kind="recovered")
    assert events[0][0] == "stake_recovery" and events[0][1]["expected_nano"] == 11 * NANO


def test_the_authorization_request_names_the_fields_the_node_schema_defines():
    # The harness replaces the request class with a fake, so a field the generated
    # schema does not have would pass there and fail on the first live round.
    import ast
    import inspect

    tree = ast.parse(Path(SPEC.origin).read_text())
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and getattr(node.func, "attr", None) == "Engine_validator_createPqStakeAuthorizationRequest"
    ]
    assert len(calls) == 1
    sent = {keyword.arg for keyword in calls[0].keywords}
    real = driver.tos_api.Engine_validator_createPqStakeAuthorizationRequest
    defined = set(inspect.signature(real).parameters) - {"self"}
    assert sent == defined
