"""Onboarding a validator whose host only its operator touches.

The coordinator runs `testnet-elections.py onboard --no-host` (its own journaled
value steps, then the operator's outcome read on chain); the operator runs
`testnet-operator.py onboard` on their own host. Both run here against the
asynchronous fake chain (fakechain.py) and the fake validator host of
test_elections.py.
"""

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys

import fakechain
import pytest
import testnet_lib as lib
from conftest import SCRIPTS
from test_elections import (  # noqa: F401 (boarding and pinned_tos are fixtures)
    ALL_STEPS,
    HOST_WALLET,
    NANO,
    boarding,
    crash,
    elections,
    onboard,
    pinned_tos,
    settled_ids,
)

spec = importlib.util.spec_from_file_location("testnet_operator", SCRIPTS / "testnet-operator.py")
operator_tool = importlib.util.module_from_spec(spec)
sys.modules["testnet_operator"] = operator_tool
spec.loader.exec_module(operator_tool)

PROFILE = lib.load_profile()
E = PROFILE["elections"]


def no_host_args(b):
    return argparse.Namespace(**dict(vars(b["args"]), host=None, ssh_key=None, no_host=True))


def coordinator(b):
    return elections.onboard_external(no_host_args(b), b["ops"], 2, lib.load_profile())


def operator_args(b, **extra):
    fields = {
        "name": "node-1",
        "pool": b["pool"],
        "owner": b["owner"],
        "rpc": None,
        "out": None,
        "tos_root": b["tos"],
    }
    fields.update(extra)
    return argparse.Namespace(**fields)


def operator(b, **extra):
    chain = b["chain"]
    reader = operator_tool.NodeReader("http://local", fakechain.NodeRpc(chain, False, False))
    return operator_tool.onboard_host(
        operator_args(b, **extra),
        b["host"],
        reader,
        lib.load_profile(),
        sleep=lambda s: chain.tick(),
    )


@pytest.fixture
def external(boarding, monkeypatch):  # noqa: F811 (the imported fixture)
    """The coordinator side of an operator-run host: constructing an SSH Host, or
    running ssh at all, fails the test."""

    def no_host(*args, **kwargs):
        raise AssertionError("the operator-run path constructed an SSH Host")

    monkeypatch.setattr(elections, "Host", no_host)
    refuse_remote_shells(monkeypatch)
    return boarding


REMOTE_TOOLS = ("ssh", "scp", "sftp")
# A remote tool named as a word of a shell string: "ssh host", "x; /usr/bin/scp f h:".
REMOTE_IN_SHELL = re.compile(r"(?:^|[\s;|&(/])(?:ssh|scp|sftp)(?:\s|$)")


def names_remote_tool(command) -> bool:
    if isinstance(command, (bytes, str, os.PathLike)):
        text = os.fsdecode(command)
        return os.path.basename(text) in REMOTE_TOOLS or bool(REMOTE_IN_SHELL.search(text))
    parts = [os.fsdecode(c) for c in command if isinstance(c, (bytes, str, os.PathLike))]
    return any(
        os.path.basename(part) in REMOTE_TOOLS or REMOTE_IN_SHELL.search(part) for part in parts
    )


def refuse_remote_shells(monkeypatch):
    """Every way this process could start ssh, scp or sftp fails the test instead:
    subprocess (run, call, check_output and Popen all go through Popen),
    os.system, and the os.exec* / os.spawn* / os.posix_spawn* families."""
    real_popen = subprocess.Popen

    class GuardedPopen(real_popen):
        def __init__(self, args, *rest, **kwargs):
            assert not names_remote_tool(args), f"the operator-run path ran {args!r}"
            super().__init__(args, *rest, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", GuardedPopen)

    def guard(name):
        real = getattr(os, name)

        def call(*args, **kwargs):
            # exec*/spawn*/posix_spawn*: (mode,) path, argv, ...; system: the command.
            for arg in args:
                if isinstance(arg, (str, bytes, os.PathLike, list, tuple)):
                    assert not names_remote_tool(arg), f"the operator-run path ran {args!r}"
            return real(*args, **kwargs)

        monkeypatch.setattr(os, name, call)

    for name in dir(os):
        if name == "system" or re.fullmatch(r"(exec|spawn)[lv]p?e?|posix_spawnp?", name):
            guard(name)


def test_the_remote_shell_guard_refuses_every_spelling(monkeypatch):
    refuse_remote_shells(monkeypatch)
    for attempt in (
        lambda: subprocess.run(["ssh", "-V"]),
        lambda: subprocess.run(["/usr/bin/ssh", "-V"]),
        lambda: subprocess.Popen(["/usr/bin/scp", "a", "b:"]),
        lambda: subprocess.run("true; /usr/bin/ssh -V", shell=True),
        lambda: subprocess.check_output(["bash", "-c", "sftp host"]),
        lambda: os.system("ssh -V"),
        lambda: os.execv("/usr/bin/ssh", ["ssh", "-V"]),
        lambda: os.spawnv(os.P_WAIT, "/usr/bin/ssh", ["ssh", "-V"]),
        lambda: os.posix_spawn("/usr/bin/ssh", ["ssh", "-V"], {}),
    ):
        with pytest.raises(AssertionError, match="operator-run path ran"):
            attempt()
    assert subprocess.run(["true"]).returncode == 0


def coordinator_until_hand_off(b):
    with pytest.raises(elections.WaitingForOperator) as info:
        coordinator(b)
    return str(info.value)


# ---------------------------------------------------------------- the whole hand-off


def test_one_hand_off_onboards_an_operator_run_host(external):
    b = external
    chain = b["chain"]
    message = coordinator_until_hand_off(b)
    # Every coordinator step settled, without the host: the pool is deployed by
    # the owner and holds the principal; the operator wallet only got fee money.
    assert settled_ids(b) == sorted(ALL_STEPS)
    deploy = b["ops"].journal.record("deploy-pool-node-1")
    assert deploy["kind"] == elections.OWNER_DEPLOY_KIND
    assert deploy["wallet"] == b["owner"] and deploy["operator"] == b["host"].operator
    assert chain.account(b["pool"])["balance"] == (E["pool_deploy_tos"] + E["pool_tos"]) * NANO
    assert chain.account(b["host"].operator)["balance"] == E["operator_funding_tos"] * NANO
    assert chain.account(b["host"].operator)["state"] != "active"
    assert len(chain.sent) == len(ALL_STEPS)
    assert b["host"].commands == []
    # The hand-off names the operator's exact command.
    assert (
        f"testnet-operator.py onboard --name node-1 --pool {b['pool']} --owner {b['owner']}"
        in message
    )

    result = operator(b)
    assert result["operator_state"] == "active" and result["elections_unit"] == "active"
    assert b["host"].config["pools"]["pool-node-1"] == {"address": b["pool"], "owner": b["owner"]}
    assert b["host"].config["bindings"]["node-1"] == {"wallet": "op-node-1", "pool": "pool-node-1"}
    assert sum("enable-elections.sh" in c for c in b["host"].commands) == 1
    # The operator's only message: the wallet's own deployment, no value sent.
    assert len(chain.sent) == len(ALL_STEPS) + 1

    done = coordinator(b)
    assert done["operator_state"] == "active"
    assert done["pool_nanotos"] == (E["pool_deploy_tos"] + E["pool_tos"]) * NANO
    # The host's binding and election task are not on chain before an election.
    assert done["host_binding_and_election_task"] == "UNVERIFIED"
    assert "Elector" in done["next"]
    assert len(chain.sent) == len(ALL_STEPS) + 1


def test_reruns_on_both_sides_change_nothing(external):
    b = external
    coordinator_until_hand_off(b)
    operator(b)
    coordinator(b)
    sent, commands = list(b["chain"].sent), list(b["host"].commands)
    config = json.loads(json.dumps(b["host"].config))
    operator(b)
    coordinator(b)
    assert b["chain"].sent == sent
    assert b["host"].config == config
    rerun = b["host"].commands[len(commands) :]
    assert not any(
        c.startswith(("tosctl config", "tosctl wallet activate")) or "enable-elections.sh" in c
        for c in rerun
    ), rerun


def test_the_main_command_never_opens_ssh_and_exits_waiting(external, monkeypatch, capsys):
    b = external
    monkeypatch.setattr(elections, "operations_for", lambda args, global_id: b["ops"])
    argv = [
        "onboard",
        "--name",
        "node-1",
        "--no-host",
        "--ceremony",
        str(b["ceremony"]),
        "--tos-root",
        str(b["tos"]),
        "--fift",
        "fift",
        "--rpc",
        "http://a",
        "--confirm-rpc",
        "http://b",
    ]
    assert elections.main(argv) == elections.WAITING_EXIT
    assert "waiting for the operator" in capsys.readouterr().err
    operator(b)
    assert elections.main(argv) == 0
    assert b["host"].commands and not any("ssh" in c for c in b["host"].commands)


@pytest.mark.parametrize(
    "extra,message",
    [
        (["--no-host", "--host", "h", "--ssh-key", "k"], "takes no --host"),
        (["--host", "h"], "needs --host and --ssh-key"),
        ([], "needs --host and --ssh-key"),
    ],
)
def test_onboard_needs_exactly_one_mode(external, monkeypatch, capsys, extra, message):
    b = external
    monkeypatch.setattr(elections, "operations_for", lambda args, global_id: b["ops"])
    argv = ["onboard", "--name", "node-1", "--ceremony", str(b["ceremony"])]
    argv += ["--tos-root", str(b["tos"]), "--fift", "fift", "--rpc", "http://a"]
    assert elections.main(argv + extra) == 1
    assert message in capsys.readouterr().err
    assert b["chain"].sent == [] and b["ops"].journal.all() == []


# ---------------------------------------------------------------- the coordinator reads the chain


def test_the_deployment_waits_for_the_owner_to_read_active(external, monkeypatch):
    b = external
    real = b["ops"].state

    def state(address):
        return "uninitialized" if address == b["owner"] else real(address)

    monkeypatch.setattr(b["ops"], "state", state)
    with pytest.raises(lib.TestnetError, match="is not active on both validators"):
        coordinator(b)
    # Refused before signing: no deployment and no principal was sent.
    assert b["ops"].journal.record("deploy-pool-node-1")["state"] == "planned"
    assert b["ops"].journal.record("principal-node-1") is None
    assert b["chain"].account(b["pool"])["state"] != "active"


def test_the_deployment_needs_the_owner_to_keep_the_principal(external, monkeypatch):
    b = external
    real = elections.owner_transfer

    def drain(*args, **kwargs):
        if args[5] == elections.OWNER_DEPLOY_KIND:
            b["chain"].account(b["owner"])["balance"] = E["pool_tos"] * NANO
        return real(*args, **kwargs)

    monkeypatch.setattr(elections, "owner_transfer", drain)
    with pytest.raises(lib.TestnetError, match="cannot pay"):
        coordinator(b)
    assert b["ops"].journal.record("deploy-pool-node-1")["state"] == "planned"
    assert b["chain"].account(b["pool"])["state"] != "active"


def test_without_the_principal_the_coordinator_does_not_reach_the_hand_off(external, monkeypatch):
    b = external
    monkeypatch.setattr(elections, "send_principal", lambda *args, **kwargs: None)
    with pytest.raises(lib.TestnetError, match="less than two stakes") as info:
        coordinator(b)
    assert not isinstance(info.value, elections.WaitingForOperator)
    # And the operator's script refuses too: the pool is deployed but not funded.
    with pytest.raises(lib.TestnetError, match="has not sent the principal yet"):
        operator(b)
    assert not any(c.startswith("tosctl") for c in b["host"].commands)


def test_an_operator_wallet_without_a_stake_order_is_not_done(external):
    b = external
    coordinator_until_hand_off(b)
    operator(b)
    b["chain"].account(b["host"].operator)["balance"] = NANO
    with pytest.raises(lib.TestnetError, match="less than a stake order") as info:
        coordinator(b)
    assert not isinstance(info.value, elections.WaitingForOperator)


@pytest.mark.parametrize("point", ["signed", "broadcast", "delivered"])
def test_an_interrupted_owner_deployment_is_never_sent_twice(external, monkeypatch, point):
    b = external
    crash(monkeypatch, "deploy-pool-node-1", point)
    with pytest.raises(KeyboardInterrupt):
        coordinator(b)
    monkeypatch.setattr(elections.ops, "crash_point", lambda i, p: None)
    b["chain"].settle_all()
    sent = list(b["chain"].sent)
    with pytest.raises(lib.TestnetError, match="open"):
        coordinator(b)
    assert b["chain"].sent == sent
    record = b["ops"].journal.record("deploy-pool-node-1")
    expect = elections.expect_for(b["args"], record)
    if point == "signed":
        b["ops"].resubmit("deploy-pool-node-1", expect=expect)
    else:
        evidence = b["ops"].settle(record, expect)[1]
        b["ops"].record_settled("deploy-pool-node-1", evidence["wallet_tx"], expect)
    coordinator_until_hand_off(b)
    assert settled_ids(b) == sorted(ALL_STEPS)
    assert len(b["chain"].sent) == len(set(b["chain"].sent)) == len(ALL_STEPS)


def test_a_team_host_onboarded_over_ssh_needs_nothing_more(boarding):  # noqa: F811
    b = boarding
    onboard(b)
    sent = list(b["chain"].sent)
    done = coordinator(b)
    assert done["operator_state"] == "active"
    assert b["ops"].journal.record("deploy-pool-node-1")["kind"] == "deploy-pool"
    assert b["chain"].sent == sent


# ---------------------------------------------------------------- the operator's host


def test_the_operator_script_waits_for_the_coordinator(external):
    b = external
    with pytest.raises(lib.TestnetError, match="has not deployed it yet"):
        operator(b)
    assert [c for c in b["host"].commands if "init-operator.sh" not in c] == []
    assert b["chain"].sent == []


def test_an_unfunded_operator_wallet_is_not_activated(external):
    b = external
    coordinator_until_hand_off(b)
    b["chain"].account(b["host"].operator)["balance"] = 0
    with pytest.raises(lib.TestnetError, match="has not sent its fee money yet"):
        operator(b)
    assert not any("wallet activate" in c for c in b["host"].commands)


def test_a_pool_of_another_operator_wallet_is_refused_on_the_host(external):
    b = external
    coordinator_until_hand_off(b)
    b["host"].operator = HOST_WALLET
    sent = list(b["chain"].sent)
    with pytest.raises(lib.TestnetError, match="validator role"):
        operator(b)
    assert b["host"].config == {"pools": {}, "bindings": {}}
    assert b["chain"].sent == sent


def test_a_pool_with_another_owner_is_refused_on_the_host(external):
    b = external
    coordinator_until_hand_off(b)
    with pytest.raises(lib.TestnetError, match="the pool's owner is"):
        operator(b, owner=HOST_WALLET)
    assert b["host"].config == {"pools": {}, "bindings": {}}


def test_elections_are_enabled_only_once_the_node_signs_for_the_pool(external):
    b = external
    coordinator_until_hand_off(b)
    b["host"].bound = "cd" * 32
    with pytest.raises(lib.TestnetError, match="signs stake authorizations for cdcd"):
        operator(b)
    assert not any("enable-elections" in c for c in b["host"].commands)
    b["host"].bound = b["pool"].split(":")[1]
    operator(b)
    assert sum("enable-elections.sh" in c for c in b["host"].commands) == 1


@pytest.mark.parametrize(
    "extra,message",
    [
        ({"name": "Node_1"}, "lower-case"),
        ({"pool": "0:" + "5c" * 32}, "not in the masterchain"),
        ({"pool": "not-an-address"}, "not a raw"),
    ],
)
def test_the_operator_script_checks_its_arguments(external, extra, message):
    b = external
    with pytest.raises(lib.TestnetError, match=message):
        operator(b, **extra)
    assert b["host"].commands == []


def test_the_operator_command_needs_root(monkeypatch, capsys):
    monkeypatch.setattr(operator_tool.os, "geteuid", lambda: 1000)
    argv = ["onboard", "--name", "node-1", "--pool", "-1:" + "5c" * 32, "--owner", HOST_WALLET]
    assert operator_tool.main(argv) == 1
    assert "as root" in capsys.readouterr().err


def test_the_operator_command_writes_its_summary_once(external, monkeypatch, tmp_path, capsys):
    b = external
    coordinator_until_hand_off(b)
    monkeypatch.setattr(operator_tool.os, "geteuid", lambda: 0)
    out = tmp_path / "onboard.json"
    reader = operator_tool.NodeReader("http://local", fakechain.NodeRpc(b["chain"], False, False))
    args = operator_args(b, out=out, profile=lib.PROFILE_PATH)
    operator_tool.cmd_onboard(args, host=b["host"], reader=reader)
    summary = json.loads(out.read_text())
    assert summary["pool"] == b["pool"] and summary["operator_wallet"] == b["host"].operator
    with pytest.raises(lib.TestnetError, match="never overwritten"):
        operator_tool.cmd_onboard(args, host=b["host"], reader=reader)


def test_local_host_runs_tosctl_as_its_own_user(monkeypatch):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return elections.subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")

    host = elections.vh.LocalHost(run)
    assert host.tosctl("wallet ls", 60) == "ok"
    [argv] = calls
    assert argv[:2] == ["bash", "-c"]
    assert argv[2].startswith("set -a; . /etc/tos/tosctl.env; set +a; cd /var/lib/tos-ctl; ")
    assert "timeout 60 runuser -u tos-ctl -- tosctl wallet ls 2>&1" in argv[2]


def test_local_host_reports_a_failed_command():
    def run(argv, **kwargs):
        return elections.subprocess.CompletedProcess(argv, 1, stdout="", stderr="boom")

    with pytest.raises(lib.TestnetError, match="boom"):
        elections.vh.LocalHost(run).run("false")


def test_the_operator_command_needs_the_owner(capsys):
    argv = ["onboard", "--name", "node-1", "--pool", "-1:" + "5c" * 32]
    with pytest.raises(SystemExit):
        operator_tool.main(argv)
    assert "--owner" in capsys.readouterr().err


def test_a_pool_with_other_code_is_refused_on_the_host(external, tmp_path):
    b = external
    coordinator_until_hand_off(b)
    other = tmp_path / "tos"
    (other / operator_tool.SINGLE_NOMINATOR_CODE).parent.mkdir(parents=True)
    (other / operator_tool.SINGLE_NOMINATOR_CODE).write_text(
        lib.serialize_boc(lib.cell_from_bits("1")).hex()
    )
    with pytest.raises(lib.TestnetError, match="not the pinned single-nominator code"):
        operator(b, tos_root=other)
    assert b["host"].config == {"pools": {}, "bindings": {}}
    with pytest.raises(lib.TestnetError, match="cannot read the pinned pool code"):
        operator(b, tos_root=tmp_path / "missing")


@pytest.mark.parametrize("already_running", [False, True])
def test_elections_must_be_active_at_the_end(external, monkeypatch, already_running):
    b = external
    coordinator_until_hand_off(b)
    host = b["host"]
    host.elections_on = already_running
    real = host.run

    def run(command, timeout=300):
        out = real(command, timeout)
        if command.startswith("systemctl is-active tos-testnet-elections.service"):
            # Active when first asked (already running), then found failed at the end;
            # or never active after enable-elections.sh.
            calls.append(command)
            if not already_running or len(calls) > 1:
                return "failed\n"
        return out

    calls = []
    monkeypatch.setattr(host, "run", run)
    if already_running:
        # Already active: nothing restarts it, and the summary reports it active.
        assert operator(b)["elections_unit"] == "active"
        assert not any("enable-elections.sh" in c for c in host.commands)
        return
    with pytest.raises(lib.TestnetError, match="is failed after enable-elections.sh"):
        operator(b)
    assert sum("enable-elections.sh" in c for c in host.commands) == 1


# ---------------------------------------------------------------- pool deployment settlement


def flaky_pool_reads(monkeypatch, b, failures):
    """verify_pool_both raises a read error (an HTTP 502) while `failures[0]` > 0 once
    the pool is active, as a validator's JSON-RPC behind a proxy does."""
    real = elections.verify_pool_both

    def verify(operations, tos_root, pool, owner, operator):
        if failures[0] > 0 and b["chain"].account(pool)["state"] == "active":
            failures[0] -= 1
            raise lib.TestnetError("http://a getAddressInformation: HTTP 502")
        return real(operations, tos_root, pool, owner, operator)

    monkeypatch.setattr(elections, "verify_pool_both", verify)


def test_a_read_error_after_delivery_is_pending_then_settles(external, monkeypatch):
    b = external
    failures = [3]
    flaky_pool_reads(monkeypatch, b, failures)
    coordinator_until_hand_off(b)
    record = b["ops"].journal.record("deploy-pool-node-1")
    assert record["state"] == "settled" and failures == [0]
    assert not any(r and r["state"] == "failed" for r in b["ops"].journal.all())


def test_a_read_error_that_outlasts_the_watch_stays_open_and_is_recorded_later(
    external, monkeypatch
):
    b = external
    failures = [10**6]
    flaky_pool_reads(monkeypatch, b, failures)
    with pytest.raises(lib.TestnetError, match="broadcast but not settled"):
        coordinator(b)
    record = b["ops"].journal.record("deploy-pool-node-1")
    assert record["state"] == "broadcast"
    with pytest.raises(lib.TestnetError, match="not settled: pending"):
        evidence = b["ops"].settle(record, elections.expect_for(b["args"], record))[1]
        b["ops"].record_settled(
            "deploy-pool-node-1", "00" * 32, elections.expect_for(b["args"], record)
        )
    failures[0] = 0
    expect = elections.expect_for(b["args"], record)
    evidence = b["ops"].settle(record, expect)[1]
    b["ops"].record_settled("deploy-pool-node-1", evidence["wallet_tx"], expect)
    coordinator_until_hand_off(b)
    assert settled_ids(b) == sorted(ALL_STEPS)


def test_a_definite_mismatch_after_delivery_still_fails(external, monkeypatch):
    b = external

    def wrong_roles(self, address):
        return HOST_WALLET, HOST_WALLET

    monkeypatch.setattr(elections.Chain, "pool_roles", wrong_roles)
    with pytest.raises(lib.TestnetError, match="failed"):
        coordinator(b)
    record = b["ops"].journal.record("deploy-pool-node-1")
    assert record["state"] == "failed" and record["evidence"]["form"] == "b"
    assert "reports roles" in record["evidence"]["reason"]


def test_the_outcome_separates_read_errors_from_mismatches(monkeypatch):
    evidence = {"wallet_tx": "ab"}
    for error, outcome in (
        (elections.ops.Unknown("the validators disagree"), "pending"),
        (lib.TestnetError("HTTP 502"), "pending"),
        (lib.TestnetError("-1:5c is uninitialized, not active"), "pending"),
        (elections.PoolMismatch("reports roles"), "failed"),
    ):

        def verify(*args, error=error):
            raise error

        monkeypatch.setattr(elections, "verify_pool_both", verify)
        assert elections.pool_deployment_outcome(None, None, "p", "o", "v", evidence)[0] == outcome
    monkeypatch.setattr(elections, "verify_pool_both", lambda *args: None)
    assert elections.pool_deployment_outcome(None, None, "p", "o", "v", evidence) == (
        "settled",
        evidence,
    )


def test_a_read_error_in_a_team_host_deployment_is_pending_too(boarding, monkeypatch):  # noqa: F811
    b = boarding
    failures = [3]
    flaky_pool_reads(monkeypatch, b, failures)
    onboard(b)
    assert b["ops"].journal.record("deploy-pool-node-1")["state"] == "settled"
    assert failures == [0]


# ---------------------------------------------------------------- replacing a team-host deployment


def ssh_deploy_record(b, *states):
    """An operator-wallet deploy-pool attempt in the journal, through `states`."""
    journal = b["ops"].journal
    params = {
        "kind": "deploy-pool",
        "wallet": b["host"].operator,
        "destination": b["pool"],
        "value": E["pool_deploy_tos"] * NANO,
        "bounce": False,
        "body_hash": elections.EMPTY_BODY_HASH,
        "state_init_hash": "00" * 32,
        "name": "node-1",
        "subwallet": 698983191,
        "owner": b["owner"],
    }
    journal.append("deploy-pool-node-1", dict(params, state="planned"))
    for state in states:
        extra = {"evidence": {"form": "a", "reason": "the wallet emitted two messages"}}
        journal.append(
            "deploy-pool-node-1", dict({"state": state}, **(extra if state == "failed" else {}))
        )


def test_a_failed_team_host_deployment_is_succeeded_by_the_owner(external):
    b = external
    ssh_deploy_record(b, "failed")
    coordinator_until_hand_off(b)
    journal = b["ops"].journal
    assert journal.newest("deploy-pool-node-1") == "deploy-pool-node-1.attempt-2"
    successor = journal.record("deploy-pool-node-1.attempt-2")
    assert successor["kind"] == elections.OWNER_DEPLOY_KIND and successor["state"] == "settled"
    assert successor["predecessor"] == "deploy-pool-node-1"
    assert "failed" in successor["reason"]
    assert journal.record("deploy-pool-node-1")["state"] == "failed"
    sent = list(b["chain"].sent)
    coordinator_until_hand_off(b)
    assert b["chain"].sent == sent
    assert journal.newest("deploy-pool-node-1") == "deploy-pool-node-1.attempt-2"


@pytest.mark.parametrize(
    "states,message",
    [
        ((), "never signed: finish it with `onboard --host --ssh-key`"),
        (("signed",), "`resubmit --id deploy-pool-node-1`"),
        (("signed", "broadcast"), "`testnet-elections.py reconcile`"),
    ],
)
def test_an_unfinished_team_host_deployment_still_refuses(external, states, message):
    b = external
    ssh_deploy_record(b, *states)
    with pytest.raises(lib.TestnetError, match=re.escape(message)):
        coordinator(b)
    assert b["ops"].journal.newest("deploy-pool-node-1") == "deploy-pool-node-1"
    assert b["chain"].account(b["pool"])["state"] != "active"


def test_a_successor_needs_a_failed_attempt_of_the_named_kind(external):
    b = external
    ops_ = b["ops"]
    with pytest.raises(lib.TestnetError, match="has no attempt"):
        ops_.successor_with(
            "deploy-pool-node-1", {"kind": "owner-deploy-pool"}, "r", ("deploy-pool",)
        )
    ssh_deploy_record(b, "signed")
    with pytest.raises(lib.TestnetError, match="only a failed"):
        ops_.successor_with(
            "deploy-pool-node-1", {"kind": "owner-deploy-pool"}, "r", ("deploy-pool",)
        )
    with pytest.raises(lib.TestnetError, match="needs a reason"):
        ops_.successor_with(
            "deploy-pool-node-1", {"kind": "owner-deploy-pool"}, " ", ("deploy-pool",)
        )
