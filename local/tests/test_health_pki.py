"""The health PKI rotation re-issues the set, moves the pins, proves monitoring
recovers, and survives an interruption at every live-file replacement."""

import hashlib
import importlib.util
import json
import shutil
import ssl
import subprocess
import sys
import time
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "health-pki.py"
SPEC = importlib.util.spec_from_file_location("health_pki", SCRIPT)
pki = importlib.util.module_from_spec(SPEC)
sys.modules["health_pki"] = pki  # dataclasses look their module up while it loads
SPEC.loader.exec_module(pki)

NODES = ["validator1", "validator2", "validator3", "validator4", "observer5", "observer6", "validator7"]


class Killed(BaseException):
    """Stands for the process being terminated at a fault point."""


def leaf_sha(pem: bytes) -> str:
    return hashlib.sha256(pki.first_cert_der(pem)).hexdigest()


def chains(identity: Path, ca: Path) -> bool:
    return subprocess.run(["openssl", "verify", "-CAfile", str(ca), str(identity)], capture_output=True).returncode == 0


class FakeStack:
    """An ingress that enforces the CA, the configured pins and the routes."""

    def __init__(self, state: Path) -> None:
        self.state = state
        self.restarts: list[list[str]] = []
        self.unit_files = units_for(state)
        self.healthy = [True]  # observations; the last value repeats
        self.enforce_pins = True
        self.serve_live_server = True
        self.still_accepted: dict[str, str] = {}  # leaf pin -> role, accepted whatever the CA
        self.sequence_frozen = False
        self.rate_limited = 0  # answer 429 to this many requests first; -1 for ever
        self.broken_negative: str | None = None  # result for replaced/unpinned requests
        self.drop_with_other_server = False
        self.restart_error: BaseException | None = None
        self.observe_error: BaseException | None = None
        self.fault_at: str | None = None
        self.clock = time.time()
        self.sequence = 0

    def units(self):
        return list(self.unit_files)

    def restart(self, units):
        self.restarts.append(list(units))
        if self.restart_error is not None:
            raise self.restart_error

    def active(self, unit):
        return True

    def request(self, listener, ca, identity, method, path, headers=None, hostname="localhost"):
        live = self.state / "pki"
        if self.broken_negative and identity is not None and {"other", "control"} & set(Path(identity).parts):
            return self.broken_negative, None, b""
        if self.rate_limited:
            self.rate_limited -= 1 if self.rate_limited > 0 else 0
            return 429, leaf_sha((live / "server.pem").read_bytes()), b""
        if Path(ca).read_bytes() != (live / "ca.pem").read_bytes():
            return pki.TRANSPORT, None, b""  # the client cannot verify the served chain
        served = leaf_sha((live / "server.pem").read_bytes()) if self.serve_live_server else "0" * 64
        config = json.loads((self.state / "config" / listener.config).read_text())
        pin = leaf_sha(Path(identity).read_bytes()) if identity is not None else ""
        configured = {p["certificate_sha256"] for p in config["peers"]}
        if pin in self.still_accepted and pin not in configured:
            want_method, want_path, want = pki.OPERATIONS[self.still_accepted[pin]]
            return (want if (method, path) == (want_method, want_path) else 403), served, b""
        if identity is None or not chains(Path(identity), live / "ca.pem"):
            return pki.REJECTED, None, b""  # the credential alert a real ingress sends
        roles = [p["role"] for p in config["peers"] if p["certificate_sha256"] == pin]
        if not roles and self.enforce_pins:
            # The real ingress closes an unpinned connection right after the handshake.
            return pki.DROPPED, (served if not self.drop_with_other_server else "f" * 64), b""
        role = roles[0] if roles else config["peers"][0]["role"]
        if listener.config == "manager-ingress.json" and path == "/v1/manager/state":
            self.sequence += 0 if self.sequence_frozen else 1
            return 200, served, json.dumps({"evaluation_sequence": str(self.sequence)}).encode()
        want_method, want_path, want = pki.OPERATIONS[role]
        if (method, path) == (want_method, want_path):
            return want, served, b""
        return 403, served, b""

    def observe(self):
        if self.observe_error is not None:
            raise self.observe_error
        good = self.healthy.pop(0) if len(self.healthy) > 1 else self.healthy[0]
        status = "partial" if good else "error"
        cache = {"status": "error", "error": {"code": "CACHE_MISS"}}
        return [
            {"node": node, "results": {**{s: {"status": status} for s in pki.CORE_SCOPES}, "host": cache, "telemetry": cache}}
            for node in NODES
        ]

    def sleep(self, seconds):
        self.clock += seconds

    def now(self):
        return self.clock

    def fault(self, point):
        if point == self.fault_at:
            raise self.fault_error if self.fault_error is not None else Killed(point)

    fault_error: BaseException | None = None


def units_for(state: Path) -> list[str]:
    names =[f"tos-local-health-edge-ingress-{i}.service" for i in range(1, 8)] + ["tos-local-health-manager-ingress.service"]
    names += [f"tos-local-health-collector-{n[-1]}.service" for n in NODES]
    names += [f"tos-local-health-probe-{i}.service" for i in range(1, 8)]
    names += [f"tos-local-health-native-poll-{i}.service" for i in range(1, 8)]
    names += ["tos-local-health-manager.service", "tos-local-health-query.service", *pki.PKI_UNITS]
    return names


def make_state(root: Path, days: int = 30) -> Path:
    """A state directory as the live stack has it, with a PKI issued `days` long."""
    state = root / "state"
    (state / "config").mkdir(parents=True)
    (state / "pki").mkdir(mode=0o700)
    issued = root / "issued"
    issued.mkdir()
    live = pki.issue(issued, days)
    for name, data in live.items():
        (state / "pki" / name).write_bytes(data)
        (state / "pki" / name).chmod(0o600)
    pins = {alias: leaf_sha(live[name]) for alias, name in pki.IDENTITIES.items()}
    for index in range(1, 8):
        write_ingress(state, f"edge-ingress-{index}.json", 19580 + index, pins, ("edge_watchdog", "edge_reader"))
    write_ingress(state, "manager-ingress.json", 19590, pins, ("manager_ingest", "manager_reader"))
    for node in NODES:
        (state / "config" / f"collector-{node}.json").write_text(json.dumps({"node_id": node}))
    for index in range(1, 8):
        (state / "config" / f"probe-{index}.json").write_text("{}")
        (state / "config" / f"native-poll-{index}.json").write_text("{}")
    (state / "config" / "manager.json").write_text("{}")
    (state / "config" / "query-inventory.json").write_text("{}")
    (state / "config" / "manager-read.token").write_text("token\n")
    return state


def write_ingress(state, name, port, pins, roles):
    config = {
        "listen": f"127.0.0.1:{port}",
        "server_name": "localhost",
        "peers": [
            {"alias": "local_probe", "certificate_sha256": pins["local_probe"], "role": roles[0]},
            {"alias": "local_reader", "certificate_sha256": pins["local_reader"], "role": roles[1]},
        ],
    }
    (state / "config" / name).write_text(json.dumps(config, indent=2) + "\n")


def snapshot(state: Path) -> dict[str, bytes]:
    paths = [state / "pki" / n for n in pki.PKI_FILES] + [state / "config" / n for n in pki.INGRESS_CONFIGS]
    return {str(p): p.read_bytes() for p in paths}


@pytest.fixture
def state(tmp_path):
    return make_state(tmp_path)


def run_rotate(state, stack, *extra):
    return pki.main(["rotate", "--state-dir", str(state), *extra], stack_factory=lambda _: stack)


def assert_consistent_new(state: Path, before: dict[str, bytes]) -> None:
    """Every live file changed, the leaves chain to the live CA and the pins name them."""
    after = snapshot(state)
    assert all(after[path] != before[path] for path in before)
    live = state / "pki"
    for name in ("server.pem", *pki.IDENTITIES.values()):
        assert chains(live / name, live / "ca.pem")
    for name in pki.INGRESS_CONFIGS:
        peers = json.loads((state / "config" / name).read_text())["peers"]
        assert {p["certificate_sha256"] for p in peers} == {
            leaf_sha((live / f).read_bytes()) for f in pki.IDENTITIES.values()
        }


def test_check_reports_due_and_missing(state, capsys):
    stack = FakeStack(state)
    assert pki.main(["check", "--state-dir", str(state), "--within-days", "7"], stack_factory=lambda _: stack) == 0
    assert pki.main(["check", "--state-dir", str(state), "--within-days", "40"], stack_factory=lambda _: stack) == 1
    (state / "pki" / "server.pem").unlink()
    assert pki.main(["check", "--state-dir", str(state)], stack_factory=lambda _: stack) == 2


def test_not_due_changes_nothing(state):
    before = snapshot(state)
    stack = FakeStack(state)
    assert run_rotate(state, stack, "--if-due-within-days", "7") == 0
    assert snapshot(state) == before and stack.restarts == []


def test_due_rotation_moves_everything_and_verifies(state):
    before = snapshot(state)
    stack = FakeStack(state)
    assert run_rotate(state, stack, "--if-due-within-days", "40") == 0
    assert_consistent_new(state, before)
    assert not (state / pki.JOURNAL).exists()
    assert [len(call) for call in stack.restarts] == [8, 23]
    assert all("ingress" in unit for unit in stack.restarts[0])
    assert not any(unit in pki.PKI_UNITS for call in stack.restarts for unit in call)
    retired = list((state / "retired").iterdir())
    assert len(retired) == 1 and (retired[0] / "ca.pem").read_bytes() == before[str(state / "pki" / "ca.pem")]
    assert not list(state.glob("pki-staging-*")), "the new CA key must not outlive the rotation"


def test_only_the_newest_two_backups_are_kept(state):
    stack = FakeStack(state)
    for _ in range(3):
        stack.clock += 2
        assert run_rotate(state, stack) == 0
    assert len(list((state / "retired").iterdir())) == 2


@pytest.mark.parametrize(
    "break_config",
    [
        lambda c: c["peers"][0].__setitem__("certificate_sha256", "ab" * 32),  # unknown pin
        lambda c: c["peers"].pop(),  # the reader is not pinned
    ],
    ids=["unknown-pin", "missing-peer"],
)
def test_unexpected_pins_refuse_and_change_nothing(state, break_config):
    path = state / "config" / "edge-ingress-3.json"
    config = json.loads(path.read_text())
    break_config(config)
    path.write_text(json.dumps(config))
    before = snapshot(state)
    assert run_rotate(state, FakeStack(state)) == 2
    assert snapshot(state) == before
    assert not (state / pki.JOURNAL).exists()


def test_a_unit_outside_the_configured_stack_refuses(state):
    stack = FakeStack(state)
    stack.unit_files.append("tos-local-health-collector-8.service")
    before = snapshot(state)
    assert run_rotate(state, stack) == 2
    assert snapshot(state) == before


def test_failed_verification_restores_and_verifies_the_old_pki(state):
    before = snapshot(state)
    stack = FakeStack(state)
    stack.healthy = [False] * 20 + [True]  # unhealthy through the new PKI's window, then well
    assert run_rotate(state, stack) == 1
    assert snapshot(state) == before
    assert json.loads((state / pki.JOURNAL).read_text())["phase"] == "rolled_back"
    # The next run clears the journal and, when due, tries again.
    assert run_rotate(state, stack, "--if-due-within-days", "1") == 0
    assert not (state / pki.JOURNAL).exists()


def test_an_ingress_ignoring_pins_fails_the_rotation(state):
    stack = FakeStack(state)
    stack.enforce_pins = False
    before = snapshot(state)
    # The unpinned control from the new CA is accepted, so the new PKI fails; the
    # restored stack does not trust the new CA at all, so the old one verifies.
    assert run_rotate(state, stack) == 1
    assert snapshot(state) == before


def test_an_ingress_still_accepting_the_replaced_identities_fails(state):
    stack = FakeStack(state)
    for name, role in (("probe-identity.pem", "edge_watchdog"), ("reader-identity.pem", "edge_reader")):
        stack.still_accepted[leaf_sha((state / "pki" / name).read_bytes())] = role
    before = snapshot(state)
    assert run_rotate(state, stack) == 1  # the restored stack accepts them, as it should
    assert snapshot(state) == before


def test_a_rate_limited_ingress_is_waited_out(state):
    before = snapshot(state)
    stack = FakeStack(state)
    stack.rate_limited = 10  # a burst of 429 answers, as the real ingresses give
    assert run_rotate(state, stack) == 0
    assert_consistent_new(state, before)


def test_an_ingress_that_never_stops_rate_limiting_fails(state):
    stack = FakeStack(state)
    stack.rate_limited = -1
    assert run_rotate(state, stack) == 3
    assert "429" in json.loads((state / pki.JOURNAL).read_text())["reason"]


def test_a_manager_that_stops_evaluating_fails(state):
    stack = FakeStack(state)
    stack.sequence_frozen = True
    assert run_rotate(state, stack) == 3  # it does not recover under the old PKI either
    assert "evaluation sequence" in json.loads((state / pki.JOURNAL).read_text())["reason"]


def test_a_listener_serving_another_certificate_fails(state):
    stack = FakeStack(state)
    stack.serve_live_server = False
    assert run_rotate(state, stack) == 3  # the restored stack serves the wrong certificate too
    assert json.loads((state / pki.JOURNAL).read_text())["phase"] == "recovery_failed"


def test_failed_recovery_is_reported_until_resolved(state):
    stack = FakeStack(state)
    stack.healthy = [False]
    assert run_rotate(state, stack) == 3
    journal = json.loads((state / pki.JOURNAL).read_text())
    assert journal["phase"] == "recovery_failed"
    assert Path(journal["staging"]).exists() and Path(journal["backup"]).exists()
    assert run_rotate(state, stack, "--if-due-within-days", "7") == 3
    stack.healthy = [True]
    assert run_rotate(state, stack, "--resolve", "keep-new") == 0
    assert not (state / pki.JOURNAL).exists()


def test_an_expired_old_pki_is_not_restored(tmp_path):
    state = make_state(tmp_path, days=1)
    before = snapshot(state)
    stack = FakeStack(state)
    stack.clock += 3 * 86400  # the one-day PKI has expired
    stack.healthy = [False]
    assert run_rotate(state, stack) == 3
    assert json.loads((state / pki.JOURNAL).read_text())["phase"] == "recovery_failed"
    assert snapshot(state) != before, "the new PKI stays installed when the old one is expired"


@pytest.mark.parametrize("index", range(13))
def test_interrupted_installation_is_completed(state, index):
    before = snapshot(state)
    stack = FakeStack(state)
    stack.fault_at = f"installing:{index}"
    with pytest.raises(Killed):
        run_rotate(state, stack)
    stack.fault_at = None
    assert run_rotate(state, stack) == 0
    assert_consistent_new(state, before)


@pytest.mark.parametrize("index", range(13))
def test_interrupted_rollback_is_completed(state, index):
    before = snapshot(state)
    stack = FakeStack(state)
    stack.healthy = [False] * 20 + [True]
    stack.fault_at = f"rolling_back:{index}"
    with pytest.raises(Killed):
        run_rotate(state, stack)
    stack.fault_at = None
    assert run_rotate(state, stack) == 1
    assert snapshot(state) == before


@pytest.mark.parametrize("index", [0, 6, 12])
def test_interrupted_resolve_is_completed(state, index):
    before = snapshot(state)
    stack = FakeStack(state)
    stack.healthy = [False]
    assert run_rotate(state, stack) == 3
    stack.healthy = [True]
    # recovery_failed after a rollback left the old files; keep-new installs again.
    stack.fault_at = f"installing:{index}"
    with pytest.raises(Killed):
        run_rotate(state, stack, "--resolve", "keep-new")
    stack.fault_at = None
    assert run_rotate(state, stack) == 0
    assert_consistent_new(state, before)


def test_a_foreign_or_missing_live_file_refuses(state):
    stack = FakeStack(state)
    stack.fault_at = "installing:3"
    with pytest.raises(Killed):
        run_rotate(state, stack)
    stack.fault_at = None
    victim = state / "config" / "edge-ingress-1.json"
    original = victim.read_bytes()
    victim.write_text("{}")
    assert run_rotate(state, stack) == 2
    assert victim.read_text() == "{}"
    victim.unlink()
    assert run_rotate(state, stack) == 2
    victim.write_bytes(original)
    assert run_rotate(state, stack) == 0


def test_a_second_rotation_is_refused_while_one_runs(state):
    import fcntl

    with open(state / "pki.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert run_rotate(state, FakeStack(state)) == 2


def test_the_unit_files_use_no_personal_paths():
    units = Path(__file__).resolve().parents[1] / "systemd" / "user"
    texts = [path.read_text() for path in units.glob("tos-local-health-pki.*")]
    assert len(texts) == 2
    assert all("/home/" not in text and "%h/" in "".join(texts) for text in texts)


# --- failures after the transaction began -------------------------------------


def journal_of(state):
    return json.loads((state / pki.JOURNAL).read_text())


def test_refusals_before_staging_leave_no_secret_behind(state):
    path = state / "config" / "edge-ingress-2.json"
    config = json.loads(path.read_text())
    config["peers"][1]["certificate_sha256"] = "cd" * 32
    path.write_text(json.dumps(config))
    assert run_rotate(state, FakeStack(state)) == 2
    assert not list(state.glob("pki-staging-*"))
    assert not (state / "retired").exists() or not list((state / "retired").iterdir())


def test_a_failure_while_staging_removes_the_staging(state, monkeypatch):
    real_issue = pki.issue

    def issue_then_fail(directory, days):
        real_issue(directory, days)  # the new CA key now exists in the staging
        raise pki.Refusal("injected failure after issuing")

    monkeypatch.setattr(pki, "issue", issue_then_fail)
    before = snapshot(state)
    assert run_rotate(state, FakeStack(state)) == 2
    assert snapshot(state) == before
    assert not list(state.glob("pki-staging-*"))
    assert not (state / "retired").exists() or not list((state / "retired").iterdir())
    assert not (state / pki.JOURNAL).exists()


@pytest.mark.parametrize("index", [0, 6, 12])
@pytest.mark.parametrize("damage", ["deleted", "corrupted"])
def test_lost_staging_after_partial_install_restores_and_reports(state, index, damage):
    before = snapshot(state)
    stack = FakeStack(state)
    stack.fault_at = f"installing:{index}"
    with pytest.raises(Killed):
        run_rotate(state, stack)
    stack.fault_at = None
    staging = Path(journal_of(state)["staging"])
    if damage == "deleted":
        shutil.rmtree(staging)
    else:
        next(staging.glob("live-*.json")).write_text("tampered")
    assert run_rotate(state, stack) == 3
    assert snapshot(state) == before, "the old PKI is restored from the backup"
    journal = journal_of(state)
    assert journal["phase"] == "recovery_failed" and "staging lost" in journal["reason"]


def test_an_unusable_backup_touches_nothing(state):
    stack = FakeStack(state)
    stack.fault_at = "installing:5"
    with pytest.raises(Killed):
        run_rotate(state, stack)
    stack.fault_at = None
    shutil.rmtree(journal_of(state)["backup"])
    stack.healthy = [False]  # the completed installation fails, so a rollback is needed
    assert run_rotate(state, stack) == 3
    journal = journal_of(state)
    assert journal["phase"] == "recovery_failed" and "backup is unusable" in journal["reason"]
    middle = snapshot(state)
    assert run_rotate(state, stack) == 3
    assert snapshot(state) == middle


def test_a_write_error_during_install_is_a_failed_recovery(state):
    stack = FakeStack(state)
    stack.fault_at = "installing:4"
    stack.fault_error = OSError(28, "No space left on device")
    assert run_rotate(state, stack) == 3
    journal = journal_of(state)
    assert journal["phase"] == "recovery_failed" and "No space left" in journal["reason"]
    assert Path(journal["staging"]).exists() and Path(journal["backup"]).exists()


@pytest.mark.parametrize(
    "error", [pki.Unhealthy("restart failed"), OSError(5, "I/O error")], ids=["unhealthy", "oserror"]
)
def test_a_failing_restart_is_reported(state, error):
    stack = FakeStack(state)
    stack.restart_error = error
    assert run_rotate(state, stack) == 3
    assert journal_of(state)["phase"] == "recovery_failed"


def test_an_error_inside_verification_is_reported(state):
    stack = FakeStack(state)
    stack.observe_error = OSError(13, "Permission denied")
    assert run_rotate(state, stack) == 3
    assert "Permission denied" in journal_of(state)["reason"]


# --- what counts as a refusal --------------------------------------------------


def ssl_error(reason, kind=ssl.SSLError):
    error = kind(1, reason)
    error.reason = reason
    return error


def test_only_credential_alerts_count_as_rejection():
    assert pki.classify_tls_error(ssl_error("TLSV1_ALERT_DECRYPT_ERROR")) == pki.REJECTED
    assert pki.classify_tls_error(ssl_error("TLSV13_ALERT_CERTIFICATE_REQUIRED")) == pki.REJECTED
    assert pki.classify_tls_error(ssl_error("SSLV3_ALERT_HANDSHAKE_FAILURE")) == pki.TRANSPORT
    assert pki.classify_tls_error(ssl_error("WRONG_VERSION_NUMBER")) == pki.TRANSPORT
    verification = ssl_error("CERTIFICATE_VERIFY_FAILED", ssl.SSLCertVerificationError)
    assert pki.classify_tls_error(verification) == pki.TRANSPORT


@pytest.mark.parametrize(
    "result",
    [pki.TRANSPORT, pki.classify_tls_error(ssl_error("SSLV3_ALERT_HANDSHAKE_FAILURE"))],
    ids=["transport", "handshake-failure"],
)
def test_a_transport_failure_in_the_negative_checks_proves_nothing(state, result):
    stack = FakeStack(state)
    stack.broken_negative = result
    assert run_rotate(state, stack) == 3  # the restored stack's negative checks fail the same way
    assert "transport" in journal_of(state)["reason"]


def test_a_drop_counts_only_with_the_expected_server_certificate(state):
    stack = FakeStack(state)
    stack.drop_with_other_server = True
    before = snapshot(state)
    # The new PKI fails on the unpinned check; the restored stack does not trust the
    # new CA, so its refusal is a credential alert and the old PKI verifies.
    assert run_rotate(state, stack) == 1
    assert snapshot(state) == before
    assert "transport" in journal_of(state)["reason"]


def tls_server(tmp_path, behaviour):
    """A local TLS listener using a test PKI.

    'drop-reset': handshake, then a reset with the request unread (what the
    ingress does to an unpinned certificate); 'drop-clean': handshake, read the
    request, close cleanly; 'partial': handshake, send half a status line, reset;
    'reset': reset before any handshake.
    """
    import socket
    import struct
    import threading

    def hard_close(sock):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        sock.close()

    issued = tmp_path / "server-pki"
    issued.mkdir()
    live = pki.issue(issued, 2)
    for name, data in live.items():
        (issued / name).write_bytes(data)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(issued / "server.pem"), str(issued / "server.key"))
    context.load_verify_locations(str(issued / "ca.pem"))
    context.verify_mode = ssl.CERT_REQUIRED

    def serve():
        for _ in range(2):
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            if behaviour == "reset":
                hard_close(conn)
                continue
            try:
                tls = context.wrap_socket(conn, server_side=True)
                if behaviour == "drop-reset":
                    tls.recv(1)  # the request arrives and is left unread
                    hard_close(tls)
                elif behaviour == "drop-clean":
                    tls.recv(65536)
                    tls.close()
                elif behaviour == "answer":
                    tls.recv(65536)
                    body = b'{"evaluation_sequence": "7"}' + b" " * 40000  # larger than one read
                    head = f"HTTP/1.1 200 OK\r\ncontent-length: {len(body)}\r\nconnection: close\r\n\r\n"
                    tls.sendall(head.encode() + body)
                    tls.close()
                elif behaviour == "partial":
                    tls.recv(65536)
                    tls.sendall(b"HTTP/1.1 2")
                    time.sleep(0.2)
                    hard_close(tls)
            except (ssl.SSLError, OSError):
                conn.close()

    threading.Thread(target=serve, daemon=True).start()
    port = listener.getsockname()[1]
    return issued, pki.Listener("x.json", "127.0.0.1", port, "localhost", ()), listener


@pytest.mark.parametrize(
    "behaviour, expected",
    [("drop-reset", "dropped"), ("drop-clean", "dropped"), ("partial", "transport"), ("reset", "transport")],
)
def test_request_classifies_a_real_drop_and_a_real_reset(tmp_path, behaviour, expected):
    issued, listener, server = tls_server(tmp_path, behaviour)
    try:
        status, served, _ = pki.Stack(tmp_path).request(
            listener, issued / "ca.pem", issued / "probe-identity.pem", "GET", "/"
        )
    finally:
        server.close()
    assert status == expected
    if expected == "dropped":
        assert served == leaf_sha((issued / "server.pem").read_bytes())


def test_request_reads_a_whole_response_after_the_server_closes(tmp_path):
    issued, listener, server = tls_server(tmp_path, "answer")
    try:
        status, served, body = pki.Stack(tmp_path).request(
            listener, issued / "ca.pem", issued / "reader-identity.pem", "GET", "/v1/manager/state"
        )
    finally:
        server.close()
    assert status == 200 and served == leaf_sha((issued / "server.pem").read_bytes())
    assert json.loads(body)["evaluation_sequence"] == "7" and len(body) > 40000


def test_request_reports_nothing_listening_as_transport(tmp_path):
    issued = tmp_path / "pki"
    issued.mkdir()
    for name, data in pki.issue(issued, 2).items():
        (issued / name).write_bytes(data)
    nothing = pki.Listener("x.json", "127.0.0.1", 9, "localhost", ())
    status, _, _ = pki.Stack(tmp_path).request(nothing, issued / "ca.pem", issued / "probe-identity.pem", "GET", "/")
    assert status == "transport"


# --- health criteria and validity ----------------------------------------------


def rows(core=None, host=None):
    cache = {"status": "error", "error": {"code": "CACHE_MISS"}, "data": None}
    return [
        {
            "node": node,
            "results": {
                **{s: dict(core or {"status": "partial", "error": None}) for s in pki.CORE_SCOPES},
                "host": dict(host or cache),
                "telemetry": dict(cache),
            },
        }
        for node in NODES
    ]


def test_health_accepts_only_error_free_results_and_the_exact_cache_miss():
    nodes = set(NODES)
    assert pki.healthy(rows(), nodes) is None
    assert pki.healthy(rows(core={"status": "partial", "error": {"code": "STALE"}}), nodes)
    assert pki.healthy(rows(host={"status": "partial", "error": {"code": "CACHE_MISS"}}), nodes)
    assert pki.healthy(rows(host={"status": "unknown", "error": {"code": "CACHE_MISS"}, "data": None}), nodes)
    assert pki.healthy(rows(host={"status": "error", "error": {"code": "CACHE_MISS"}, "data": {"x": 1}}), nodes)
    assert pki.healthy(rows()[:-1], nodes)


def test_a_not_yet_valid_pki_is_due(state):
    stack = FakeStack(state)
    stack.clock -= 2 * 86400  # before the certificates' notBefore
    check = ["check", "--state-dir", str(state), "--within-days", "1"]
    assert pki.main(check, stack_factory=lambda _: stack) == 1
    before = snapshot(state)
    assert run_rotate(state, stack, "--if-due-within-days", "1") == 0
    assert_consistent_new(state, before)
