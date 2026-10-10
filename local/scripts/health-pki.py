#!/usr/bin/env python3
"""Check and rotate the local health-monitoring development PKI.

The local health stack authenticates every hop with a private development CA:
one server certificate for the eight TLS ingress listeners and two client
identities (probe, reader) that the ingress configs pin by the SHA-256 of their
DER encoding. The CA key is not kept, so a rotation issues a new CA, server
certificate and both identities, moves the pins, restarts the stack and proves
that monitoring works again. Verification is never disabled to rotate.

    health-pki.py check  [--state-dir D] [--within-days N]
    health-pki.py rotate [--state-dir D] [--if-due-within-days N] [--days 30]
    health-pki.py rotate --resolve keep-new|restore-old

A rotation is a journaled transaction (pki-rotation.json in the state
directory) under an exclusive lock. Every live file is replaced in place,
atomically, so at any instant it equals either the recorded old or the recorded
new content; an interrupted run is finished or undone by the next one. A failed
verification restores the old PKI when it is still valid and verifies that too.

Exit status: 0 done (or nothing due), 1 rotation failed and the old PKI was
restored and verified, 2 refused (nothing changed), 3 recovery failed:
monitoring remains unhealthy and needs `--resolve`.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import http.client
import io
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

EXIT_OK, EXIT_ROLLED_BACK, EXIT_REFUSED, EXIT_RECOVERY_FAILED = 0, 1, 2, 3
HEALTH_ROOT = Path.home() / ".local/state/tos-local-health"
PKI_FILES = ("ca.pem", "server.pem", "server.key", "probe-identity.pem", "reader-identity.pem")
CERTS = ("ca.pem", "server.pem", "probe-identity.pem", "reader-identity.pem")
IDENTITIES = {"local_probe": "probe-identity.pem", "local_reader": "reader-identity.pem"}
SUBJECTS = {
    "ca": "NHM local development CA",
    "server": "NHM local server",
    "probe": "NHM local probe",
    "reader": "NHM local reader",
}
# What each pinned client may do, and the status that proves TLS, the pin and the
# route all passed: the GETs need a bearer token the check does not send (401),
# the POST gets an empty body (400).
OPERATIONS = {
    "edge_watchdog": ("GET", "/v1/edge/heartbeat", 401),
    "edge_reader": ("GET", "/v1/edge/heartbeat", 401),
    "manager_reader": ("GET", "/v1/monitor/heartbeat", 401),
    "manager_ingest": ("POST", "/v1/manager/facts", 400),
}
INGRESS_CONFIGS = tuple(f"edge-ingress-{i}.json" for i in range(1, 8)) + ("manager-ingress.json",)
CORE_SCOPES = ("process", "consensus", "storage", "chain")
CACHE_ONLY_SCOPES = ("host", "telemetry")
PKI_UNITS = ("tos-local-health-pki.service", "tos-local-health-pki.timer")
JOURNAL = "pki-rotation.json"
KEEP_RETIRED = 2
REJECTED, TRANSPORT, DROPPED = "rejected", "transport", "dropped"
# TLS alerts in which a server refuses the client's certificate (RFC 8446 6.2);
# DECRYPT_ERROR is what the ingress sends for a certificate from another CA.
CREDENTIAL_ALERTS = (
    "ALERT_BAD_CERTIFICATE",
    "ALERT_UNKNOWN_CA",
    "ALERT_CERTIFICATE_UNKNOWN",
    "ALERT_CERTIFICATE_REQUIRED",
    "ALERT_DECRYPT_ERROR",
    "ALERT_ACCESS_DENIED",
    "ALERT_UNSUPPORTED_CERTIFICATE",
)
RATE_LIMIT_RETRIES = 20
RATE_LIMIT_PAUSE = 3.0


class Refusal(Exception):
    """Nothing was changed; exit 2."""


class Unhealthy(Exception):
    """A verification step failed."""


def log(message: str) -> None:
    print(f"health-pki: {message}", flush=True)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(command: list[str], timeout: float = 120, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(command, input=input_bytes, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise Unhealthy(f"{command[0]} timed out after {timeout:g} s") from None
    except OSError as error:
        raise Refusal(f"cannot run {command[0]}: {error}") from None


def durable_write(path: Path, data: bytes, mode: int) -> None:
    """Replace path atomically: a complete temp file, fsync'd, renamed, directory fsync'd."""
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fchmod(handle.fileno(), mode)
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


# --- certificates -------------------------------------------------------------


def first_cert_der(pem: bytes) -> bytes:
    match = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)
    if not match:
        raise Refusal("no certificate in PEM data")
    return ssl.PEM_cert_to_DER_cert(match.group(0).decode())


def validity(path: Path) -> tuple[float, float]:
    """(notBefore, notAfter) as epoch seconds."""
    result = run(["openssl", "x509", "-noout", "-startdate", "-enddate", "-in", str(path)], timeout=30)
    if result.returncode != 0:
        raise Refusal(f"cannot read {path}: {result.stderr.decode(errors='replace').strip()}")
    fields = dict(line.split("=", 1) for line in result.stdout.decode().splitlines() if "=" in line)
    try:
        return ssl.cert_time_to_seconds(fields["notBefore"]), ssl.cert_time_to_seconds(fields["notAfter"])
    except (KeyError, ValueError):
        raise Refusal(f"cannot parse the validity of {path}") from None


def all_valid_now(pki: dict[str, bytes], now: float) -> bool:
    with tempfile.TemporaryDirectory() as scratch:
        for name in CERTS:
            path = Path(scratch) / name
            path.write_bytes(pki[name])
            start, end = validity(path)
            if not start <= now < end:
                return False
    return True


def openssl(args: list[str], what: str) -> None:
    result = run(["openssl", *args], timeout=60)
    if result.returncode != 0:
        raise Refusal(f"openssl failed to {what}: {result.stderr.decode(errors='replace').strip()[:300]}")


def issue_leaf(directory: Path, name: str, subject: str, usage: str, days: int, ca_key: Path) -> tuple[Path, Path]:
    key, csr, cert, ext = (directory / f"{name}{s}" for s in (".key", ".csr", ".pem", ".ext"))
    lines = ["basicConstraints=CA:FALSE", "keyUsage=digitalSignature,keyEncipherment", f"extendedKeyUsage={usage}"]
    if usage == "serverAuth":
        lines.append("subjectAltName=DNS:localhost,IP:127.0.0.1")
    ext.write_text("\n".join(lines) + "\n")
    openssl(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={subject}"], f"create the {name} key")
    serial = "0x" + os.urandom(16).hex()
    openssl(
        ["x509", "-req", "-in", str(csr), "-CA", str(directory / "ca.pem"), "-CAkey", str(ca_key), "-set_serial", serial,
         "-days", str(days), "-sha256", "-extfile", str(ext), "-out", str(cert)],
        f"sign the {name} certificate",
    )
    csr.unlink()
    ext.unlink()
    return cert, key


def issue(directory: Path, days: int) -> dict[str, bytes]:
    """A complete new PKI in directory (which keeps ca.key for the controls), as live file contents."""
    ca_key = directory / "ca.key"
    openssl(
        ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key), "-out", str(directory / "ca.pem"),
         "-days", str(days), "-sha256", "-subj", f"/CN={SUBJECTS['ca']}",
         "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
        "create the CA",
    )
    server, server_key = issue_leaf(directory, "server", SUBJECTS["server"], "serverAuth", days, ca_key)
    pki = {"ca.pem": (directory / "ca.pem").read_bytes(), "server.pem": server.read_bytes(), "server.key": server_key.read_bytes()}
    for name in ("probe", "reader"):
        cert, key = issue_leaf(directory, name, SUBJECTS[name], "clientAuth", days, ca_key)
        pki[f"{name}-identity.pem"] = cert.read_bytes() + key.read_bytes()
        cert.unlink()
        key.unlink()
    for path in (directory / "ca.pem", server, server_key):
        if path != directory / "ca.pem":
            path.unlink()
    check_chain(directory, pki)
    return pki


def check_chain(directory: Path, pki: dict[str, bytes]) -> None:
    """Every leaf chains to the CA with the purpose it is used for."""
    for name, purpose in (("server.pem", "sslserver"), ("probe-identity.pem", "sslclient"), ("reader-identity.pem", "sslclient")):
        leaf = directory / f"check-{name}"
        leaf.write_bytes(pki[name])
        ca = directory / "check-ca.pem"
        ca.write_bytes(pki["ca.pem"])
        result = run(["openssl", "verify", "-CAfile", str(ca), "-purpose", purpose, str(leaf)], timeout=30)
        leaf.unlink()
        ca.unlink()
        if result.returncode != 0:
            raise Refusal(f"the new {name} does not verify for {purpose}: {result.stdout.decode().strip()}")


def throwaway_identity(directory: Path) -> Path:
    """A client certificate from the new CA whose fingerprint no config pins."""
    ca_key = directory / "ca.key"
    if not ca_key.exists():
        raise Unhealthy("the new CA key needed for the pin control is gone")
    scratch = directory / "control"
    scratch.mkdir(exist_ok=True)
    (scratch / "ca.pem").write_bytes((directory / "ca.pem").read_bytes() if (directory / "ca.pem").exists() else b"")
    cert, key = issue_leaf(scratch, "unpinned", "NHM unpinned control", "clientAuth", 1, ca_key)
    identity = scratch / "unpinned-identity.pem"
    identity.write_bytes(cert.read_bytes() + key.read_bytes())
    return identity


# --- the stack ----------------------------------------------------------------


@dataclass(frozen=True)
class Listener:
    config: str
    host: str
    port: int
    server_name: str
    peers: tuple[tuple[str, str], ...]  # (alias, role)


class Stack:
    """The real environment. Tests replace this with a stand-in."""

    def __init__(self, state: Path) -> None:
        self.state = state

    def units(self) -> list[str]:
        result = run(["systemctl", "--user", "list-unit-files", "--no-legend", "--plain", "tos-local-health-*"], timeout=60)
        if result.returncode != 0:
            raise Refusal("cannot list the user units")
        return [line.split()[0] for line in result.stdout.decode().splitlines() if line.strip()]

    def restart(self, units: list[str]) -> None:
        if run(["systemctl", "--user", "restart", *units], timeout=180).returncode != 0:
            raise Unhealthy(f"restarting {len(units)} units failed")

    def active(self, unit: str) -> bool:
        return run(["systemctl", "--user", "is-active", unit], timeout=30).stdout.decode().strip() == "active"

    def request(self, listener: Listener, ca: Path, identity: Path | None, method: str, path: str,
                headers: dict[str, str] | None = None, hostname: str = "localhost") -> tuple[int | str, str | None, bytes]:
        """(HTTP status, REJECTED or TRANSPORT; served leaf SHA-256; body)."""
        context = ssl.create_default_context(cafile=str(ca))
        if identity is not None:
            context.load_cert_chain(str(identity))
        # Connecting by `hostname` makes the handshake verify that name (DNS or IP
        # SAN); both names reach the loopback listener.
        connection = http.client.HTTPSConnection(hostname, listener.port, context=context, timeout=15)
        served_pin = None
        counting = None
        try:
            connection.connect()
            served = connection.sock.getpeercert(binary_form=True)
            served_pin = sha256(served) if served else None
            # Count response bytes where they arrive, so a reply cut off after a
            # partial status line is never mistaken for one that never started.
            counting = CountingSocket(connection.sock)
            connection.sock = counting
            connection.request(method, path, body=b"" if method == "POST" else None, headers=headers or {})
            response = connection.getresponse()
            return response.status, served_pin, response.read()
        except ConnectionResetError:
            # Includes RemoteDisconnected. After a completed handshake, a close or
            # reset before a single response byte is how the ingress turns away a
            # certificate it does not pin; a reset with any byte received is not.
            dropped = served_pin is not None and counting is not None and counting.received == 0
            return (DROPPED if dropped else TRANSPORT), served_pin, b""
        except ssl.SSLError as error:
            return classify_tls_error(error), None, b""
        except (OSError, http.client.HTTPException):
            return TRANSPORT, None, b""
        finally:
            connection.close()

    def observe(self) -> list[dict]:
        script = self.state / "observe.py"
        result = run([sys.executable, str(script)], timeout=300)
        text = result.stdout.decode(errors="replace")
        match = re.search(r"^saved (\S+)$", text, re.M)
        if result.returncode != 0 or not match:
            raise Unhealthy(f"observe.py failed: {(text + result.stderr.decode(errors='replace')).strip()[-300:]}")
        return json.loads(Path(match.group(1)).read_text())

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def now(self) -> float:
        return time.time()

    def fault(self, point: str) -> None:
        """Tests interrupt the transaction here."""


class _CountingRaw(io.RawIOBase):
    """Counts bytes read from the socket's own raw file, which also keeps the
    socket open while the response is read after http.client closes it."""

    def __init__(self, source) -> None:
        self.source = source
        self.received = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer):
        count = self.source.readinto(buffer)
        if count:
            self.received += count
        return count

    def close(self) -> None:
        self.source.close()
        super().close()


class CountingSocket:
    """A connected socket whose response reader counts every byte received."""

    def __init__(self, sock) -> None:
        self._sock = sock
        self._raw: _CountingRaw | None = None

    @property
    def received(self) -> int:
        return self._raw.received if self._raw is not None else 0

    def makefile(self, mode: str = "rb", *args, **kwargs):
        self._raw = _CountingRaw(self._sock.makefile("rb", buffering=0))
        return io.BufferedReader(self._raw)

    def __getattr__(self, name: str):
        return getattr(self._sock, name)


def classify_tls_error(error: ssl.SSLError) -> str:
    """REJECTED only for an alert in which the server refuses our client credential.

    A failure to verify the server, and any other alert (handshake_failure can be
    a failed parameter negotiation), is a transport failure and proves nothing
    about the credential.
    """
    if isinstance(error, ssl.SSLCertVerificationError):
        return TRANSPORT
    reason = str(getattr(error, "reason", "") or "")
    return REJECTED if reason.endswith(CREDENTIAL_ALERTS) else TRANSPORT


def listeners(state: Path) -> list[Listener]:
    found = []
    for name in INGRESS_CONFIGS:
        path = state / "config" / name
        try:
            config = json.loads(path.read_text())
            host, port = config["listen"].rsplit(":", 1)
            peers = tuple((peer["alias"], peer["role"]) for peer in config["peers"])
            found.append(Listener(name, host, int(port), config["server_name"], peers))
        except (OSError, ValueError, KeyError, TypeError):
            raise Refusal(f"cannot read the ingress config {path}") from None
        for alias, role in peers:
            if alias not in IDENTITIES or role not in OPERATIONS:
                raise Refusal(f"{name}: unknown peer {alias} with role {role}")
    return found


def stack_units(state: Path, present: list[str]) -> tuple[list[str], list[str]]:
    """(ingress units, client units), derived from the configs and checked against systemd."""
    config = state / "config"
    ingress = [f"tos-local-health-{name[:-5]}.service" for name in INGRESS_CONFIGS]
    clients = []
    for path in sorted(config.glob("collector-*.json")):
        number = re.search(r"(\d+)$", path.stem)
        if not number:
            raise Refusal(f"cannot map {path.name} to a unit")
        clients.append(f"tos-local-health-collector-{number.group(1)}.service")
    for prefix in ("probe", "native-poll"):
        clients += [f"tos-local-health-{path.stem}.service" for path in sorted(config.glob(f"{prefix}-*.json"))]
    for config_name, unit in (("manager.json", "manager"), ("query-inventory.json", "query")):
        if (config / config_name).exists():
            clients.append(f"tos-local-health-{unit}.service")
    expected = set(ingress) | set(clients)
    services = {unit for unit in present if unit.endswith(".service")} - set(PKI_UNITS)
    if services != expected:
        raise Refusal(
            f"the stack's units differ from its configs: missing {sorted(expected - services)}, "
            f"unexpected {sorted(services - expected)}"
        )
    return ingress, clients


def expected_nodes(state: Path) -> set[str]:
    nodes = set()
    for path in (state / "config").glob("collector-*.json"):
        try:
            nodes.add(json.loads(path.read_text())["node_id"])
        except (OSError, ValueError, KeyError):
            raise Refusal(f"cannot read {path}") from None
    return nodes


# --- verification -------------------------------------------------------------


def call(stack: Stack, *args, **kwargs) -> tuple[int | None, str | None, bytes]:
    """One request, waiting out the ingress's rate limit.

    The ingresses answer 429 once a peer has used its token bucket, after TLS and
    the pin have passed; the verification sends enough requests to hit it. A 429
    says nothing about the credentials, so it is retried, a bounded number of
    times, rather than counted as a result.
    """
    for _ in range(RATE_LIMIT_RETRIES):
        status, served, body = stack.request(*args, **kwargs)
        if status != 429:
            return status, served, body
        stack.sleep(RATE_LIMIT_PAUSE)
    raise Unhealthy(f"the ingress kept answering 429 after {RATE_LIMIT_RETRIES} attempts")


def refused(stack: Stack, what: str, server_pin: str, *args) -> None:
    """A negative check: a credential alert, a 403, or the ingress's pin drop.

    A drop (handshake completed, then closed before any response) counts only
    when the expected server certificate was served; the caller runs it only on
    a listener whose positive checks just passed. Anything else proves nothing.
    """
    status, served, _ = call(stack, *args)
    if status == DROPPED and served == server_pin:
        return
    if status in (TRANSPORT, DROPPED):
        raise Unhealthy(f"{what}: the request failed in transport, which proves nothing")
    if status not in (REJECTED, 403):
        raise Unhealthy(f"{what} was accepted ({status})")


def verify(
    stack: Stack,
    state: Path,
    live: Path,
    other: Path | None,
    control_dir: Path | None,
    units: tuple[list[str], list[str]],
) -> None:
    """Prove the PKI in `live` works end to end and `other` identities are refused.

    `live` holds the PKI that must work, `other` the identities that must not.
    The pin control is a fresh client certificate from the new CA (kept in
    control_dir), pinned nowhere, which must be refused whichever PKI is live.
    Without `other` and `control_dir` (the staging was lost) only the positive
    checks run; the caller must then not call the result verified.
    """
    ingress, clients = units
    deadline = stack.now() + 60
    for unit in ingress + clients:
        while not stack.active(unit):
            if stack.now() > deadline:
                raise Unhealthy(f"{unit} is not active")
            stack.sleep(2)
    ca = live / "ca.pem"
    server_pin = sha256(first_cert_der((live / "server.pem").read_bytes()))
    unpinned = throwaway_identity(control_dir) if control_dir is not None else None
    for listener in listeners(state):
        for hostname in ("localhost", "127.0.0.1"):
            status, served, _ = call(stack, listener, ca, live / IDENTITIES[listener.peers[0][0]], "GET", "/", hostname=hostname)
            if not isinstance(status, int) or served != server_pin:
                raise Unhealthy(f"{listener.config}: the served certificate is not the expected one ({hostname}, {status})")
        # Every positive check on this listener first, so a refusal below is read
        # against a listener that has just served the live identities.
        for alias, role in listener.peers:
            method, path, want = OPERATIONS[role]
            status, _, _ = call(stack, listener, ca, live / IDENTITIES[alias], method, path)
            if status != want:
                raise Unhealthy(f"{listener.config}: {alias} {method} {path} gave {status}, expected {want}")
        for alias, role in listener.peers:
            if other is not None:
                method, path, _ = OPERATIONS[role]
                refused(stack, f"{listener.config}: the replaced {alias} identity", server_pin,
                        listener, ca, other / IDENTITIES[alias], method, path)
        if unpinned is not None:
            method, path, _ = OPERATIONS[listener.peers[0][1]]
            refused(stack, f"{listener.config}: an unpinned certificate from the new CA", server_pin,
                    listener, ca, unpinned, method, path)
    verify_observations(stack, state, live)


def evaluation_sequence(stack: Stack, state: Path, live: Path) -> int:
    manager = next(listener for listener in listeners(state) if listener.config == "manager-ingress.json")
    token = (state / "config" / "manager-read.token").read_text().strip()
    status, _, body = call(
        stack, manager, live / "ca.pem", live / IDENTITIES["local_reader"], "GET", "/v1/manager/state",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        if status != 200:
            raise ValueError
        return int(json.loads(body)["evaluation_sequence"])
    except (ValueError, KeyError, TypeError):
        raise Unhealthy(f"cannot read the manager's evaluation sequence (status {status})") from None


def healthy(rows: list[dict], nodes: set[str]) -> str | None:
    """None if the observation shows healthy monitoring, else why not."""
    seen = {row.get("node") for row in rows}
    if seen != nodes:
        return f"observed nodes {sorted(seen)}, expected {sorted(nodes)}"
    for row in rows:
        results = row.get("results", {})
        for scope in CORE_SCOPES + CACHE_ONLY_SCOPES:
            result = results.get(scope) or {}
            good = result.get("status") in ("ok", "partial") and not result.get("error")
            # The one allowed exception: no collector feeds host and telemetry.
            cache_miss = (
                scope in CACHE_ONLY_SCOPES
                and result.get("status") == "error"
                and (result.get("error") or {}).get("code") == "CACHE_MISS"
                and result.get("data") is None
            )
            if not (good or cache_miss):
                return f"{row['node']} {scope} is {result.get('status')} ({(result.get('error') or {}).get('code')})"
    return None


def verify_observations(stack: Stack, state: Path, live: Path) -> None:
    nodes = expected_nodes(state)
    first = evaluation_sequence(stack, state, live)
    deadline = stack.now() + 300
    problem = "no observation yet"
    while stack.now() <= deadline:
        stack.sleep(20)
        try:
            problem = healthy(stack.observe(), nodes) or ""
            if not problem and evaluation_sequence(stack, state, live) > first:
                return
            problem = problem or "the manager's evaluation sequence did not advance"
        except Unhealthy as error:
            problem = str(error)
    raise Unhealthy(f"monitoring did not recover: {problem}")


# --- the transaction ----------------------------------------------------------


class Rotation:
    def __init__(self, state: Path, stack: Stack) -> None:
        self.state = state
        self.stack = stack
        self.journal_path = state / JOURNAL

    def live_paths(self) -> list[Path]:
        return [self.state / "pki" / name for name in PKI_FILES] + [self.state / "config" / n for n in INGRESS_CONFIGS]

    def journal(self) -> dict | None:
        try:
            return json.loads(self.journal_path.read_text())
        except FileNotFoundError:
            return None
        except ValueError:
            raise Refusal(f"{self.journal_path} is unreadable; resolve it by hand") from None

    def record(self, journal: dict, phase: str, reason: str = "") -> None:
        journal["phase"] = phase
        journal["reason"] = reason
        durable_write(self.journal_path, json.dumps(journal, indent=2).encode(), 0o600)

    def units(self) -> tuple[list[str], list[str]]:
        return stack_units(self.state, self.stack.units())

    # staging

    def read_live(self) -> tuple[dict[str, bytes], list[tuple[Path, str, dict, int]]]:
        """The live PKI and the eight ingress configs, refusing unexpected pins."""
        try:
            old = {name: (self.state / "pki" / name).read_bytes() for name in PKI_FILES}
        except OSError as error:
            raise Refusal(f"cannot read the live PKI: {error}") from None
        live_pins = {alias: sha256(first_cert_der(old[name])) for alias, name in IDENTITIES.items()}
        configs = []
        for name in INGRESS_CONFIGS:
            path = self.state / "config" / name
            try:
                text = path.read_text()
                config = json.loads(text)
                aliases = sorted(peer["alias"] for peer in config["peers"])
            except (OSError, ValueError, KeyError, TypeError):
                raise Refusal(f"cannot read {path}") from None
            if aliases != sorted(IDENTITIES):
                raise Refusal(f"{name} does not pin exactly the probe and the reader identity")
            for peer in config["peers"]:
                if peer.get("certificate_sha256") != live_pins[peer["alias"]]:
                    raise Refusal(f"{name}: {peer['alias']} pins {str(peer.get('certificate_sha256'))[:12]}…, not the live identity")
            configs.append((path, text, config, path.stat().st_mode & 0o777))
        return old, configs

    def stage(self, days: int) -> dict:
        # Validate everything before anything is created or issued.
        old, configs = self.read_live()
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(self.stack.now()))
        staging = self.state / f"pki-staging-{stamp}"
        backup = self.state / "retired" / stamp
        try:
            for directory in (staging, backup):
                directory.mkdir(parents=True, mode=0o700)
            new = issue(staging, days)
            new_pins = {alias: sha256(first_cert_der(new[name])) for alias, name in IDENTITIES.items()}
            files = []
            for path, text, config, mode in configs:
                for peer in config["peers"]:
                    peer["certificate_sha256"] = new_pins[peer["alias"]]
                files.append((path, text.encode(), (json.dumps(config, indent=2) + "\n").encode(), mode))
            for name in PKI_FILES:
                files.append((self.state / "pki" / name, old[name], new[name], 0o600))
            manifest = []
            for path, before, after, mode in files:
                durable_write(backup / path.name, before, 0o600)
                durable_write(staging / f"live-{path.name}", after, 0o600)
                manifest.append({"path": str(path), "old": sha256(before), "new": sha256(after), "mode": mode})
            journal = {"staging": str(staging), "backup": str(backup), "files": manifest, "days": days}
            self.record(journal, "staged")
        except BaseException:
            # Nothing live has changed yet; leave no staging and no new CA key behind.
            shutil.rmtree(staging, ignore_errors=True)
            shutil.rmtree(backup, ignore_errors=True)
            self.journal_path.unlink(missing_ok=True)
            raise
        return journal

    def content(self, journal: dict, entry: dict, which: str) -> bytes:
        source = Path(journal["backup"] if which == "old" else journal["staging"])
        name = Path(entry["path"]).name
        data = (source / name if which == "old" else source / f"live-{name}").read_bytes()
        if sha256(data) != entry[which]:
            raise Refusal(f"the recorded {which} copy of {name} does not match its hash")
        return data

    def classify(self, journal: dict) -> list[str]:
        """'old' or 'new' for each live file; anything else is foreign and refuses."""
        states = []
        for entry in journal["files"]:
            try:
                digest = sha256(Path(entry["path"]).read_bytes())
            except OSError:
                raise Refusal(f"{entry['path']} is missing; it is neither the old nor the new content") from None
            if digest == entry["new"]:
                states.append("new")
            elif digest == entry["old"]:
                states.append("old")
            else:
                raise Refusal(f"{entry['path']} matches neither recorded version; resolve it by hand")
        return states

    def put(self, journal: dict, which: str, phase: str) -> None:
        self.record(journal, phase)
        for index, entry in enumerate(journal["files"]):
            path = Path(entry["path"])
            if sha256(path.read_bytes()) != entry[which]:
                durable_write(path, self.content(journal, entry, which), entry["mode"])
            self.stack.fault(f"{phase}:{index}")

    def staging_usable(self, journal: dict) -> bool:
        try:
            for entry in journal["files"]:
                self.content(journal, entry, "new")
            return (Path(journal["staging"]) / "ca.key").is_file()
        except (Refusal, OSError):
            return False

    def backup_usable(self, journal: dict) -> bool:
        try:
            for entry in journal["files"]:
                self.content(journal, entry, "old")
            return True
        except (Refusal, OSError):
            return False

    def verify_side(self, journal: dict, which: str, controls: bool = True) -> None:
        """Restart and verify with `which` PKI live; the other identities must fail.

        Without `controls` (the staging is lost) the negative checks that need the
        replacement identities and the new CA key cannot run.
        """
        ingress, clients = self.units()
        self.stack.restart(ingress)
        self.stack.restart(clients)
        live = self.state / "pki"
        if not controls:
            verify(self.stack, self.state, live, None, None, (ingress, clients))
            return
        staging = Path(journal["staging"])
        other = staging / "other"
        other.mkdir(exist_ok=True)
        for entry in journal["files"]:
            name = Path(entry["path"]).name
            if name in IDENTITIES.values():
                durable_write(other / name, self.content(journal, entry, "old" if which == "new" else "new"), 0o600)
        verify(self.stack, self.state, live, other, staging, (ingress, clients))

    def failed(self, journal: dict, reason: str) -> int:
        try:
            self.record(journal, "recovery_failed", reason)
        except OSError:
            pass  # the journal keeps its last phase, which the next run recovers
        log(f"RECOVERY FAILED: monitoring remains unhealthy: {reason}")
        return EXIT_RECOVERY_FAILED

    def guarded(self, journal: dict, action) -> int:
        """Run a step that may change live files; an unexpected error is a failed recovery.

        Once installation may have begun, "refused, nothing changed" would be a
        false claim, so every error other than a verification failure (which the
        step handles itself) ends in recovery_failed with the artifacts kept.
        """
        try:
            return action()
        except (Refusal, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            return self.failed(journal, f"unexpected error after the rotation began: {error}")

    def finish(self, journal: dict) -> int:
        self.record(journal, "verified")
        shutil.rmtree(journal["staging"], ignore_errors=True)
        retired = sorted((self.state / "retired").iterdir())
        for old in retired[:-KEEP_RETIRED]:
            shutil.rmtree(old, ignore_errors=True)
        self.journal_path.unlink()
        log("rotation verified")
        return EXIT_OK

    def roll_back(self, journal: dict, reason: str) -> int:
        if not self.backup_usable(journal):
            return self.failed(journal, f"{reason}; the backup is unusable, nothing was restored")
        old = {Path(e["path"]).name: self.content(journal, e, "old") for e in journal["files"]}
        if not all_valid_now(old, self.stack.now()):
            return self.failed(journal, f"{reason}; the old PKI is not valid now, the new one stays installed")
        controls = self.staging_usable(journal)
        self.put(journal, "old", "rolling_back")
        try:
            self.verify_side(journal, "old", controls)
        except Unhealthy as error:
            return self.failed(journal, f"{reason}; the restored PKI failed too: {error}")
        if not controls:
            return self.failed(
                journal,
                f"{reason}; staging lost; old PKI restored and verified without the replacement and unpinned controls",
            )
        self.record(journal, "rolled_back", reason)
        log(f"rotation failed and the old PKI was restored and verified: {reason}")
        return EXIT_ROLLED_BACK

    def complete(self, journal: dict) -> int:
        """Bring an installed or installing journal to verified, or roll it back."""
        try:
            self.put(journal, "new", "installing")
            self.record(journal, "installed")
            self.verify_side(journal, "new")
        except Unhealthy as error:
            return self.roll_back(journal, str(error))
        return self.finish(journal)

    # entry points

    def recover(self, resolve: str | None) -> int | None:
        """Handle an unfinished journal. None means: go on with a normal run."""
        journal = self.journal()
        if journal is None:
            if resolve:
                raise Refusal("there is no failed rotation to resolve")
            return None
        phase = journal.get("phase")
        log(f"found an unfinished rotation in phase {phase}")
        if phase == "staged":
            shutil.rmtree(journal["staging"], ignore_errors=True)
            shutil.rmtree(journal["backup"], ignore_errors=True)
            self.journal_path.unlink()
            return None
        self.classify(journal)  # a foreign or missing live file refuses with nothing touched
        if phase in ("installing", "installed", "rolling_back") and not self.backup_usable(journal):
            # Neither finishing (its verification needs the old identities as the
            # replaced-credential control) nor undoing is possible without it.
            return self.failed(journal, "the backup is unusable; nothing more was installed or restored")
        if phase in ("installing", "installed"):
            if not self.staging_usable(journal):
                return self.guarded(journal, lambda: self.roll_back(journal, "the staged files of an interrupted installation are gone"))
            return self.guarded(journal, lambda: self.complete(journal))
        if phase == "rolling_back":
            return self.guarded(journal, lambda: self.roll_back(journal, journal.get("reason") or "interrupted rollback"))
        if phase == "verified":
            return self.guarded(journal, lambda: self.finish(journal))
        if phase == "rolled_back":
            shutil.rmtree(journal["staging"], ignore_errors=True)
            self.journal_path.unlink()
            return None
        if phase == "recovery_failed":
            if resolve == "keep-new":
                return self.guarded(journal, lambda: self.keep_new(journal))
            if resolve == "restore-old":
                return self.guarded(journal, lambda: self.roll_back(journal, "operator restored the old PKI"))
            log(f"RECOVERY FAILED earlier: {journal.get('reason')}; run rotate --resolve keep-new|restore-old")
            return EXIT_RECOVERY_FAILED
        raise Refusal(f"unknown rotation phase {phase!r}")

    def keep_new(self, journal: dict) -> int:
        if not self.staging_usable(journal):
            return self.failed(journal, "keep-new is impossible: the staged files are gone")
        try:
            self.put(journal, "new", "installing")
            self.verify_side(journal, "new")
        except Unhealthy as error:
            return self.failed(journal, f"keep-new failed: {error}")
        return self.finish(journal)

    def rotate(self, days: int, due_within: float | None, resolve: str | None) -> int:
        outcome = self.recover(resolve)
        if outcome is not None:
            return outcome
        if resolve:
            raise Refusal("nothing to resolve")
        if due_within is not None:
            spans = [validity(self.state / "pki" / name) for name in CERTS]
            now = self.stack.now()
            soonest = min(end for _, end in spans)
            valid_now = all(start <= now < end for start, end in spans)
            if valid_now and soonest - now > due_within * 86400:
                log(f"not due: the first certificate expires {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(soonest))}")
                return EXIT_OK
        self.units()
        listeners(self.state)
        journal = self.stage(days)
        log(f"staged a new PKI valid for {days} days")
        return self.guarded(journal, lambda: self.complete(journal))


# --- command line -------------------------------------------------------------


def state_dir(given: Path | None) -> Path:
    if given:
        return given.resolve()
    candidates = [path for path in HEALTH_ROOT.iterdir() if path.is_dir()] if HEALTH_ROOT.is_dir() else []
    if len(candidates) != 1:
        raise Refusal(f"expected one state directory under {HEALTH_ROOT}, found {len(candidates)}; pass --state-dir")
    return candidates[0]


def check(state: Path, within_days: float, now: float) -> int:
    due = False
    for name in CERTS:
        start, end = validity(state / "pki" / name)
        left = (end - now) / 86400
        note = " NOT YET VALID" if start > now else ""
        log(f"{name}: expires {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(end))} ({left:.1f} days){note}")
        due |= left <= within_days or start > now
    return 1 if due else 0


def main(argv: list[str] | None = None, stack_factory=Stack) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "rotate"):
        command = sub.add_parser(name)
        command.add_argument("--state-dir", type=Path)
    sub.choices["check"].add_argument("--within-days", type=float, default=7)
    sub.choices["rotate"].add_argument("--if-due-within-days", type=float)
    sub.choices["rotate"].add_argument("--days", type=int, default=30)
    sub.choices["rotate"].add_argument("--resolve", choices=("keep-new", "restore-old"))
    args = parser.parse_args(argv)
    try:
        state = state_dir(args.state_dir)
        stack = stack_factory(state)
        if args.command == "check":
            return check(state, args.within_days, stack.now())
        if not 2 <= args.days <= 365:
            raise Refusal("--days must be between 2 and 365")
        with open(state / "pki.lock", "w") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Refusal("another rotation is in progress") from None
            return Rotation(state, stack).rotate(args.days, args.if_due_within_days, args.resolve)
    except Refusal as error:
        log(f"REFUSED: {error}")
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
