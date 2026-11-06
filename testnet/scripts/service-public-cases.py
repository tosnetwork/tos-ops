#!/usr/bin/env python3
"""Once-only public runner for the bounded service-contract acceptance cases (SC-02..SC-08).

The runner drives the pinned `tosctl` against the public testnet from a private directory
on the coordinator and records exact public receipts. It never signs the funding (pool-owner)
wallet: funding stays in `testnet-elections.py owner-fund`, and this tool only plans the
amounts, verifies the credits and keeps the cumulative total under a hard ceiling.

Guarantees the tests pin:
  * every value step has a stable label and an `O_EXCL` attempt marker written before the CLI
    is invoked; a label whose marker exists is refused, so a crash or lost reply can never lead
    to a second send of the same step (reconciliation is read-only); a step that ended in any
    verdict other than settled / refused-as-intended / cli-refused-before-broadcast is never
    replayed or re-sent;
  * a settlement claim is the exact transaction (same hash) seen on the broadcast source and on
    every confirmation source, found through the payer's own outgoing message, with the compute
    exit code, the aborted flag and the action result recorded; a refusal control must abort
    with the pinned exit code and leave the protected contract state unchanged;
  * a CLI refusal is only recorded as "nothing was sent" after a bounded observation window on
    the payer, and such a control carries no on-chain receipt, which the case result says;
  * preflight refuses a wrong CLI binary, a different genesis on any source, a global version
    other than the pinned one, the window around a validator-set rotation (ConfigParam 34
    bounds), an over-temperature package, a group-readable private directory and a cumulative
    funding total above the ceiling; the rotation and thermal guards run again before every
    value step;
  * `plan <case>` lists the exact CLI argument vectors a case will use; `case` checks them
    against the pinned CLI's own `--help` before the first send;
  * CLI stdout/stderr land in the private directory; the evidence directory only receives
    sanitized records (labels, argv with the private path redacted, addresses, hashes, codes).

Commands: preflight | setup | plan-funding | record-funding | activate | plan <case> |
case <case> | return-funds | status.  See `--help`.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

NANO = 10**9
QUIET_S = 600
TEMP_LIMIT_C = 82.0
CLI_TIMEOUT_S = 180
SETTLE_TIMEOUT_S = 150
REFUSAL_OBSERVE_S = 45
POLL_S = 2.0
CP8_VERSION = 16
WALLETS = ("sc-owner", "sc-client", "sc-verifier", "sc-respondent", "sc-outsider")
KEYS = ("sc-attestor-key", "sc-rotated-attestor-key", "sc-wrong-key")
FUNDING_PLAN_TOS = {
    "sc-owner": "7.5",
    "sc-client": "3.0",
    "sc-verifier": "2.0",
    "sc-respondent": "1.5",
    "sc-outsider": "2.0",
}
AMOUNT_RE = re.compile(r"^(\d+)(?:\.(\d{1,9}))?$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HASH = {
    "subject": "11" * 32,
    "attested_1": "22" * 32,
    "attested_2": "33" * 32,
    "metadata": "44" * 32,
    "proof_scheme": "55" * 32,
    "task_categories": "66" * 32,
    "pricing": "77" * 32,
    "verification_method": "88" * 32,
    "new_metadata": "99" * 32,
    "policy": "aa" * 32,
    "result": "bb" * 32,
    "evidence": "cc" * 32,
    "dispute": "dd" * 32,
    "claimant_evidence": "ee" * 32,
    "respondent_evidence": "ff" * 32,
    "ruling": "12" * 32,
    "response": "34" * 32,
    "request_1": "56" * 32,
    "request_2": "78" * 32,
}

# Contract exit codes (crypto/smartcont/*.fc at the pinned CLI commit) and limits.
SERVICE_NOT_OWNER = 1900
SERVICE_NOT_AUTHORIZED = 1923
TASK_ACCEPT_NOT_AGENT = 101
TASK_SETTLE_AUTHORITY = 105
TASK_RESOLVE_AUTHORITY = 124
DISPUTE_NOT_RESPONDENT = 2000
DISPUTE_NOT_REVIEWER = 2001
DISPUTE_ALREADY_RESOLVED = 2002
ATTEST_BAD_SIGNATURE = 2101
ATTEST_NOT_OWNER = 2102
REGISTRY_NOT_OWNER = 1800
REGISTRY_NOT_VERIFIER = 1801
REGISTRY_INSUFFICIENT_BOND = 1805
TASK_MIN_REVIEW_PERIOD_S = 3600
TASK_HORIZON_S = 7200
SERVICE_MIN_DEPLOY_TOS = "1.5"  # >= 1 TOS operating reserve + 0.2 TOS fee margin
SERVICE_WITHDRAW_CAP = 50_000_000  # 0.05 TOS, at most the price of the one answered call
REPLAYABLE = ("settled", "refused-as-intended", "cli-refused-before-broadcast")
RECONCILABLE = ("unknown", "unknown-not-observed", "unexpected-abort")
FLAG_FIXTURE = (
    Path(__file__).resolve().parents[1] / "tests" / "data" / "service-public-cases-cli-flags.json"
)


class Refusal(Exception):
    """A guard refused to continue; nothing was sent after it."""


def now() -> int:
    return int(time.time())


def utc(ts: int | float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def crc16_xmodem(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else crc << 1
            crc &= 0xFFFF
    return crc


def norm_addr(address: str) -> str:
    """Canonical `wc:hex` form of a raw or user-friendly (base64url, checksummed) address."""
    if not isinstance(address, str) or not address:
        raise Refusal(f"bad address {address!r}")
    if ":" in address:
        wc, _, acc = address.partition(":")
        if not re.fullmatch(r"-?\d+", wc) or not HEX64_RE.fullmatch(acc.lower()):
            raise Refusal(f"bad raw address {address!r}")
        return f"{int(wc)}:{acc.lower()}"
    try:
        raw = base64.urlsafe_b64decode(address.replace("+", "-").replace("/", "_") + "==")
    except (ValueError, TypeError) as exc:
        raise Refusal(f"bad address {address!r}") from exc
    if len(raw) != 36 or crc16_xmodem(raw[:34]) != int.from_bytes(raw[34:], "big"):
        raise Refusal(f"bad address checksum {address!r}")
    wc = int.from_bytes(raw[1:2], "big", signed=True)
    return f"{wc}:{raw[2:34].hex()}"


def same_addr(a: str | None, b: str | None) -> bool:
    try:
        return bool(a) and bool(b) and norm_addr(a) == norm_addr(b)
    except Refusal:
        return False


def tos_to_nanotos(text: str) -> int:
    m = AMOUNT_RE.fullmatch(str(text).strip())
    if not m:
        raise Refusal(f"bad TOS amount {text!r}")
    whole, frac = m.group(1), m.group(2) or ""
    return int(whole) * NANO + int((frac + "0" * 9)[:9])


def nanotos_text(value: int) -> str:
    if value < 0:
        raise Refusal("negative amount")
    return f"{value // NANO}.{value % NANO:09d}"


def state_nanotos(value) -> int:
    """A contract view amount, which the CLI prints either as nanotos or as a TOS string."""
    if isinstance(value, bool) or value is None:
        raise Refusal(f"amount field missing: {value!r}")
    if isinstance(value, int):
        return value
    text = str(value)
    return tos_to_nanotos(text) if "." in text else int(text)


def boc_root_data(raw: bytes) -> bytes:
    """Data bytes of the root cell of a serialized bag of cells (no cell parsing beyond that)."""
    try:
        if raw[:4] != bytes.fromhex("b5ee9c72"):
            raise Refusal("not a BOC")
        flags = raw[4]
        size = flags & 7
        has_index = bool(flags & 0x80)
        off = raw[5]
        p = 6
        count = int.from_bytes(raw[p : p + size], "big")
        p += size * 3  # cells, roots, absent
        p += off  # total size
        root = int.from_bytes(raw[p : p + size], "big")
        p += size
        if has_index:
            p += count * off
        for i in range(count):
            d1, d2 = raw[p], raw[p + 1]
            refs = d1 & 7
            stored = bool(d1 & 16)
            p += 2
            if stored:
                hashes = bin(d1 >> 5).count("1") + 1
                p += hashes * 34
            ln = (d2 + 1) // 2
            data = raw[p : p + ln]
            if len(data) != ln:
                raise Refusal("BOC truncated")
            p += ln + refs * size
            if i == root:
                return data
    except IndexError as exc:
        raise Refusal("BOC truncated") from exc
    raise Refusal("BOC root missing")


def quiet_window_distance(ts: int, since: int, until: int) -> int:
    """Seconds between `ts` and the nearest validator-set boundary; 0 once `until` has passed."""
    if ts >= until or ts < since:
        return 0
    return min(ts - since, until - ts)


def package_temperatures() -> list[float]:
    out: list[float] = []
    for hw in sorted(Path("/sys/class/hwmon").glob("hwmon*")):
        for label in hw.glob("temp*_label"):
            try:
                if not label.read_text().startswith("Package id"):
                    continue
                value = label.with_name(label.name.replace("_label", "_input")).read_text()
                out.append(int(value.strip()) / 1000.0)
            except (OSError, ValueError):
                continue
    return out


class Rpc:
    def __init__(self, primary: str, confirms: list[str]):
        self.primary = primary
        self.confirms = confirms

    @property
    def all_sources(self) -> list[str]:
        return [self.primary, *self.confirms]

    def call(self, method: str, url: str | None = None, **params):
        url = url or self.primary
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        req = urllib.request.Request(
            url, data=body.encode(), headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                answer = json.loads(resp.read())
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            raise Refusal(f"rpc {method} on {url}: {exc}") from exc
        if "result" not in answer:
            raise Refusal(f"rpc {method} on {url}: {answer.get('error')}")
        return answer["result"]

    def genesis(self, url: str) -> dict:
        init = self.call("getMasterchainInfo", url)["init"]
        return {"root_hash": init["root_hash"], "file_hash": init["file_hash"]}

    def head(self, url: str | None = None) -> dict:
        return self.call("getMasterchainInfo", url)["last"]

    def config_param(self, idx: int) -> bytes:
        res = self.call("getConfigParam", config_id=idx)
        return boc_root_data(base64.b64decode(res["config"]["bytes"]))

    def global_version(self) -> int:
        data = self.config_param(8)
        if len(data) < 5 or data[0] != 0xC4:
            raise Refusal("ConfigParam 8 tag")
        return int.from_bytes(data[1:5], "big")

    def rotation_bounds(self) -> tuple[int, int]:
        """(utime_since, utime_until) of the installed validator set (ConfigParam 34)."""
        data = self.config_param(34)
        if len(data) < 9 or data[0] not in (0x11, 0x12):
            raise Refusal("ConfigParam 34 tag")
        return int.from_bytes(data[1:5], "big"), int.from_bytes(data[5:9], "big")

    def info(self, address: str, url: str | None = None) -> dict:
        return self.call("getAddressInformation", url, address=address)

    def balance(self, address: str) -> int:
        return int(self.info(address)["balance"])

    def state(self, address: str) -> str:
        return str(self.info(address)["state"])

    def last_lt(self, address: str, url: str | None = None) -> int:
        tid = self.info(address, url).get("last_transaction_id") or {}
        return int(tid.get("lt") or 0)

    def transactions_after(self, address: str, lt: int, url: str | None = None) -> list[dict]:
        rows = self.call("getTransactions", url, address=address, limit=10)
        if len(rows) == 10 and all(int(r["transaction_id"]["lt"]) > lt for r in rows):
            raise Refusal(f"transaction page for {address} does not reach the baseline lt")
        return [r for r in rows if int(r["transaction_id"]["lt"]) > lt]


class Journal:
    def __init__(self, evidence: Path):
        self.evidence = evidence
        self.steps = evidence / "steps"
        self.steps.mkdir(parents=True, exist_ok=True)
        self.events = evidence / "events.jsonl"

    def log(self, **event) -> None:
        event.setdefault("utc", utc(now()))
        with self.events.open("a") as fh:
            fh.write(json.dumps(event, sort_keys=True) + "\n")

    def attempt(self, label: str, record: dict) -> Path:
        path = self.steps / f"{label}.attempt.json"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise Refusal(
                f"step {label!r} was already attempted; reconcile read-only, never re-send"
            ) from None
        with os.fdopen(fd, "w") as fh:
            json.dump({"label": label, "utc": utc(now()), **record}, fh, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        return path

    def attempt_record(self, label: str) -> dict | None:
        path = self.steps / f"{label}.attempt.json"
        return json.loads(path.read_text()) if path.exists() else None

    def done(self, label: str, record: dict) -> None:
        path = self.steps / f"{label}.done.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"label": label, "utc": utc(now()), **record}, sort_keys=True))
        os.replace(tmp, path)

    def result(self, label: str) -> dict | None:
        """The step's record: a read-only reconciliation, if one was made, else the original."""
        for suffix in ("reconciled", "done"):
            path = self.steps / f"{label}.{suffix}.json"
            if path.exists():
                return json.loads(path.read_text())
        return None

    def reconciled(self, label: str, record: dict) -> None:
        path = self.steps / f"{label}.reconciled.json"
        with path.open("x") as fh:
            json.dump({"label": label, "utc": utc(now()), **record}, fh, sort_keys=True)

    def attempted(self, label: str) -> bool:
        return (self.steps / f"{label}.attempt.json").exists()


class Cli:
    def __init__(self, path: Path, sha256: str, private_dir: Path, journal: Journal):
        self.path = path
        self.expected_sha = sha256
        self.private = private_dir
        self.config = private_dir / "tosctl-config.json"
        self.vault_env = private_dir / "vault.env"
        self.receipts = private_dir / "receipts"
        self.journal = journal
        self.calls = 0

    def check_binary(self) -> str:
        actual = sha256_file(self.path)
        if actual != self.expected_sha:
            raise Refusal(f"CLI sha256 {actual} != pinned {self.expected_sha}")
        return actual

    def env(self) -> dict:
        env = {k: v for k, v in os.environ.items() if k not in ("VAULT_URL",)}
        if self.vault_env.exists():
            for line in self.vault_env.read_text().splitlines():
                key, _, value = line.partition("=")
                if key.strip() == "VAULT_URL":
                    env["VAULT_URL"] = value.strip()
        return env

    def redact(self, args: tuple[str, ...]) -> list[str]:
        private = str(self.private)
        return [a.replace(private, "<private>") if private in a else a for a in args]

    def run(self, label: str, *args: str, want_json: bool = False):
        """Run tosctl once. Raw output stays private; the sanitized record is journaled.

        Returns (exit code or None on timeout, stdout text or parsed JSON)."""
        self.receipts.mkdir(mode=0o700, exist_ok=True)
        argv = [str(self.path), *args, "-c", str(self.config)]
        if want_json:
            argv += ["--format", "json"]
        self.calls += 1
        started = utc(now())
        timed_out = False
        try:
            proc = subprocess.run(
                argv, env=self.env(), capture_output=True, timeout=CLI_TIMEOUT_S, check=False
            )
            rc, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            rc, stdout, stderr = None, exc.stdout or b"", exc.stderr or b""
        (self.receipts / f"{label}.stdout").write_bytes(stdout)
        (self.receipts / f"{label}.stderr").write_bytes(stderr)
        self.journal.log(
            kind="cli",
            label=label,
            argv=self.redact(args),
            exit_code=rc,
            timed_out=timed_out,
            started=started,
            stdout_sha256=hashlib.sha256(stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        )
        text = stdout.decode("utf-8", "replace")
        if want_json and rc == 0:
            try:
                return rc, json.loads(text)
            except json.JSONDecodeError as exc:
                raise Refusal(f"{label}: CLI did not return JSON ({exc})") from exc
        return rc, text


def pinned_flags(path: Path) -> dict:
    return json.loads(path.read_text())


class Runner:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.private = Path(args.private_dir).expanduser()
        self.evidence = Path(args.evidence_dir).expanduser()
        self.evidence.mkdir(parents=True, exist_ok=True)
        self.journal = Journal(self.evidence)
        self.cli = Cli(Path(args.cli), args.cli_sha256, self.private, self.journal)
        self.rpc = Rpc(args.rpc, list(args.confirm_rpc or []))
        self.actors_path = self.evidence / "actors.json"
        self.ledger_path = self.evidence / "funding-ledger.jsonl"
        self.plan_path = self.evidence / "funding-plan.json"
        self.ceiling = tos_to_nanotos(args.stop_ceiling)

    # ----- state files ------------------------------------------------------------------
    def actors(self) -> dict:
        if not self.actors_path.exists():
            raise Refusal("actors.json missing; run setup first")
        return json.loads(self.actors_path.read_text())

    def actor_address(self, actor: str) -> str:
        wallets = self.actors()["wallets"]
        if actor not in wallets:
            raise Refusal(f"unknown actor {actor!r}; known: {sorted(wallets)}")
        return wallets[actor]

    def funded_total(self) -> int:
        total = 0
        if self.ledger_path.exists():
            for line in self.ledger_path.read_text().splitlines():
                total += int(json.loads(line)["amount_nanotos"])
        return total

    # ----- guards -------------------------------------------------------------------------
    def check_private_dir(self) -> None:
        if not self.private.exists():
            self.private.mkdir(mode=0o700, parents=True)
        mode = stat.S_IMODE(self.private.stat().st_mode)
        if mode & 0o077:
            raise Refusal(f"private dir {self.private} mode {oct(mode)} must be 0700")

    def check_genesis(self) -> dict:
        seen = {url: self.rpc.genesis(url) for url in self.rpc.all_sources}
        pinned = {"root_hash": self.args.genesis_root, "file_hash": self.args.genesis_file}
        for url, g in seen.items():
            if g != pinned:
                raise Refusal(f"genesis on {url} is {g}, pinned {pinned}")
        return pinned

    def check_quiet_window(self) -> dict:
        since, until = self.rpc.rotation_bounds()
        distance = quiet_window_distance(now(), since, until)
        if distance < QUIET_S:
            raise Refusal(
                f"within {distance}s of a validator-set boundary (since {utc(since)}, "
                f"until {utc(until)}); wait"
            )
        return {"utime_since": since, "utime_until": until, "seconds_to_boundary": distance}

    def check_thermal(self) -> list[float]:
        temps = package_temperatures()
        if self.args.skip_thermal:
            return temps
        if not temps:
            raise Refusal("no package temperature readable; use --skip-thermal only off-host")
        if max(temps) > TEMP_LIMIT_C:
            raise Refusal(f"package temperature {max(temps)} C above {TEMP_LIMIT_C}")
        return temps

    def guards(self) -> dict:
        """The two conditions that can change while a case runs; checked before every step."""
        return {
            "quiet_window": self.check_quiet_window(),
            "package_temperatures_c": self.check_thermal(),
        }

    def preflight(self, value_action: bool = True) -> dict:
        record = {
            "utc": utc(now()),
            "cli_sha256": self.cli.check_binary(),
            "genesis": self.check_genesis(),
            "global_version": self.rpc.global_version(),
            "head": self.rpc.head(),
            "funded_total_nanotos": self.funded_total(),
            "stop_ceiling_nanotos": self.ceiling,
        }
        if record["global_version"] != CP8_VERSION:
            raise Refusal(f"global version {record['global_version']} != {CP8_VERSION}")
        if value_action:
            record.update(self.guards())
        self.check_private_dir()
        self.journal.log(kind="preflight", **record)
        return record

    # ----- non-value CLI steps -----------------------------------------------------------------
    def local(self, label: str, *argv: str, want_json: bool = False):
        """A once-only CLI step that moves no value (profile, key or wallet bookkeeping)."""
        previous = self.journal.result(label)
        if previous:
            if previous.get("exit_code") == 0:
                return previous.get("answer")
            raise Refusal(f"step {label!r} already failed with exit {previous.get('exit_code')}")
        if self.journal.attempted(label):
            raise Refusal(f"step {label!r} was attempted without a result; reconcile by hand")
        self.journal.attempt(label, {"kind": "local", "argv": self.cli.redact(argv)})
        rc, answer = self.cli.run(label, *argv, want_json=want_json)
        self.journal.done(
            label, {"exit_code": rc, "answer": answer if want_json and rc == 0 else None}
        )
        if rc != 0:
            raise Refusal(f"{label}: exit {rc}")
        return answer if want_json else None

    # ----- setup --------------------------------------------------------------------------
    def setup(self) -> dict:
        self.preflight(value_action=False)
        if not self.cli.config.exists():
            rc, _ = self.cli.run(
                "setup-config", "config", "generate", "-o", str(self.cli.config), "--force"
            )
            if rc != 0:
                raise Refusal("config generate failed")
            cfg = json.loads(self.cli.config.read_text())
            cfg["chain_rpc"] = {
                "urls": [self.args.rpc.rsplit("/jsonRPC", 1)[0] + "/"],
                "api_key": None,
            }
            cfg["elections"] = None
            cfg["master_wallet"] = None
            cfg["indexer_enabled"] = False
            self.cli.config.write_text(json.dumps(cfg, indent=2) + "\n")
            os.chmod(self.cli.config, 0o600)
        if not self.cli.vault_env.exists():
            vault = self.private / "vault.json"
            master = secrets.token_hex(32)
            fd = os.open(self.cli.vault_env, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(f"VAULT_URL=file://{vault}?master_key={master}\n")
            del master
        for key in KEYS:
            self.local(f"setup-key-{key}", "key", "add", "--name", key)
        for wallet in WALLETS:
            self.local(
                f"setup-wallet-{wallet}", "wallet", "create", "-n", wallet, "-v", "V3R2", "-w", "0"
            )
        rc, rows = self.cli.run(f"setup-wallet-ls-{self.cli.calls}", "wallet", "ls", want_json=True)
        if rc != 0 or not isinstance(rows, list):
            raise Refusal("wallet ls failed")
        addresses = {}
        for row in rows:
            if isinstance(row, dict) and row.get("name") in WALLETS and row.get("address"):
                addresses[row["name"]] = norm_addr(row["address"])
        missing = [w for w in WALLETS if w not in addresses]
        if missing:
            raise Refusal(f"wallets without address: {missing}")
        actors = {"wallets": addresses, "keys": list(KEYS), "created_utc": utc(now())}
        self.actors_path.write_text(json.dumps(actors, indent=2, sort_keys=True) + "\n")
        self.journal.log(kind="setup", wallets=addresses)
        return actors

    # ----- funding ------------------------------------------------------------------------
    def plan_funding(self, source: str) -> dict:
        actors = self.actors()
        source = norm_addr(source)
        plan = []
        total = 0
        for wallet, amount in FUNDING_PLAN_TOS.items():
            nanotos = tos_to_nanotos(amount)
            total += nanotos
            plan.append(
                {
                    "actor": wallet,
                    "to": actors["wallets"][wallet],
                    "amount_tos": amount,
                    "operation_id": f"sc-fund-{wallet.removeprefix('sc-')}-{self.args.date}",
                    "purpose": f"service contract public cases {wallet} {self.args.date}",
                }
            )
        if self.funded_total() + total > self.ceiling:
            raise Refusal("plan exceeds the stop ceiling")
        out = {
            "funding_source": source,
            "plan": plan,
            "total_nanotos": total,
            "stop_ceiling_nanotos": self.ceiling,
            "tool": "testnet-elections.py owner-fund --name node-4 --new --dry-run first",
        }
        self.plan_path.write_text(json.dumps(out, indent=2) + "\n")
        return out

    def funding_source(self) -> str:
        if not self.plan_path.exists():
            raise Refusal("funding-plan.json missing; run plan-funding first")
        return norm_addr(json.loads(self.plan_path.read_text())["funding_source"])

    def record_funding(self, actor: str, amount: str, operation_id: str) -> dict:
        address = self.actor_address(actor)
        nanotos = tos_to_nanotos(amount)
        if nanotos <= 0:
            raise Refusal("amount must be positive")
        if self.funded_total() + nanotos > self.ceiling:
            raise Refusal(
                f"recording {amount} TOS would exceed the stop ceiling "
                f"{nanotos_text(self.ceiling)} (funded {nanotos_text(self.funded_total())})"
            )
        if self.ledger_path.exists():
            for line in self.ledger_path.read_text().splitlines():
                if json.loads(line)["operation_id"] == operation_id:
                    raise Refusal(f"operation {operation_id} already recorded")
        balances = {
            url: int(self.rpc.info(address, url)["balance"]) for url in self.rpc.all_sources
        }
        if min(balances.values()) < nanotos:
            raise Refusal(f"credit not visible on every source yet: {balances}")
        row = {
            "utc": utc(now()),
            "actor": actor,
            "to": address,
            "amount_nanotos": nanotos,
            "operation_id": operation_id,
            "balances_nanotos": balances,
        }
        with self.ledger_path.open("a") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
        self.journal.log(kind="funding-recorded", **row)
        return row

    def activate(self) -> dict:
        self.preflight()
        actors = self.actors()
        out = {}
        for wallet, address in actors["wallets"].items():
            state = self.rpc.state(address)
            if state == "active":
                out[wallet] = "already-active"
                continue
            if self.rpc.balance(address) < tos_to_nanotos("0.05"):
                out[wallet] = "unfunded"
                continue
            label = f"activate-{wallet}"
            if self.journal.attempted(label):
                raise Refusal(f"{label} was attempted before and the wallet is {state}")
            self.guards()
            self.journal.attempt(label, {"kind": "wallet-activate", "address": address})
            rc, _ = self.cli.run(label, "wallet", "activate", "-n", wallet)
            ok = rc == 0 and self.wait(lambda: self.rpc.state(address) == "active")
            self.journal.done(label, {"exit_code": rc, "active": ok})
            if not ok:
                raise Refusal(f"{label}: wallet did not become active")
            out[wallet] = "activated"
        return out

    # ----- generic value step -------------------------------------------------------------
    def wait(self, predicate, timeout: float | None = None) -> bool:
        deadline = time.monotonic() + (SETTLE_TIMEOUT_S if timeout is None else timeout)
        while True:
            try:
                if predicate():
                    return True
            except Refusal:
                pass
            if time.monotonic() >= deadline:
                return False
            time.sleep(POLL_S)

    def external_arrivals(self, observe: str, since_lt: int, url: str | None = None) -> list[dict]:
        """Transactions of `observe` after `since_lt` that were triggered by an external message
        (a command signed for the contract itself, not sent by another account)."""
        return [
            r
            for r in self.rpc.transactions_after(observe, since_lt, url)
            if (r.get("in_msg") or {}).get("kind") == "external"
        ]

    def sends_to(self, payer: str, since_lt: int, observe: str | None) -> list[dict]:
        """Payer transactions after `since_lt` that carry a message to `observe` (any, if None)."""
        rows = self.rpc.transactions_after(payer, since_lt)
        if observe is None:
            return [r for r in rows if r.get("out_msgs")]
        return [
            r
            for r in rows
            if any(same_addr(m.get("destination"), observe) for m in r.get("out_msgs", []))
        ]

    def step(
        self,
        label: str,
        argv: list[str],
        payer: str,
        observe: str | None,
        expect_exit: int = 0,
        want_json: bool = False,
        show=None,
        external: bool = False,
    ) -> dict:
        """One CLI action that sends exactly one message from `payer` (an actor wallet).

        `external=True` for a command the CLI signs for the contract itself: no wallet sends
        anything, the proof is the single new transaction of `observe` with an external
        in-message after the baseline (`payer` is then the contract, for its balance).

        `observe` is the contract address whose next transaction must be the message from
        `payer` (None for a deploy whose address is only known from the CLI answer).
        `expect_exit` 0 = must succeed; another code = must abort with exactly that compute exit
        code while the protected state read by `show` stays unchanged.
        """
        previous = self.journal.result(label)
        if previous:
            if previous.get("verdict") in REPLAYABLE:
                previous.setdefault("label", label)
                return previous
            raise Refusal(
                f"step {label!r} already ended with verdict {previous.get('verdict')!r}; "
                "it is never re-sent"
            )
        if self.journal.attempted(label):
            raise Refusal(f"step {label!r} was attempted without a result; reconcile read-only")
        self.guards()
        before = {
            "head": self.rpc.head(),
            "payer_lt": self.rpc.last_lt(payer),
            "payer_balance": self.rpc.balance(payer),
            "observe_lt": self.rpc.last_lt(observe) if observe else None,
            "observe_balance": self.rpc.balance(observe) if observe else None,
            "state": show() if show else None,
        }
        base = {
            "label": label,
            "argv": self.cli.redact(tuple(argv)),
            "payer": payer,
            "observe": observe,
            "external": external,
            "expect_exit": expect_exit,
            "before": before,
        }
        if os.environ.get("SC_DRILL_CRASH") == label:
            self.journal.attempt(label, {"kind": "drill", **base})
            raise SystemExit(f"drill: process lost after the attempt marker of {label}")
        self.journal.attempt(label, {"kind": "value", **base})
        rc, answer = self.cli.run(label, *argv, want_json=want_json)
        record: dict = {"exit_code": rc, **base}
        if want_json and rc == 0 and isinstance(answer, dict):
            record["answer"] = {
                k: v for k, v in answer.items() if k in ("address", "request_id", "status")
            }
            answered = answer.get("address")
            observe = observe or (norm_addr(answered) if answered else None)
            record["observe"] = observe
        if rc != 0:
            # The CLI refused, timed out or crashed. Watch the payer for a bounded window: a
            # message that was broadcast anyway makes the outcome unknown. Never retry.
            sent: list[dict] = []

            def broadcast() -> bool:
                if external:
                    sent[:] = self.external_arrivals(observe, before["observe_lt"] or 0)
                else:
                    sent[:] = self.sends_to(payer, before["payer_lt"], observe)
                return bool(sent)

            self.wait(broadcast, REFUSAL_OBSERVE_S)
            record["payer_tx_after"] = [r["transaction_id"] for r in sent]
            if rc is not None and len(sent) == 1 and observe:
                # The CLI broadcast the message and then reported the contract's own failure
                # (or its own) with a non-zero exit. Exactly one message is on chain, so the
                # contract transaction decides exactly as for a clean exit.
                record["cli_reported_failure"] = True
            elif sent or rc is None:
                record["verdict"] = "unknown"
            elif expect_exit != 0:
                # A negative control the CLI already refuses client-side: nothing was sent, the
                # protected state is unchanged, but no on-chain refusal row exists for it.
                record["after"] = {"state": show() if show else None}
                record["verdict"] = (
                    "cli-refused-before-broadcast"
                    if record["after"]["state"] == before["state"]
                    else "refusal-control-failed"
                )
            else:
                record["verdict"] = "cli-refused"
            if "verdict" in record:
                self.journal.done(label, record)
                if record["verdict"] == "cli-refused-before-broadcast":
                    return record
                raise Refusal(f"{label}: CLI exit {rc}; {record['verdict']}; reconciled read-only")
        found: dict = {}

        def settled() -> bool:
            if external:
                arrivals = self.external_arrivals(observe, before["observe_lt"] or 0)
                if len(arrivals) > 1:
                    found["error"] = f"{len(arrivals)} external messages reached {observe}"
                    return True
                if not arrivals:
                    return False
                found["payer_tx"] = None
                found["tx"] = arrivals[0]
                return True
            sends = self.sends_to(payer, before["payer_lt"], observe)
            if len(sends) > 1:
                found["error"] = f"payer sent {len(sends)} messages to {observe}"
                return True
            if not sends or not observe:
                return False
            out_hash = [
                m["hash"] for m in sends[0]["out_msgs"] if same_addr(m.get("destination"), observe)
            ][0]
            rows = self.rpc.transactions_after(observe, before["observe_lt"] or 0)
            hit = [r for r in rows if (r.get("in_msg") or {}).get("hash") == out_hash]
            if not hit:
                return False
            found["payer_tx"] = sends[0]
            found["tx"] = hit[0]
            return True

        observed = self.wait(settled)
        if "error" in found:
            record["verdict"] = "multiple-sends-observed"
            record["error"] = found["error"]
            self.journal.done(label, record)
            raise Refusal(f"{label}: {found['error']}; stop and reconcile by hand")
        if not observed:
            record["verdict"] = "unknown-not-observed"
            self.journal.done(label, record)
            raise Refusal(f"{label}: the exact message was not observed in time; no retry")
        tx = found["tx"]
        compute = tx.get("compute") or {}
        action = tx.get("action")
        confirmations = {}
        for url in self.rpc.confirms:
            confirmations[url] = self.wait(
                lambda u=url: any(
                    r["transaction_id"]["hash"] == tx["transaction_id"]["hash"]
                    for r in self.rpc.transactions_after(observe, before["observe_lt"] or 0, u)
                )
            )
        after_state = show() if show else None
        record.update(
            {
                "payer_tx": (found["payer_tx"] or {}).get("transaction_id"),
                "tx": tx["transaction_id"],
                "block_id": tx.get("block_id"),
                "compute": compute,
                "aborted": tx.get("aborted"),
                "action": action,
                "in_msg_hash": (tx.get("in_msg") or {}).get("hash"),
                "out_msgs": [
                    {k: m.get(k) for k in ("destination", "value", "bounced", "hash")}
                    for m in tx.get("out_msgs", [])
                ],
                "confirmed_on": confirmations,
                "after": {
                    "head": self.rpc.head(),
                    "payer_balance": self.rpc.balance(payer),
                    "observe_balance": self.rpc.balance(observe),
                    "state": after_state,
                },
            }
        )
        if not all(confirmations.values()):
            record["verdict"] = "not-confirmed-on-all-sources"
            self.journal.done(label, record)
            raise Refusal(f"{label}: transaction not seen on every confirmation source")
        if expect_exit == 0:
            how = self.positive_outcome(
                tx, before["observe_balance"] or 0, record["after"]["observe_balance"]
            )
            ok = bool(how)
            record["settled_as"] = how or None
            record["verdict"] = "settled" if ok else "unexpected-abort"
        else:
            aborted = tx.get("aborted") is True and compute.get("success") is False
            code_ok = compute.get("exit_code") == expect_exit
            state_ok = show is None or before["state"] == after_state
            ok = aborted and code_ok and state_ok
            record["verdict"] = "refused-as-intended" if ok else "refusal-control-failed"
        self.journal.done(label, record)
        if not ok:
            raise Refusal(f"{label}: {record['verdict']} ({compute}, aborted={tx.get('aborted')})")
        return record

    def show(self, *argv: str):
        def read():
            rc, data = self.cli.run(f"show-{secrets.token_hex(4)}", *argv, want_json=True)
            if rc != 0 or not isinstance(data, dict):
                raise Refusal(f"show failed: {argv}")
            return data

        return read

    @staticmethod
    def transferred(record: dict, to: str, min_tos: str) -> bool:
        """Whether the step's contract transaction carried at least `min_tos` to `to` without a
        bounce; read from the record, so a replayed step gives the same answer."""
        floor = tos_to_nanotos(min_tos)
        return any(
            same_addr(m.get("destination"), to)
            and not m.get("bounced")
            and int(m.get("value") or 0) >= floor
            for m in record.get("out_msgs") or []
        )

    @staticmethod
    def argv_value(record: dict, flag: str) -> str:
        """The value that followed `flag` in the step's recorded argument vector."""
        argv = list(record.get("argv") or [])
        if flag not in argv or argv.index(flag) + 1 >= len(argv):
            raise Refusal(f"{record.get('label')}: {flag} missing from the recorded argv")
        return str(argv[argv.index(flag) + 1])

    @staticmethod
    def positive_outcome(tx: dict, before_balance: int | None, after_balance: int | None) -> str:
        """How a step that had to succeed settled: `executed`, `credited-without-compute`
        (a plain value transfer to an account without code: compute phase skipped, nothing
        bounced, the balance grew) or `` when neither holds."""
        compute = tx.get("compute") or {}
        action = tx.get("action")
        action_ok = action is None or action.get("success") is not False
        if (
            compute.get("success") is True
            and compute.get("exit_code") == 0
            and tx.get("aborted") is False
            and action_ok
        ):
            return "executed"
        if (
            compute.get("skipped") is True
            and not tx.get("out_msgs")
            and before_balance is not None
            and after_balance is not None
            and after_balance > before_balance
        ):
            return "credited-without-compute"
        return ""

    @staticmethod
    def verdict(final_ok: bool, controls: list[dict]) -> dict:
        """A control passes with an on-chain refusal, or with a client-side refusal only where
        the case declared that the protected property is enforced by the CLI (no contract row
        can exist); such controls are listed separately so the report stays explicit."""

        def passed(c: dict) -> bool:
            if c.get("verdict") == "refused-as-intended":
                return True
            return c.get("verdict") == "cli-refused-before-broadcast" and bool(
                c.get("client_side_refusal_accepted")
            )

        without = [c["label"] for c in controls if not passed(c)]
        client_side = [
            c["label"] for c in controls if passed(c) and c.get("verdict") != "refused-as-intended"
        ]
        return {
            "final_state_ok": final_ok,
            "controls": {c["label"]: c.get("verdict") for c in controls},
            "controls_refused_client_side": client_side,
            "controls_without_on_chain_receipt": without,
            "pass": bool(final_ok) and not without,
        }

    # ----- cases --------------------------------------------------------------------------
    CASES = ("sc02", "sc03", "sc04", "sc05", "sc06", "sc07", "sc08")

    def case_fn(self, name: str):
        fn = getattr(self, f"case_{name}", None)
        if name not in self.CASES or fn is None:
            raise Refusal(f"unknown case {name}; known: {self.CASES}")
        return fn

    def plan(self, name: str) -> list[dict]:
        """The CLI argument vectors a case will issue, produced by a dry pass without any send."""
        planner = PlanRunner(self.args, self.actors()["wallets"])
        planner.case_fn(name)(planner.wallets)
        return planner.recorded

    def check_flags(self, planned: list[dict], flags: dict) -> None:
        """Every `--flag` and `--operation` value of a plan exists in the pinned CLI's help."""
        if flags.get("cli_sha256") != self.args.cli_sha256:
            raise Refusal("flag fixture was recorded from a different CLI binary")
        for item in planned:
            argv = item["argv"]
            path = " ".join(argv[:3]) if argv[0] == "agent" else " ".join(argv[:2])
            known = flags["commands"].get(path)
            if not known:
                raise Refusal(f"{item['label']}: command {path!r} is not in the flag fixture")
            for i, token in enumerate(argv):
                if token.startswith("--") and token not in known["flags"]:
                    raise Refusal(f"{item['label']}: {path} does not accept {token}")
                if token == "--operation":
                    values = {
                        v.strip() for group in known["possible_values"] for v in group.split(",")
                    }
                    if values and argv[i + 1] not in values:
                        raise Refusal(f"{item['label']}: {path} has no operation {argv[i + 1]}")

    def case(self, name: str) -> dict:
        self.preflight()
        planned = self.plan(name)
        if not self.args.flag_fixture:
            raise Refusal("a case runs only against the pinned CLI flag fixture (--flag-fixture)")
        self.check_flags(planned, pinned_flags(Path(self.args.flag_fixture)))
        self.journal.log(kind="case-start", case=name, planned_steps=[p["label"] for p in planned])
        result = self.case_fn(name)(self.actors()["wallets"])
        (self.evidence / f"{name}-RESULT.json").write_text(
            json.dumps({"case": name, "utc": utc(now()), **result}, indent=2, sort_keys=True) + "\n"
        )
        return result

    def wait_active(self, address: str, what: str) -> None:
        if not self.wait(lambda: self.rpc.state(address) == "active"):
            raise Refusal(f"{what} at {address} is not active")

    def case_sc07(self, w: dict) -> dict:
        owner, outsider = w["sc-owner"], w["sc-outsider"]
        deploy = self.step(
            "sc07-deploy",
            [
                "agent",
                "attestation",
                "deploy",
                "--name",
                "sc07",
                "--owner",
                owner,
                "--signer-vault-key",
                "sc-attestor-key",
                "--subject-hash",
                HASH["subject"],
                "--from",
                "sc-owner",
                "--amount",
                "0.1",
                "-w",
                "0",
                "--yes",
            ],
            payer=owner,
            observe=None,
            want_json=True,
        )
        address = deploy["observe"]
        show = self.show("agent", "attestation", "show", "--name", "sc07")
        self.wait_active(address, "sc07 attestation")
        send = ["agent", "attestation", "send", "--name", "sc07", "--yes", "--amount", "0.1"]
        controls = []
        self.step(
            "sc07-attest-valid",
            send
            + [
                "--operation",
                "attest",
                "--from",
                "sc-outsider",
                "--attested-hash",
                HASH["attested_1"],
                "--signer-vault-key",
                "sc-attestor-key",
            ],
            payer=outsider,
            observe=address,
            show=show,
        )
        controls.append(
            self.step(
                "sc07-attest-wrong-key",
                send
                + [
                    "--operation",
                    "attest",
                    "--from",
                    "sc-outsider",
                    "--attested-hash",
                    HASH["attested_2"],
                    "--signer-vault-key",
                    "sc-wrong-key",
                ],
                payer=outsider,
                observe=address,
                expect_exit=ATTEST_BAD_SIGNATURE,
                show=show,
            )
        )
        controls.append(
            self.step(
                "sc07-rotate-outsider",
                send
                + [
                    "--operation",
                    "rotate-key",
                    "--from",
                    "sc-outsider",
                    "--new-signer-vault-key",
                    "sc-rotated-attestor-key",
                ],
                payer=outsider,
                observe=address,
                expect_exit=ATTEST_NOT_OWNER,
                show=show,
            )
        )
        self.step(
            "sc07-rotate-owner",
            send
            + [
                "--operation",
                "rotate-key",
                "--from",
                "sc-owner",
                "--new-signer-vault-key",
                "sc-rotated-attestor-key",
            ],
            payer=owner,
            observe=address,
            show=show,
        )
        controls.append(
            self.step(
                "sc07-revoke-outsider",
                send + ["--operation", "revoke", "--from", "sc-outsider"],
                payer=outsider,
                observe=address,
                expect_exit=ATTEST_NOT_OWNER,
                show=show,
            )
        )
        self.step(
            "sc07-revoke-owner",
            send + ["--operation", "revoke", "--from", "sc-owner"],
            payer=owner,
            observe=address,
            show=show,
        )
        final = show()
        final_ok = final.get("revoked") is True and final.get("has_attestation") is False
        return {"address": address, "final_state": final, **self.verdict(final_ok, controls)}

    def case_sc04(self, w: dict) -> dict:
        owner, client, outsider = w["sc-owner"], w["sc-client"], w["sc-outsider"]
        deploy = self.step(
            "sc04-deploy",
            [
                "agent",
                "service",
                "deploy",
                "--name",
                "sc04",
                "--owner",
                owner,
                "--price-per-call",
                "0.05",
                "--storage-fee",
                "0.2",
                "--cleanup-bounty",
                "0.1",
                "--response-sla",
                "3600",
                "--refund-claim-window",
                "3600",
                "--rate-limit-per-day",
                "0",
                "--metadata-hash",
                HASH["metadata"],
                "--proof-scheme-hash",
                HASH["proof_scheme"],
                "--authorized-caller",
                client,
                "--signer-vault-key",
                "sc-attestor-key",
                "--from",
                "sc-owner",
                "--amount",
                SERVICE_MIN_DEPLOY_TOS,
                "-w",
                "0",
                "--yes",
            ],
            payer=owner,
            observe=None,
            want_json=True,
        )
        address = deploy["observe"]
        show = self.show("agent", "service", "show", "--name", "sc04")
        self.wait_active(address, "sc04 service")
        # Message values are left to the CLI, which quotes them from the on-chain policy
        # (price + storage fee + admission allowance for a call, payout allowance otherwise).
        send = ["agent", "service", "send", "--name", "sc04", "--yes"]
        controls = []
        controls.append(
            self.step(
                "sc04-call-outsider",
                send
                + [
                    "--operation",
                    "call",
                    "--from",
                    "sc-outsider",
                    "--request-hash",
                    HASH["request_2"],
                ],
                payer=outsider,
                observe=address,
                expect_exit=SERVICE_NOT_AUTHORIZED,
                show=show,
            )
        )
        self.step(
            "sc04-call-client",
            send
            + ["--operation", "call", "--from", "sc-client", "--request-hash", HASH["request_1"]],
            payer=client,
            observe=address,
            show=show,
        )
        state = show()
        if "next_request_id" not in state:
            raise Refusal("service view has no next_request_id")
        request_id = str(int(state["next_request_id"]) - 1)
        controls.append(
            self.step(
                "sc04-respond-outsider",
                send
                + [
                    "--operation",
                    "respond",
                    "--from",
                    "sc-outsider",
                    "--request-id",
                    request_id,
                    "--response-hash",
                    HASH["response"],
                    "--signer-vault-key",
                    "sc-attestor-key",
                ],
                payer=outsider,
                observe=address,
                expect_exit=SERVICE_NOT_OWNER,
                show=show,
            )
        )
        self.step(
            "sc04-respond-owner",
            send
            + [
                "--operation",
                "respond",
                "--from",
                "sc-owner",
                "--request-id",
                request_id,
                "--response-hash",
                HASH["response"],
                "--signer-vault-key",
                "sc-attestor-key",
            ],
            payer=owner,
            observe=address,
            show=show,
        )
        controls.append(
            self.step(
                "sc04-withdraw-outsider",
                send
                + [
                    "--operation",
                    "withdraw-revenue",
                    "--from",
                    "sc-outsider",
                    "--withdraw-amount",
                    "0.01",
                ],
                payer=outsider,
                observe=address,
                expect_exit=SERVICE_NOT_OWNER,
                show=show,
            )
        )
        withdrawable = state_nanotos(show().get("withdrawable_revenue"))
        if withdrawable <= 0:
            raise Refusal("no withdrawable revenue after the answered call")
        amount = nanotos_text(min(withdrawable, SERVICE_WITHDRAW_CAP))
        self.step(
            "sc04-withdraw-owner",
            send
            + [
                "--operation",
                "withdraw-revenue",
                "--from",
                "sc-owner",
                "--withdraw-amount",
                amount,
            ],
            payer=owner,
            observe=address,
            show=show,
        )
        final = show()
        final_ok = int(final.get("pending_count", -1)) == 0 and state_nanotos(
            final.get("withdrawable_revenue")
        ) == withdrawable - tos_to_nanotos(amount)
        return {
            "address": address,
            "request_id": request_id,
            "withdrawn_tos": amount,
            "final_state": final,
            **self.verdict(final_ok, controls),
        }

    def task_create_argv(self, name: str, w: dict) -> list[str]:
        return [
            "agent",
            "task",
            "create",
            "--name",
            name,
            "--creator",
            w["sc-owner"],
            "--agent",
            w["sc-client"],
            "--verifier",
            w["sc-verifier"],
            "--budget",
            "1",
            "--deadline",
            str(now() + TASK_HORIZON_S),
            "--review-period",
            str(TASK_MIN_REVIEW_PERIOD_S),
            "--policy-hash",
            HASH["policy"],
            "--from",
            "sc-owner",
            "--amount",
            "1.3",
            "-w",
            "0",
            "--yes",
        ]

    def case_sc05(self, w: dict) -> dict:
        creator, agent = w["sc-owner"], w["sc-client"]
        deploy = self.step(
            "sc05-create",
            self.task_create_argv("sc05", w),
            payer=creator,
            observe=None,
            want_json=True,
        )
        address = deploy["observe"]
        show = self.show("agent", "task", "show", "--name", "sc05")
        self.wait_active(address, "sc05 task")
        # Task message values are quoted by the CLI from the escrow's fee schedule.
        send = ["agent", "task", "send", "--name", "sc05", "--yes"]
        controls = []
        controls.append(
            self.step(
                "sc05-accept-creator",
                send + ["--operation", "accept", "--from", "sc-owner"],
                payer=creator,
                observe=address,
                expect_exit=TASK_ACCEPT_NOT_AGENT,
                show=show,
            )
        )
        self.step(
            "sc05-accept-agent",
            send + ["--operation", "accept", "--from", "sc-client"],
            payer=agent,
            observe=address,
            show=show,
        )
        self.step(
            "sc05-result-agent",
            send
            + [
                "--operation",
                "result",
                "--from",
                "sc-client",
                "--result-hash",
                HASH["result"],
                "--evidence-hash",
                HASH["evidence"],
            ],
            payer=agent,
            observe=address,
            show=show,
        )
        controls.append(
            self.step(
                "sc05-settle-agent",
                send + ["--operation", "settle", "--from", "sc-client", "--payout", "0.6"],
                payer=agent,
                observe=address,
                expect_exit=TASK_SETTLE_AUTHORITY,
                show=show,
            )
        )
        agent_before = self.rpc.balance(agent)
        self.step(
            "sc05-settle-creator",
            send + ["--operation", "settle", "--from", "sc-owner", "--payout", "0.6"],
            payer=creator,
            observe=address,
            show=show,
        )
        paid = self.wait(lambda: self.rpc.balance(agent) >= agent_before + tos_to_nanotos("0.59"))
        final = show()
        final_ok = final.get("status") == "settled" and paid
        return {
            "address": address,
            "final_state": final,
            "agent_paid": paid,
            **self.verdict(final_ok, controls),
        }

    def case_sc06(self, w: dict) -> dict:
        claimant, respondent, reviewer, outsider = (
            w["sc-client"],
            w["sc-respondent"],
            w["sc-verifier"],
            w["sc-outsider"],
        )
        deploy = self.step(
            "sc06-deploy",
            [
                "agent",
                "dispute",
                "deploy",
                "--name",
                "sc06",
                "--claimant",
                claimant,
                "--respondent",
                respondent,
                "--reviewer",
                reviewer,
                "--deadline",
                str(now() + TASK_HORIZON_S),
                "--subject-hash",
                HASH["subject"],
                "--claimant-evidence-hash",
                HASH["claimant_evidence"],
                "--from",
                "sc-client",
                "--amount",
                "0.1",
                "-w",
                "0",
                "--yes",
            ],
            payer=claimant,
            observe=None,
            want_json=True,
        )
        address = deploy["observe"]
        show = self.show("agent", "dispute", "show", "--name", "sc06")
        self.wait_active(address, "sc06 dispute")
        send = ["agent", "dispute", "send", "--name", "sc06", "--yes", "--amount", "0.1"]
        controls = []
        controls.append(
            self.step(
                "sc06-evidence-outsider",
                send
                + [
                    "--operation",
                    "submit-respondent-evidence",
                    "--from",
                    "sc-outsider",
                    "--respondent-evidence-hash",
                    HASH["respondent_evidence"],
                ],
                payer=outsider,
                observe=address,
                expect_exit=DISPUTE_NOT_RESPONDENT,
                show=show,
            )
        )
        self.step(
            "sc06-evidence-respondent",
            send
            + [
                "--operation",
                "submit-respondent-evidence",
                "--from",
                "sc-respondent",
                "--respondent-evidence-hash",
                HASH["respondent_evidence"],
            ],
            payer=respondent,
            observe=address,
            show=show,
        )
        controls.append(
            self.step(
                "sc06-rule-outsider",
                send
                + [
                    "--operation",
                    "rule",
                    "--from",
                    "sc-outsider",
                    "--ruling",
                    "claimant",
                    "--ruling-hash",
                    HASH["ruling"],
                ],
                payer=outsider,
                observe=address,
                expect_exit=DISPUTE_NOT_REVIEWER,
                show=show,
            )
        )
        self.step(
            "sc06-rule-reviewer",
            send
            + [
                "--operation",
                "rule",
                "--from",
                "sc-verifier",
                "--ruling",
                "claimant",
                "--ruling-hash",
                HASH["ruling"],
            ],
            payer=reviewer,
            observe=address,
            show=show,
        )
        controls.append(
            self.step(
                "sc06-rule-again",
                send
                + [
                    "--operation",
                    "rule",
                    "--from",
                    "sc-verifier",
                    "--ruling",
                    "respondent",
                    "--ruling-hash",
                    HASH["ruling"],
                ],
                payer=reviewer,
                observe=address,
                expect_exit=DISPUTE_ALREADY_RESOLVED,
                show=show,
            )
        )
        final = show()
        final_ok = final.get("status") == "resolved" and final.get("ruling") == "claimant"
        return {"address": address, "final_state": final, **self.verdict(final_ok, controls)}

    def case_sc02(self, w: dict) -> dict:
        owner, verifier, outsider = w["sc-owner"], w["sc-verifier"], w["sc-outsider"]
        deploy = self.step(
            "sc02-deploy",
            [
                "agent",
                "registry",
                "deploy",
                "--name",
                "sc02",
                "--owner",
                owner,
                "--verifier",
                verifier,
                "--task-categories-hash",
                HASH["task_categories"],
                "--pricing-hash",
                HASH["pricing"],
                "--metadata-hash",
                HASH["metadata"],
                "--verification-method-hash",
                HASH["verification_method"],
                "--bond",
                "0.5",
                "--from",
                "sc-owner",
                "--amount",
                "0.7",
                "-w",
                "0",
                "--yes",
            ],
            payer=owner,
            observe=None,
            want_json=True,
        )
        address = deploy["observe"]
        show = self.show("agent", "registry", "show", "--name", "sc02")
        self.wait_active(address, "sc02 registry")
        send = ["agent", "registry", "send", "--name", "sc02", "--yes", "--amount", "0.1"]
        meta = [
            "--task-categories-hash",
            HASH["task_categories"],
            "--pricing-hash",
            HASH["pricing"],
            "--metadata-hash",
            HASH["new_metadata"],
            "--verification-method-hash",
            HASH["verification_method"],
        ]
        controls = []
        controls.append(
            self.step(
                "sc02-update-outsider",
                send + ["--operation", "update-metadata", "--from", "sc-outsider"] + meta,
                payer=outsider,
                observe=address,
                expect_exit=REGISTRY_NOT_OWNER,
                show=show,
            )
        )
        self.step(
            "sc02-update-owner",
            send + ["--operation", "update-metadata", "--from", "sc-owner"] + meta,
            payer=owner,
            observe=address,
            show=show,
        )
        controls.append(
            self.step(
                "sc02-reputation-outsider",
                send
                + ["--operation", "update-reputation", "--from", "sc-outsider", "--delta", "10"],
                payer=outsider,
                observe=address,
                expect_exit=REGISTRY_NOT_VERIFIER,
                show=show,
            )
        )
        self.step(
            "sc02-reputation-verifier",
            send + ["--operation", "update-reputation", "--from", "sc-verifier", "--delta", "10"],
            payer=verifier,
            observe=address,
            show=show,
        )
        controls.append(
            self.step(
                "sc02-overdraw-bond",
                send
                + [
                    "--operation",
                    "withdraw-bond",
                    "--from",
                    "sc-owner",
                    "--withdraw-amount",
                    "100",
                ],
                payer=owner,
                observe=address,
                expect_exit=REGISTRY_INSUFFICIENT_BOND,
                show=show,
            )
        )
        self.step(
            "sc02-withdraw-bond",
            send
            + ["--operation", "withdraw-bond", "--from", "sc-owner", "--withdraw-amount", "0.3"],
            payer=owner,
            observe=address,
            show=show,
        )
        self.step(
            "sc02-deactivate",
            send + ["--operation", "deactivate", "--from", "sc-owner"],
            payer=owner,
            observe=address,
            show=show,
        )
        final = show()
        final_ok = final.get("active") is False and int(final.get("reputation_score", -1)) == 10
        return {"address": address, "final_state": final, **self.verdict(final_ok, controls)}

    def case_sc03(self, w: dict) -> dict:
        owner, target = w["sc-owner"], w["sc-verifier"]
        self.local(
            "sc03-agent-wallet-create",
            "agent",
            "wallet",
            "create",
            "-n",
            "sc03-agent",
            "-v",
            "V5R1",
            "-w",
            "0",
            "--max-per-tx",
            "0.5",
            "--daily-limit",
            "2",
        )
        deploy = self.step(
            "sc03-account-deploy",
            [
                "agent",
                "account",
                "deploy",
                "--wallet",
                "sc03-agent",
                "--from",
                "sc-owner",
                "-w",
                "0",
                "--amount",
                "0.5",
                "--yes",
            ],
            payer=owner,
            observe=None,
            want_json=True,
        )
        account = deploy["observe"]
        profile = self.local(
            "sc03-agent-wallet-show", "agent", "wallet", "show", "-n", "sc03-agent", want_json=True
        )
        answered = (profile or {}).get("address") or ((profile or {}).get("result") or {}).get(
            "address"
        )
        agent_wallet = norm_addr(answered)
        self.step(
            "sc03-agent-wallet-fund",
            [
                "agent",
                "wallet",
                "fund",
                "--name",
                "sc03-agent",
                "--from",
                "sc-owner",
                "--amount",
                "0.5",
                "--yes",
            ],
            payer=owner,
            observe=agent_wallet,
        )
        if self.rpc.state(agent_wallet) != "active":
            self.local(
                "sc03-agent-wallet-activate", "agent", "wallet", "activate", "-n", "sc03-agent"
            )
            self.wait_active(agent_wallet, "sc03 agent wallet")
        first = self.step(
            "sc03-task-send-1",
            [
                "agent",
                "account",
                "task-send",
                "--wallet",
                "sc03-agent",
                "--target",
                target,
                "--value",
                "0.1",
                "--valid-until",
                str(now() + 300),
                "--action-id",
                secrets.token_hex(32),
                "--yes",
            ],
            payer=account,
            observe=account,
            external=True,
        )
        # Replay-safe: the delivery and the action id to replay come from the step's own record.
        delivered = self.transferred(first, target, "0.09")
        action_1 = self.argv_value(first, "--action-id")
        # Replaying the same action id must not execute a second transfer. The CLI refuses it
        # client-side from its custody journal (the account contract stores no action id), so
        # no on-chain row is expected; a second successful transfer is the failure.
        duplicate = self.duplicate_control(
            "sc03-task-send-1-duplicate",
            [
                "agent",
                "account",
                "task-send",
                "--wallet",
                "sc03-agent",
                "--target",
                target,
                "--value",
                "0.1",
                "--valid-until",
                str(now() + 300),
                "--action-id",
                action_1,
                "--yes",
            ],
            account,
            account,
            target,
            external=True,
        )
        self.local(
            "sc03-policy-local",
            "agent",
            "wallet",
            "update-policy",
            "-n",
            "sc03-agent",
            "--max-per-tx",
            "0.2",
            "--daily-limit",
            "1",
        )
        self.step(
            "sc03-update-policy",
            [
                "agent",
                "account",
                "update-policy",
                "--wallet",
                "sc03-agent",
                "--amount",
                "0.05",
                "--yes",
            ],
            payer=agent_wallet,
            observe=account,
        )
        self.local("sc03-rotate-local", "agent", "wallet", "rotate-controller", "-n", "sc03-agent")
        self.step(
            "sc03-rotate-controller",
            [
                "agent",
                "account",
                "rotate-controller",
                "--wallet",
                "sc03-agent",
                "--amount",
                "0.05",
                "--yes",
            ],
            payer=account,
            observe=account,
            external=True,
        )
        second = self.step(
            "sc03-task-send-2",
            [
                "agent",
                "account",
                "task-send",
                "--wallet",
                "sc03-agent",
                "--target",
                target,
                "--value",
                "0.1",
                "--valid-until",
                str(now() + 300),
                "--action-id",
                secrets.token_hex(32),
                "--yes",
            ],
            payer=agent_wallet,
            observe=account,
        )
        delivered_2 = self.transferred(second, target, "0.09")
        status = self.local(
            "sc03-status", "agent", "account", "status", "--wallet", "sc03-agent", want_json=True
        )
        final_ok = bool(delivered and delivered_2 and duplicate["verdict"] != "DUPLICATE-EXECUTED")
        return {
            "account": account,
            "agent_wallet": agent_wallet,
            "status": status,
            "first_transfer_delivered": delivered,
            "transfer_after_rotation_delivered": delivered_2,
            **self.verdict(final_ok, [duplicate]),
        }

    def duplicate_control(
        self,
        label: str,
        argv: list[str],
        payer: str,
        account: str,
        target: str,
        external: bool = False,
    ) -> dict:
        """Replay of an already executed action id: it must not pay the target a second time.

        The proof is the exact on-chain row, as in `step()`: the agent wallet's message to the
        account and the account transaction it produced. An aborted account transaction is the
        intended refusal and its exit code is recorded; a CLI refusal with no send is recorded
        as client-side (no on-chain row); a second transfer is the failure. A missing row is an
        unknown that stops the case, never a pass.
        """
        duplicate = self.journal.result(label)
        if duplicate is not None:
            if duplicate.get("verdict") not in REPLAYABLE:
                raise Refusal(f"{label} ended {duplicate.get('verdict')!r}; reconcile read-only")
            duplicate.setdefault("label", label)
            return duplicate
        if self.journal.attempted(label):
            raise Refusal(f"{label} was attempted without a result; reconcile read-only")
        self.guards()
        before = {
            "payer_lt": self.rpc.last_lt(payer),
            "observe_lt": self.rpc.last_lt(account),
            "target_balance": self.rpc.balance(target),
        }
        record: dict = {
            "argv": self.cli.redact(tuple(argv)),
            "payer": payer,
            "observe": account,
            "external": external,
            "target": target,
            "before": before,
        }
        self.journal.attempt(label, {"kind": "value", **record})
        rc, _ = self.cli.run(label, *argv)
        record["exit_code"] = rc
        paid_at = before["target_balance"] + tos_to_nanotos("0.09")

        def finish(verdict: str) -> dict:
            record["target_paid_again"] = self.rpc.balance(target) >= paid_at
            record["client_side_refusal_accepted"] = True
            record["verdict"] = verdict
            self.journal.done(label, record)
            record["label"] = label
            return record

        if rc != 0:
            sent: list[dict] = []

            def broadcast() -> bool:
                if external:
                    sent[:] = self.external_arrivals(account, before["observe_lt"])
                else:
                    sent[:] = self.sends_to(payer, before["payer_lt"], account)
                return bool(sent)

            self.wait(broadcast, REFUSAL_OBSERVE_S)
            record["payer_tx_after"] = [r["transaction_id"] for r in sent]
            if sent or rc is None:
                finish("unknown")
                raise Refusal(f"{label}: CLI exit {rc} but a message left the wallet; reconcile")
            if self.rpc.balance(target) >= paid_at:
                return finish("DUPLICATE-EXECUTED")
            return finish("cli-refused-before-broadcast")
        found: dict = {}

        def settled() -> bool:
            if external:
                arrivals = self.external_arrivals(account, before["observe_lt"])
                if len(arrivals) > 1:
                    found["error"] = f"{len(arrivals)} external messages reached {account}"
                    return True
                if not arrivals:
                    return False
                found["payer_tx"] = None
                found["tx"] = arrivals[0]
                return True
            sends = self.sends_to(payer, before["payer_lt"], account)
            if len(sends) > 1:
                found["error"] = f"payer sent {len(sends)} messages to {account}"
                return True
            if not sends:
                return False
            out_hash = [
                m["hash"] for m in sends[0]["out_msgs"] if same_addr(m.get("destination"), account)
            ][0]
            rows = self.rpc.transactions_after(account, before["observe_lt"])
            hit = [r for r in rows if (r.get("in_msg") or {}).get("hash") == out_hash]
            if not hit:
                return False
            found["payer_tx"] = sends[0]
            found["tx"] = hit[0]
            return True

        observed = self.wait(settled)
        if "error" in found:
            record["error"] = found["error"]
            finish("multiple-sends-observed")
            raise Refusal(f"{label}: {found['error']}; stop and reconcile by hand")
        if not observed:
            finish("unknown-not-observed")
            raise Refusal(f"{label}: the exact message was not observed in time; no retry")
        tx = found["tx"]
        compute = tx.get("compute") or {}
        confirmations = {
            url: self.wait(
                lambda u=url: any(
                    r["transaction_id"]["hash"] == tx["transaction_id"]["hash"]
                    for r in self.rpc.transactions_after(account, before["observe_lt"], u)
                )
            )
            for url in self.rpc.confirms
        }
        transferred = [
            {k: m.get(k) for k in ("destination", "value", "bounced", "hash")}
            for m in tx.get("out_msgs", [])
            if same_addr(m.get("destination"), target)
        ]
        record.update(
            {
                "payer_tx": (found["payer_tx"] or {}).get("transaction_id"),
                "tx": tx["transaction_id"],
                "block_id": tx.get("block_id"),
                "compute": compute,
                "aborted": tx.get("aborted"),
                "action": tx.get("action"),
                "in_msg_hash": (tx.get("in_msg") or {}).get("hash"),
                "transfers_to_target": transferred,
                "confirmed_on": confirmations,
            }
        )
        if not all(confirmations.values()):
            finish("not-confirmed-on-all-sources")
            raise Refusal(f"{label}: transaction not seen on every confirmation source")
        if transferred or self.rpc.balance(target) >= paid_at:
            return finish("DUPLICATE-EXECUTED")
        if tx.get("aborted") is True and compute.get("success") is False:
            return finish("refused-as-intended")
        return finish("accepted-without-transfer")

    def case_sc08(self, w: dict) -> dict:
        """Integrated journey with a disputed task and the lost-reply drill.

        Run once with `SC_DRILL_CRASH=sc08-resolve-verifier`: the process exits after that
        step's attempt marker. The second run must refuse to re-send that label, prove nothing
        reached the chain after the marker, and only then issue the resolve under a new label.
        """
        creator, agent, verifier = w["sc-owner"], w["sc-client"], w["sc-verifier"]
        parts = {}
        for name in ("sc02", "sc03", "sc04", "sc05", "sc06", "sc07"):
            path = self.evidence / f"{name}-RESULT.json"
            if not path.exists():
                raise Refusal(f"sc08 needs {name} first")
            parts[name] = json.loads(path.read_text())
        deploy = self.step(
            "sc08-task-create",
            self.task_create_argv("sc08", w),
            payer=creator,
            observe=None,
            want_json=True,
        )
        address = deploy["observe"]
        show = self.show("agent", "task", "show", "--name", "sc08")
        self.wait_active(address, "sc08 task")
        send = ["agent", "task", "send", "--name", "sc08", "--yes"]
        controls = []
        self.step(
            "sc08-accept",
            send + ["--operation", "accept", "--from", "sc-client"],
            payer=agent,
            observe=address,
            show=show,
        )
        self.step(
            "sc08-result",
            send
            + [
                "--operation",
                "result",
                "--from",
                "sc-client",
                "--result-hash",
                HASH["result"],
                "--evidence-hash",
                HASH["evidence"],
            ],
            payer=agent,
            observe=address,
            show=show,
        )
        self.step(
            "sc08-dispute",
            send
            + ["--operation", "dispute", "--from", "sc-owner", "--dispute-hash", HASH["dispute"]],
            payer=creator,
            observe=address,
            show=show,
        )
        controls.append(
            self.step(
                "sc08-resolve-agent",
                send + ["--operation", "resolve", "--from", "sc-client", "--payout", "0.4"],
                payer=agent,
                observe=address,
                expect_exit=TASK_RESOLVE_AUTHORITY,
                show=show,
            )
        )
        drill = "sc08-resolve-verifier"
        resolve = send + ["--operation", "resolve", "--from", "sc-verifier", "--payout", "0.4"]
        attempt = self.journal.attempt_record(drill)
        drill_state = "not-exercised"
        if attempt and not self.journal.result(drill):
            # A marker without a result: the first run was lost after writing it. Re-send only
            # when the marker says it was the drill and nothing reached the chain after it.
            before = attempt.get("before") or {}
            after_contract = self.rpc.transactions_after(address, before.get("observe_lt") or 0)
            after_payer = self.sends_to(verifier, before.get("payer_lt") or 0, address)
            record = {
                "verdict": "lost-reply-reconciled",
                "kind": attempt.get("kind"),
                "contract_tx_after_marker": len(after_contract),
                "payer_sends_after_marker": len(after_payer),
                "re_sent": False,
            }
            if attempt.get("kind") != "drill" or after_contract or after_payer:
                record["verdict"] = "lost-reply-unresolved"
                self.journal.done(drill, record)
                raise Refusal(
                    f"{drill}: marker without result and the chain is not provably "
                    "untouched; reconcile by hand, never re-send"
                )
            self.journal.done(drill, record)
            drill_state = "reconciled"
            self.step(
                "sc08-resolve-verifier-2", resolve, payer=verifier, observe=address, show=show
            )
        else:
            self.step(drill, resolve, payer=verifier, observe=address, show=show)
        final = show()
        final_ok = final.get("status") == "settled"
        return {
            "address": address,
            "final_state": final,
            "components": {
                k: {"address": v.get("address") or v.get("account"), "pass": v.get("pass")}
                for k, v in parts.items()
            },
            "lost_reply_drill": drill_state,
            **self.verdict(final_ok, controls),
        }

    # ----- wrap-up ------------------------------------------------------------------------
    def return_funds(self, to: str) -> dict:
        self.preflight()
        to = norm_addr(to)
        source = self.funding_source()
        if to != source:
            raise Refusal(f"return destination {to} is not the recorded funding source {source}")
        actors = self.actors()["wallets"]
        out = {}
        keep = tos_to_nanotos("0.05")
        for wallet, address in actors.items():
            balance = self.rpc.balance(address)
            if balance <= keep * 2:
                out[wallet] = {"skipped": balance}
                continue
            amount = balance - keep
            rec = self.step(
                f"return-{wallet}",
                [
                    "wallet",
                    "send",
                    "--from",
                    wallet,
                    "--to",
                    to,
                    "--amount-nanotos",
                    str(amount),
                    "--bounce",
                    "--yes",
                ],
                payer=address,
                observe=to,
            )
            out[wallet] = {"returned_nanotos": amount, "tx": rec["tx"]}
        return out

    def reconcile(self, label: str, external: bool = False) -> dict:
        """Read-only reconciliation of a step that ended `unknown` or `unexpected-abort`.

        Nothing is sent. The payer's single message to the observed contract after the step's
        baseline is located, the contract transaction it produced is read and confirmed on
        every source, and the verdict follows the same rules as a live step. The original
        record is kept; the reconciliation is written beside it and replayed from then on.
        """
        self.preflight(value_action=False)
        done = self.journal.result(label)
        if done is None:
            raise Refusal(f"{label} has no record")
        if done.get("reconciled"):
            raise Refusal(f"{label} was already reconciled")
        if done.get("verdict") not in RECONCILABLE:
            raise Refusal(
                f"{label} ended {done.get('verdict')!r}; only {RECONCILABLE} are reconciled"
            )
        payer, observe = done.get("payer"), done.get("observe")
        before = done.get("before") or {}
        external = bool(done.get("external")) or external
        if not payer or not observe or "payer_lt" not in before:
            raise Refusal(f"{label} lacks payer/observe/baseline; reconcile by hand")
        if external:
            arrivals = self.external_arrivals(observe, int(before.get("observe_lt") or 0))
            if len(arrivals) != 1:
                raise Refusal(f"{label}: {len(arrivals)} external messages reached {observe}")
            sends = [None]
            tx = arrivals[0]
            out_hash = (tx.get("in_msg") or {}).get("hash")
        else:
            sends = self.sends_to(payer, int(before["payer_lt"]), observe)
            if len(sends) != 1:
                raise Refusal(f"{label}: payer sent {len(sends)} messages to {observe}; by hand")
            out_hash = [
                m["hash"] for m in sends[0]["out_msgs"] if same_addr(m.get("destination"), observe)
            ][0]
            rows = self.rpc.transactions_after(observe, int(before.get("observe_lt") or 0))
            hit = [r for r in rows if (r.get("in_msg") or {}).get("hash") == out_hash]
            if len(hit) != 1:
                raise Refusal(f"{label}: {len(hit)} contract transactions carry the message")
            tx = hit[0]
        compute = tx.get("compute") or {}
        action = tx.get("action")
        confirmations = {
            url: any(
                r["transaction_id"]["hash"] == tx["transaction_id"]["hash"]
                for r in self.rpc.transactions_after(
                    observe, int(before.get("observe_lt") or 0), url
                )
            )
            for url in self.rpc.confirms
        }
        record = dict(done)
        record.update(
            {
                "reconciled": True,
                "reconciled_from_verdict": done.get("verdict"),
                "external": external,
                "payer_tx": (sends[0] or {}).get("transaction_id"),
                "tx": tx["transaction_id"],
                "block_id": tx.get("block_id"),
                "compute": compute,
                "aborted": tx.get("aborted"),
                "action": action,
                "in_msg_hash": out_hash,
                "out_msgs": [
                    {k: m.get(k) for k in ("destination", "value", "bounced", "hash")}
                    for m in tx.get("out_msgs", [])
                ],
                "confirmed_on": confirmations,
                "state_check": "unavailable",
            }
        )
        if not all(confirmations.values()):
            raise Refusal(f"{label}: transaction not seen on every confirmation source")
        expect_exit = int(done.get("expect_exit") or 0)
        if expect_exit == 0:
            after_balance = self.rpc.balance(observe)
            record["after"] = {**(done.get("after") or {}), "observe_balance": after_balance}
            how = self.positive_outcome(tx, before.get("observe_balance") or 0, after_balance)
            record["settled_as"] = how or None
            record["verdict"] = "settled" if how else "unexpected-abort"
        else:
            ok = (
                tx.get("aborted") is True
                and compute.get("success") is False
                and compute.get("exit_code") == expect_exit
            )
            record["verdict"] = "refused-as-intended" if ok else "refusal-control-failed"
        self.journal.reconciled(label, record)
        self.journal.log(kind="reconciled", label=label, verdict=record["verdict"])
        return record

    def status(self) -> dict:
        actors = self.actors() if self.actors_path.exists() else {}
        balances = {n: self.rpc.balance(a) for n, a in actors.get("wallets", {}).items()}
        steps = sorted(p.name for p in self.journal.steps.glob("*.json"))
        return {"funded_total_nanotos": self.funded_total(), "balances": balances, "steps": steps}


class PlanRunner(Runner):
    """A dry pass over a case: records every CLI argument vector and sends nothing."""

    def __init__(self, args: argparse.Namespace, wallets: dict):
        self.args = args
        self.wallets = dict(wallets)
        self.recorded: list[dict] = []
        self.fake = "0:" + "0f" * 32

    def guards(self) -> dict:
        return {}

    def local(self, label, *argv, want_json=False):
        self.recorded.append({"label": label, "argv": list(argv), "value": False})
        return {"address": self.fake, "result": {"address": self.fake}} if want_json else None

    def step(
        self, label, argv, payer, observe, expect_exit=0, want_json=False, show=None, external=False
    ):
        self.recorded.append(
            {
                "label": label,
                "argv": list(argv),
                "value": True,
                "payer": payer,
                "external": external,
                "expect_exit": expect_exit,
            }
        )
        return {
            "label": label,
            "observe": observe or self.fake,
            "argv": list(argv),
            "verdict": "settled" if expect_exit == 0 else "refused-as-intended",
        }

    def show(self, *argv):
        return lambda: {
            "status": "settled",
            "ruling": "claimant",
            "revoked": True,
            "has_attestation": False,
            "active": False,
            "reputation_score": 10,
            "next_request_id": 1,
            "pending_count": 0,
            "withdrawable_revenue": 250_000_000,
        }

    def wait(self, predicate, timeout=None):
        return True

    def wait_active(self, address, what):
        return None

    def duplicate_control(self, label, argv, payer, account, target, external=False):
        self.recorded.append(
            {"label": label, "argv": list(argv), "value": True, "payer": payer, "expect_exit": -1}
        )
        return {"label": label, "verdict": "refused-as-intended"}

    @property
    def rpc(self):
        return _PlanRpc()

    @property
    def journal(self):
        return _PlanJournal()

    @property
    def evidence(self):
        return _PlanEvidence()


class _PlanRpc:
    def balance(self, address):
        return 10 * NANO

    def state(self, address):
        return "active"

    def last_lt(self, address, url=None):
        return 0

    def transactions_after(self, address, lt, url=None):
        return []


class _PlanJournal:
    def result(self, label):
        return None

    def attempted(self, label):
        return False

    def attempt_record(self, label):
        return None

    def attempt(self, label, record):
        return None

    def done(self, label, record):
        return None


class _PlanEvidence:
    def __truediv__(self, name):
        return _PlanPart(name)


class _PlanPart:
    def __init__(self, name):
        self.name = name

    def exists(self):
        return True

    def read_text(self):
        return json.dumps({"address": "0:" + "0f" * 32, "pass": True})


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--private-dir", required=True)
    p.add_argument("--evidence-dir", required=True)
    p.add_argument("--cli", required=True)
    p.add_argument("--cli-sha256", required=True)
    p.add_argument("--rpc", required=True, help="broadcast + primary read JSON-RPC URL")
    p.add_argument("--confirm-rpc", action="append", default=[])
    p.add_argument("--genesis-root", required=True)
    p.add_argument("--genesis-file", required=True)
    p.add_argument("--stop-ceiling", default="20", help="hard cumulative funding ceiling, TOS")
    p.add_argument(
        "--flag-fixture",
        default=str(FLAG_FIXTURE),
        help="JSON of the pinned CLI's accepted flags per command; required for `case`",
    )
    p.add_argument("--skip-thermal", action="store_true")
    p.add_argument("--date", default=time.strftime("%Y%m%d", time.gmtime()))
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("preflight")
    sub.add_parser("setup")
    pf = sub.add_parser("plan-funding")
    pf.add_argument("--funding-source", required=True, help="pool-owner address funds come from")
    rf = sub.add_parser("record-funding")
    rf.add_argument("--actor", required=True)
    rf.add_argument("--amount", required=True)
    rf.add_argument("--operation-id", required=True)
    sub.add_parser("activate")
    pl = sub.add_parser("plan")
    pl.add_argument("name")
    c = sub.add_parser("case")
    c.add_argument("name")
    r = sub.add_parser("return-funds")
    r.add_argument("--to", required=True)
    sub.add_parser("status")
    rc = sub.add_parser("reconcile")
    rc.add_argument("label")
    rc.add_argument(
        "--external",
        action="store_true",
        help="the step's command was signed for the contract itself (no wallet send)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    runner = Runner(args)
    try:
        if args.command == "preflight":
            out = runner.preflight()
        elif args.command == "setup":
            out = runner.setup()
        elif args.command == "plan-funding":
            out = runner.plan_funding(args.funding_source)
        elif args.command == "record-funding":
            out = runner.record_funding(args.actor, args.amount, args.operation_id)
        elif args.command == "activate":
            out = runner.activate()
        elif args.command == "plan":
            out = runner.plan(args.name)
        elif args.command == "case":
            out = runner.case(args.name)
        elif args.command == "return-funds":
            out = runner.return_funds(args.to)
        elif args.command == "reconcile":
            out = runner.reconcile(args.label, external=args.external)
        else:
            out = runner.status()
    except Refusal as exc:
        reason = str(exc).replace(str(runner.private), "<private>")
        runner.journal.log(kind="refusal", command=args.command, reason=reason)
        print(json.dumps({"refused": reason}, indent=2))
        return 3
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - journaled, then surfaced as a distinct exit code
        error = repr(exc).replace(str(runner.private), "<private>")
        runner.journal.log(kind="error", command=args.command, error=error)
        print(json.dumps({"error": error}, indent=2))
        return 2
    print(json.dumps(out, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
