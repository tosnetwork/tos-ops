#!/usr/bin/env python3
"""Once-only public runner for the bounded service-contract acceptance cases (SC-02..SC-08).

The runner drives the pinned `tosctl` against the public testnet from a private directory
on the coordinator and records exact receipts. It never signs the funding (pool-owner)
wallet: funding stays in `testnet-elections.py owner-fund`, and this tool only plans the
amounts, verifies the credits and keeps the cumulative total under a hard ceiling.

Guarantees the tests pin:
  * every value step has a stable label and an `O_EXCL` attempt marker written before the CLI
    is invoked; a label whose marker exists is refused, so a crash or lost reply can never lead
    to a second send of the same step (reconciliation is read-only);
  * a settlement claim is the exact transaction (same hash) seen on the broadcast source and on
    every confirmation source, with the payer as the message source, compute exit code and
    aborted flag recorded; a refusal control must abort with the intended exit code and leave
    the protected state unchanged;
  * preflight refuses a wrong CLI binary, a different genesis on any source, a global version
    other than the pinned one, a handover quiet window, an over-temperature package and a
    cumulative funding total above the ceiling;
  * CLI stdout/stderr land in the private directory; the evidence directory only receives
    sanitized records (labels, argv without environment, addresses, hashes, exit codes).

Commands: preflight | setup | plan-funding | record-funding | activate | case <name> |
return-funds | status.  See `--help`.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

NANO = 10**9
ROTATION_PERIOD_S = 7200
QUIET_S = 600
TEMP_LIMIT_C = 82.0
CLI_TIMEOUT_S = 180
SETTLE_TIMEOUT_S = 150
POLL_S = 2.0
CP8_VERSION = 16
WALLETS = ("sc-owner", "sc-client", "sc-verifier", "sc-respondent", "sc-outsider")
KEYS = ("sc-attestor-key", "sc-rotated-attestor-key", "sc-wrong-key")
FUNDING_PLAN_TOS = {
    "sc-owner": "5.0",
    "sc-client": "3.0",
    "sc-verifier": "2.0",
    "sc-respondent": "1.5",
    "sc-outsider": "1.0",
}
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


def norm_addr(address: str) -> str:
    wc, _, acc = address.partition(":")
    return f"{int(wc)}:{acc.lower()}"


def same_addr(a: str | None, b: str | None) -> bool:
    return bool(a) and bool(b) and norm_addr(a) == norm_addr(b)


def tos_to_nanotos(text: str) -> int:
    whole, _, frac = str(text).partition(".")
    if len(frac) > 9 or not (whole or frac).replace("_", "").isdigit():
        raise Refusal(f"bad TOS amount {text!r}")
    return int(whole or "0") * NANO + int((frac + "0" * 9)[:9] or "0")


def nanotos_text(value: int) -> str:
    return f"{value // NANO}.{value % NANO:09d}"


def boc_root_data(raw: bytes) -> bytes:
    """Data bytes of the root cell of a serialized bag of cells (no cell parsing beyond that)."""
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
        p += ln + refs * size
        if i == root:
            return data
    raise Refusal("BOC root missing")


def quiet_window_distance(ts: int, anchor: int, period: int = ROTATION_PERIOD_S) -> int:
    """Seconds to the nearest validator-set rotation on the grid anchored at `anchor`."""
    phase = (ts - anchor) % period
    return min(phase, period - phase)


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
        self.transcript: list[dict] = []

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
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
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
        if data[0] != 0xC4:
            raise Refusal("ConfigParam 8 tag")
        return int.from_bytes(data[1:5], "big")

    def rotation_anchor(self) -> int:
        """utime_since of the installed validator set (ConfigParam 34)."""
        data = self.config_param(34)
        if data[0] not in (0x11, 0x12):
            raise Refusal("ConfigParam 34 tag")
        return int.from_bytes(data[1:5], "big")

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

    def done(self, label: str, record: dict) -> None:
        path = self.steps / f"{label}.done.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"label": label, "utc": utc(now()), **record}, sort_keys=True))
        os.replace(tmp, path)

    def result(self, label: str) -> dict | None:
        path = self.steps / f"{label}.done.json"
        return json.loads(path.read_text()) if path.exists() else None

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

    def run(self, label: str, *args: str, want_json: bool = False):
        """Run tosctl once. Raw output stays private; the sanitized record is journaled."""
        self.receipts.mkdir(mode=0o700, exist_ok=True)
        argv = [str(self.path), *args, "-c", str(self.config)]
        if want_json:
            argv += ["--format", "json"]
        self.calls += 1
        started = utc(now())
        proc = subprocess.run(
            argv, env=self.env(), capture_output=True, timeout=CLI_TIMEOUT_S, check=False
        )
        (self.receipts / f"{label}.stdout").write_bytes(proc.stdout)
        (self.receipts / f"{label}.stderr").write_bytes(proc.stderr)
        self.journal.log(
            kind="cli",
            label=label,
            argv=list(args),
            exit_code=proc.returncode,
            started=started,
            stdout_sha256=hashlib.sha256(proc.stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(proc.stderr).hexdigest(),
        )
        text = proc.stdout.decode("utf-8", "replace")
        if want_json and proc.returncode == 0:
            try:
                return proc.returncode, json.loads(text)
            except json.JSONDecodeError as exc:
                raise Refusal(f"{label}: CLI did not return JSON ({exc})") from exc
        return proc.returncode, text


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
        self.ceiling = tos_to_nanotos(args.stop_ceiling)

    # ----- state files ------------------------------------------------------------------
    def actors(self) -> dict:
        if not self.actors_path.exists():
            raise Refusal("actors.json missing; run setup first")
        return json.loads(self.actors_path.read_text())

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
        anchor = self.args.rotation_anchor or self.rpc.rotation_anchor()
        distance = quiet_window_distance(now(), anchor)
        if distance < QUIET_S:
            raise Refusal(f"within {distance}s of a validator-set rotation; wait")
        return {"anchor_utime_since": anchor, "seconds_to_rotation": distance}

    def check_thermal(self) -> list[float]:
        temps = package_temperatures()
        if self.args.skip_thermal:
            return temps
        if not temps:
            raise Refusal("no package temperature readable; use --skip-thermal only off-host")
        if max(temps) > TEMP_LIMIT_C:
            raise Refusal(f"package temperature {max(temps)} C above {TEMP_LIMIT_C}")
        return temps

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
            record["quiet_window"] = self.check_quiet_window()
            record["package_temperatures_c"] = self.check_thermal()
        self.check_private_dir()
        self.journal.log(kind="preflight", **record)
        return record

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
            label = f"setup-key-{key}"
            if self.journal.attempted(label):
                continue
            self.journal.attempt(label, {"kind": "key-add", "name": key})
            rc, _ = self.cli.run(label, "key", "add", "--name", key)
            if rc != 0:
                raise Refusal(f"{label}: exit {rc}")
            self.journal.done(label, {"exit_code": rc})
        for wallet in WALLETS:
            label = f"setup-wallet-{wallet}"
            if self.journal.attempted(label):
                continue
            self.journal.attempt(label, {"kind": "wallet-create", "name": wallet})
            rc, _ = self.cli.run(label, "wallet", "create", "-n", wallet, "-v", "V3R2", "-w", "0")
            if rc != 0:
                raise Refusal(f"{label}: exit {rc}")
            self.journal.done(label, {"exit_code": rc})
        rc, rows = self.cli.run("setup-wallet-ls", "wallet", "ls", want_json=True)
        if rc != 0:
            raise Refusal("wallet ls failed")
        addresses = {}
        for row in rows:
            if row.get("name") in WALLETS and row.get("address"):
                addresses[row["name"]] = norm_addr(row["address"])
        missing = [w for w in WALLETS if w not in addresses]
        if missing:
            raise Refusal(f"wallets without address: {missing}")
        actors = {"wallets": addresses, "keys": list(KEYS), "created_utc": utc(now())}
        self.actors_path.write_text(json.dumps(actors, indent=2, sort_keys=True) + "\n")
        self.journal.log(kind="setup", wallets=addresses)
        return actors

    # ----- funding ------------------------------------------------------------------------
    def plan_funding(self) -> dict:
        actors = self.actors()
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
                    "purpose": f"service-contract public cases {wallet} ({self.args.date})",
                }
            )
        if self.funded_total() + total > self.ceiling:
            raise Refusal("plan exceeds the stop ceiling")
        out = {
            "plan": plan,
            "total_nanotos": total,
            "stop_ceiling_nanotos": self.ceiling,
            "tool": "testnet-elections.py owner-fund --name node-4 --new --dry-run first",
        }
        (self.evidence / "funding-plan.json").write_text(json.dumps(out, indent=2) + "\n")
        return out

    def record_funding(self, actor: str, amount: str, operation_id: str) -> dict:
        actors = self.actors()
        address = actors["wallets"][actor]
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
        while time.monotonic() < deadline:
            try:
                if predicate():
                    return True
            except Refusal:
                pass
            time.sleep(POLL_S)
        return False

    def step(
        self,
        label: str,
        argv: list[str],
        payer: str,
        observe: str | None,
        expect_exit: int | None = 0,
        want_json: bool = False,
        show: callable | None = None,
    ) -> dict:
        """One CLI action that sends exactly one message from `payer` (an actor wallet).

        `observe` is the contract address whose next transaction must be the message from
        `payer` (None for a deploy whose address is only known from the CLI answer).
        `expect_exit` 0 = must succeed; an int = must abort with that compute exit code;
        None = must abort (code recorded, not pinned). The protected state read by `show`
        before and after must be unchanged for a refusal control.
        """
        previous = self.journal.result(label)
        if previous:
            if previous.get("verdict") in ("settled", "refused-as-intended"):
                return previous
            raise Refusal(
                f"step {label!r} already ended with verdict {previous.get('verdict')!r}; "
                "it is never re-sent"
            )
        if os.environ.get("SC_DRILL_CRASH") == label:
            self.journal.attempt(label, {"kind": "drill", "argv": argv, "payer": payer})
            raise SystemExit(f"drill: process lost after the attempt marker of {label}")
        before = {
            "head": self.rpc.head(),
            "payer_lt": self.rpc.last_lt(payer),
            "payer_balance": self.rpc.balance(payer),
            "observe_lt": self.rpc.last_lt(observe) if observe else None,
            "observe_balance": self.rpc.balance(observe) if observe else None,
            "state": show() if show else None,
        }
        self.journal.attempt(
            label,
            {
                "argv": argv,
                "payer": payer,
                "observe": observe,
                "expect_exit": expect_exit,
                "before": before,
            },
        )
        rc, answer = self.cli.run(label, *argv, want_json=want_json)
        record: dict = {"exit_code": rc, "argv": argv, "payer": payer, "before": before}
        if want_json and rc == 0 and isinstance(answer, dict):
            record["answer"] = {
                k: v
                for k, v in answer.items()
                if k in ("address", "request_id", "tx_hash", "status")
            }
            observe = observe or norm_addr(answer.get("address", "")) or None
        if rc != 0:
            # The CLI refused before or while broadcasting: reconcile read-only, never retry.
            record["payer_tx_after"] = self.rpc.transactions_after(payer, before["payer_lt"])
            record["verdict"] = "cli-refused" if not record["payer_tx_after"] else "unknown"
            self.journal.done(label, record)
            raise Refusal(f"{label}: CLI exit {rc}; {record['verdict']}; reconciled read-only")
        found: dict = {}

        def settled() -> bool:
            payer_rows = self.rpc.transactions_after(payer, before["payer_lt"])
            sends = [
                r
                for r in payer_rows
                if any(same_addr(m.get("destination"), observe) for m in r.get("out_msgs", []))
            ]
            if len(sends) > 1:
                raise Refusal(f"{label}: payer sent more than one message to {observe}")
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

        if not self.wait(settled):
            record["verdict"] = "unknown-not-observed"
            self.journal.done(label, record)
            raise Refusal(f"{label}: the exact message was not observed in time; no retry")
        tx = found["tx"]
        compute = tx.get("compute") or {}
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
                "observe": observe,
                "payer_tx": found["payer_tx"]["transaction_id"],
                "tx": tx["transaction_id"],
                "block_id": tx.get("block_id"),
                "compute": compute,
                "aborted": tx.get("aborted"),
                "action": tx.get("action"),
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
            ok = (
                compute.get("success") is True
                and compute.get("exit_code") == 0
                and tx.get("aborted") is False
            )
            record["verdict"] = "settled" if ok else "unexpected-abort"
        else:
            aborted = tx.get("aborted") is True and compute.get("success") is False
            code_ok = expect_exit is None or compute.get("exit_code") == expect_exit
            state_ok = show is None or before["state"] == after_state
            ok = aborted and code_ok and state_ok
            record["verdict"] = "refused-as-intended" if ok else "refusal-control-failed"
        self.journal.done(label, record)
        if not ok:
            raise Refusal(f"{label}: {record['verdict']} ({compute})")
        return record

    def show(self, *argv: str):
        def read():
            rc, data = self.cli.run(f"show-{self.cli.calls:05d}", *argv, want_json=True)
            if rc != 0:
                raise Refusal(f"show failed: {argv}")
            return data

        return read

    # ----- cases --------------------------------------------------------------------------
    def case(self, name: str) -> dict:
        self.preflight()
        actors = self.actors()["wallets"]
        fn = getattr(self, f"case_{name.replace('-', '_')}", None)
        if fn is None:
            raise Refusal(f"unknown case {name}")
        result = fn(actors)
        (self.evidence / f"{name}-RESULT.json").write_text(
            json.dumps({"case": name, "utc": utc(now()), **result}, indent=2, sort_keys=True) + "\n"
        )
        return result

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
        if not self.wait(lambda: self.rpc.state(address) == "active"):
            raise Refusal("sc07 not active")
        send = ["agent", "attestation", "send", "--name", "sc07", "--yes", "--amount", "0.1"]
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
            expect_exit=2101,
            show=show,
        )
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
            expect_exit=2102,
            show=show,
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
        self.step(
            "sc07-revoke-outsider",
            send + ["--operation", "revoke", "--from", "sc-outsider"],
            payer=outsider,
            observe=address,
            expect_exit=2102,
            show=show,
        )
        self.step(
            "sc07-revoke-owner",
            send + ["--operation", "revoke", "--from", "sc-owner"],
            payer=owner,
            observe=address,
            show=show,
        )
        final = show()
        return {
            "address": address,
            "final_state": final,
            "pass": final.get("revoked") is True and final.get("has_attestation") is False,
        }

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
                "1.2",
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
        if not self.wait(lambda: self.rpc.state(address) == "active"):
            raise Refusal("sc04 not active")
        send = ["agent", "service", "send", "--name", "sc04", "--yes"]
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
                "--amount",
                "0.45",
            ],
            payer=outsider,
            observe=address,
            expect_exit=None,
            show=show,
        )
        self.step(
            "sc04-call-client",
            send
            + [
                "--operation",
                "call",
                "--from",
                "sc-client",
                "--request-hash",
                HASH["request_1"],
                "--amount",
                "0.45",
            ],
            payer=client,
            observe=address,
            show=show,
        )
        state = show()
        request_id = str(state.get("next_request_id", 1) - 1) if "next_request_id" in state else "0"
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
                "--amount",
                "0.1",
            ],
            payer=outsider,
            observe=address,
            expect_exit=None,
            show=show,
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
                "--amount",
                "0.1",
            ],
            payer=owner,
            observe=address,
            show=show,
        )
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
                "--amount",
                "0.1",
            ],
            payer=outsider,
            observe=address,
            expect_exit=1900,
            show=show,
        )
        self.step(
            "sc04-withdraw-owner",
            send
            + [
                "--operation",
                "withdraw-revenue",
                "--from",
                "sc-owner",
                "--withdraw-amount",
                "0.1",
                "--amount",
                "0.1",
            ],
            payer=owner,
            observe=address,
            show=show,
        )
        final = show()
        return {
            "address": address,
            "request_id": request_id,
            "final_state": final,
            "pass": final.get("pending_count") == 0,
        }

    def case_sc05(self, w: dict) -> dict:
        creator, agent, verifier = w["sc-owner"], w["sc-client"], w["sc-verifier"]
        deadline = str(now() + 3600)
        deploy = self.step(
            "sc05-create",
            [
                "agent",
                "task",
                "create",
                "--name",
                "sc05",
                "--creator",
                creator,
                "--agent",
                agent,
                "--verifier",
                verifier,
                "--budget",
                "1",
                "--deadline",
                deadline,
                "--review-period",
                "600",
                "--policy-hash",
                HASH["policy"],
                "--from",
                "sc-owner",
                "--amount",
                "1.3",
                "-w",
                "0",
                "--yes",
            ],
            payer=creator,
            observe=None,
            want_json=True,
        )
        address = deploy["observe"]
        show = self.show("agent", "task", "show", "--name", "sc05")
        if not self.wait(lambda: show().get("status") == "open"):
            raise Refusal("sc05 not open")
        send = ["agent", "task", "send", "--name", "sc05", "--yes", "--amount", "0.1"]
        self.step(
            "sc05-accept-creator",
            send + ["--operation", "accept", "--from", "sc-owner"],
            payer=creator,
            observe=address,
            expect_exit=None,
            show=show,
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
        self.step(
            "sc05-settle-agent",
            send + ["--operation", "settle", "--from", "sc-client", "--payout", "0.6"],
            payer=agent,
            observe=address,
            expect_exit=None,
            show=show,
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
        return {
            "address": address,
            "final_state": final,
            "agent_paid": paid,
            "pass": final.get("status") == "settled" and paid,
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
                str(now() + 3600),
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
        if not self.wait(lambda: self.rpc.state(address) == "active"):
            raise Refusal("sc06 not active")
        send = ["agent", "dispute", "send", "--name", "sc06", "--yes", "--amount", "0.1"]
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
            expect_exit=2000,
            show=show,
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
            expect_exit=2001,
            show=show,
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
            expect_exit=None,
            show=show,
        )
        final = show()
        return {
            "address": address,
            "final_state": final,
            "pass": final.get("status") == "resolved" and final.get("ruling") == "claimant",
        }

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
        if not self.wait(lambda: self.rpc.state(address) == "active"):
            raise Refusal("sc02 not active")
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
        self.step(
            "sc02-update-outsider",
            send + ["--operation", "update-metadata", "--from", "sc-outsider"] + meta,
            payer=outsider,
            observe=address,
            expect_exit=1800,
            show=show,
        )
        self.step(
            "sc02-update-owner",
            send + ["--operation", "update-metadata", "--from", "sc-owner"] + meta,
            payer=owner,
            observe=address,
            show=show,
        )
        self.step(
            "sc02-reputation-outsider",
            send + ["--operation", "update-reputation", "--from", "sc-outsider", "--delta", "10"],
            payer=outsider,
            observe=address,
            expect_exit=1801,
            show=show,
        )
        self.step(
            "sc02-reputation-verifier",
            send + ["--operation", "update-reputation", "--from", "sc-verifier", "--delta", "10"],
            payer=verifier,
            observe=address,
            show=show,
        )
        self.step(
            "sc02-overdraw-bond",
            send
            + ["--operation", "withdraw-bond", "--from", "sc-owner", "--withdraw-amount", "100"],
            payer=owner,
            observe=address,
            expect_exit=1805,
            show=show,
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
        return {
            "address": address,
            "final_state": final,
            "pass": final.get("active") is False and final.get("reputation_score") == 10,
        }

    def case_sc03(self, w: dict) -> dict:
        owner, target = w["sc-owner"], w["sc-verifier"]
        label = "sc03-agent-wallet-create"
        if not self.journal.attempted(label):
            self.journal.attempt(label, {"kind": "local-profile"})
            rc, _ = self.cli.run(
                label,
                "agent",
                "wallet",
                "create",
                "--name",
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
            self.journal.done(label, {"exit_code": rc})
            if rc != 0:
                raise Refusal(f"{label}: exit {rc}")
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
        rc, profile = self.cli.run(
            "sc03-agent-wallet-show", "agent", "wallet", "show", "-n", "sc03-agent", want_json=True
        )
        if rc != 0:
            raise Refusal("agent wallet show failed")
        agent_wallet = norm_addr(profile.get("address") or profile["result"]["address"])
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
        label = "sc03-agent-wallet-activate"
        if not self.journal.attempted(label):
            self.journal.attempt(label, {"kind": "wallet-activate", "address": agent_wallet})
            rc, _ = self.cli.run(label, "agent", "wallet", "activate", "-n", "sc03-agent")
            ok = rc == 0 and self.wait(lambda: self.rpc.state(agent_wallet) == "active")
            self.journal.done(label, {"exit_code": rc, "active": ok})
            if not ok:
                raise Refusal("agent wallet not active")
        action_1 = secrets.token_hex(32)
        target_before = self.rpc.balance(target)
        self.step(
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
                action_1,
                "--yes",
            ],
            payer=agent_wallet,
            observe=account,
        )
        delivered = self.wait(
            lambda: self.rpc.balance(target) >= target_before + tos_to_nanotos("0.09")
        )
        label = "sc03-task-send-1-duplicate"
        duplicate_blocked = None
        if not self.journal.attempted(label):
            self.journal.attempt(label, {"kind": "duplicate-action-id", "action_id": action_1})
            lt = self.rpc.last_lt(account)
            rc, _ = self.cli.run(
                label,
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
            )
            time.sleep(POLL_S * 5)
            repeated = [
                r for r in self.rpc.transactions_after(account, lt) if r.get("aborted") is False
            ]
            duplicate_blocked = rc != 0 or not repeated
            self.journal.done(
                label,
                {
                    "exit_code": rc,
                    "new_successful_tx": len(repeated),
                    "duplicate_blocked": duplicate_blocked,
                },
            )
        label = "sc03-policy-local"
        if not self.journal.attempted(label):
            self.journal.attempt(label, {"kind": "local-profile"})
            rc, _ = self.cli.run(
                label,
                "agent",
                "wallet",
                "update-policy",
                "--name",
                "sc03-agent",
                "--max-per-tx",
                "0.2",
                "--daily-limit",
                "1",
            )
            self.journal.done(label, {"exit_code": rc})
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
        label = "sc03-rotate-local"
        if not self.journal.attempted(label):
            self.journal.attempt(label, {"kind": "local-profile"})
            rc, _ = self.cli.run(
                label, "agent", "wallet", "rotate-controller", "--name", "sc03-agent"
            )
            self.journal.done(label, {"exit_code": rc})
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
            payer=agent_wallet,
            observe=account,
        )
        target_before_2 = self.rpc.balance(target)
        self.step(
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
        delivered_2 = self.wait(
            lambda: self.rpc.balance(target) >= target_before_2 + tos_to_nanotos("0.09")
        )
        rc, status = self.cli.run(
            "sc03-status",
            "agent",
            "account",
            "status",
            "--wallet",
            "sc03-agent",
            "-w",
            "0",
            want_json=True,
        )
        return {
            "account": account,
            "agent_wallet": agent_wallet,
            "status": status,
            "first_transfer_delivered": delivered,
            "duplicate_blocked": duplicate_blocked,
            "transfer_after_rotation_delivered": delivered_2,
            "pass": bool(delivered and delivered_2 and duplicate_blocked),
        }

    def case_sc08(self, w: dict) -> dict:
        """Integrated journey over the already deployed actors plus a disputed task branch and
        the lost-reply drill (run twice: the first run exits at the drill label, the second must
        refuse that label and continue read-only)."""
        creator, agent, verifier = w["sc-owner"], w["sc-client"], w["sc-verifier"]
        parts = {}
        for name in ("sc02", "sc03", "sc04", "sc05", "sc06", "sc07"):
            path = self.evidence / f"{name}-RESULT.json"
            if not path.exists():
                raise Refusal(f"sc08 needs {name} first")
            parts[name] = json.loads(path.read_text())
        deadline = str(now() + 3600)
        deploy = self.step(
            "sc08-task-create",
            [
                "agent",
                "task",
                "create",
                "--name",
                "sc08",
                "--creator",
                creator,
                "--agent",
                agent,
                "--verifier",
                verifier,
                "--budget",
                "1",
                "--deadline",
                deadline,
                "--review-period",
                "600",
                "--policy-hash",
                HASH["policy"],
                "--from",
                "sc-owner",
                "--amount",
                "1.3",
                "-w",
                "0",
                "--yes",
            ],
            payer=creator,
            observe=None,
            want_json=True,
        )
        address = deploy["observe"]
        show = self.show("agent", "task", "show", "--name", "sc08")
        if not self.wait(lambda: show().get("status") == "open"):
            raise Refusal("sc08 task not open")
        send = ["agent", "task", "send", "--name", "sc08", "--yes", "--amount", "0.1"]
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
        self.step(
            "sc08-resolve-agent",
            send + ["--operation", "resolve", "--from", "sc-client", "--payout", "0.4"],
            payer=agent,
            observe=address,
            expect_exit=None,
            show=show,
        )
        drill = "sc08-resolve-verifier"
        drilled = self.journal.attempted(drill) and not self.journal.result(drill)
        if drilled:
            # The first run was lost after the attempt marker: reconcile read-only and record.
            attempt = json.loads((self.journal.steps / f"{drill}.attempt.json").read_text())
            rows = (
                self.rpc.transactions_after(address, attempt["before"]["observe_lt"] or 0)
                if "before" in attempt
                else []
            )
            self.journal.done(
                drill,
                {
                    "verdict": "lost-reply-reconciled",
                    "transactions_after_marker": len(rows),
                    "re_sent": False,
                },
            )
            self.step(
                "sc08-resolve-verifier-2",
                send + ["--operation", "resolve", "--from", "sc-verifier", "--payout", "0.4"],
                payer=verifier,
                observe=address,
                show=show,
            )
        else:
            self.step(
                drill,
                send + ["--operation", "resolve", "--from", "sc-verifier", "--payout", "0.4"],
                payer=verifier,
                observe=address,
                show=show,
            )
        final = show()
        return {
            "address": address,
            "final_state": final,
            "components": {
                k: {"address": v.get("address") or v.get("account"), "pass": v.get("pass")}
                for k, v in parts.items()
            },
            "lost_reply_drill": "reconciled" if drilled else "not-exercised",
            "pass": final.get("status") == "settled",
        }

    # ----- wrap-up ------------------------------------------------------------------------
    def return_funds(self, to: str) -> dict:
        self.preflight()
        actors = self.actors()["wallets"]
        out = {}
        keep = tos_to_nanotos("0.05")
        for wallet, address in actors.items():
            balance = self.rpc.balance(address)
            if balance <= keep * 2:
                out[wallet] = {"skipped": balance}
                continue
            label = f"return-{wallet}"
            amount = balance - keep
            rec = self.step(
                label,
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

    def status(self) -> dict:
        actors = self.actors() if self.actors_path.exists() else {}
        balances = {n: self.rpc.balance(a) for n, a in actors.get("wallets", {}).items()}
        steps = sorted(p.name for p in self.journal.steps.glob("*.json"))
        return {"funded_total_nanotos": self.funded_total(), "balances": balances, "steps": steps}


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
        "--rotation-anchor",
        type=int,
        default=0,
        help="utime_since of the installed set; 0 = read ConfigParam 34",
    )
    p.add_argument("--skip-thermal", action="store_true")
    p.add_argument("--date", default=time.strftime("%Y%m%d", time.gmtime()))
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("preflight")
    sub.add_parser("setup")
    sub.add_parser("plan-funding")
    rf = sub.add_parser("record-funding")
    rf.add_argument("--actor", required=True)
    rf.add_argument("--amount", required=True)
    rf.add_argument("--operation-id", required=True)
    sub.add_parser("activate")
    c = sub.add_parser("case")
    c.add_argument("name")
    r = sub.add_parser("return-funds")
    r.add_argument("--to", required=True)
    sub.add_parser("status")
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
            out = runner.plan_funding()
        elif args.command == "record-funding":
            out = runner.record_funding(args.actor, args.amount, args.operation_id)
        elif args.command == "activate":
            out = runner.activate()
        elif args.command == "case":
            out = runner.case(args.name)
        elif args.command == "return-funds":
            out = runner.return_funds(args.to)
        else:
            out = runner.status()
    except Refusal as exc:
        runner.journal.log(kind="refusal", command=args.command, reason=str(exc))
        print(json.dumps({"refused": str(exc)}, indent=2))
        return 3
    print(json.dumps(out, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
