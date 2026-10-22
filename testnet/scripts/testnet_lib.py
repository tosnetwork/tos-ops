"""Shared helpers for the public testnet ceremony and operator scripts.

Standard library only: an operator host runs these without a tos Python
environment. Every function that writes refuses to overwrite and never follows
a symlink, because the ceremony outputs (manifest, zerostate, global config)
are published and must not change silently once produced.
"""

from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
import tempfile
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
PROFILE_PATH = HERE.parent / "network" / "profile.json"

MAINNET_GLOBAL_ID = 1
LOCAL_GLOBAL_ID = 3
GENESIS_VALIDATORS = 4
PQ_PUBLIC_KEY_BYTES = 1312
HASH_BYTES = 32
MASTERCHAIN = -1
MASTERCHAIN_SHARD = -(2**63)
PQ_KEY_DOMAIN = b"TOS-PQ-CONSENSUS-KEY-v1"
PQ_ALGORITHM_MLDSA44 = 1
ED25519_PUBLIC_TL_PREFIX = bytes.fromhex("c6b41348")
ED25519_PRIVATE_TL_PREFIX = bytes.fromhex("17236849")

# The lines of the canonical template a testnet ceremony replaces: the three
# that pin it to mainnet, and the two that set the validator schedule. Exactly
# these and nothing else; any other difference in the template is a change the
# ceremony did not review, so it is refused.
TEMPLATE_GLOBAL_ID_LINE = "1 setglobalid   // TOS mainnet global_id"
TEMPLATE_EPOCH_LINE = "1789434000 constant mainnet_genesis_utime"
TEMPLATE_EPOCH_ABORT_LINE = 'now mainnet_genesis_utime = not abort"SOURCE_DATE_EPOCH must be 1789434000 for TOS mainnet genesis"'
TEMPLATE_ELECTION_PARAMS_LINE = "65536 32768 8192 32768 config.election_params!"
# The mainnet initial set lasts 6 h since tos #206 (131,072 s before it).
TEMPLATE_INITIAL_SET_LINE = "21600 =: orig_vset_valid_for"
# A version-16 genesis needs a public AUTH network tag (ConfigParam 48) defined
# before the template's own guard runs. The ceremony inserts the definition
# right after the first line; the guard must still be there to refuse a
# template run without it.
TEMPLATE_FIRST_LINE = "#!/usr/bin/create-state -s"
TEMPLATE_AUTH_GUARD_LINE = (
    'def? quantum-network-tag not abort"Version 16 Genesis requires an explicit AUTH network tag"'
)
AUTH_TAG_CONSTANT = "quantum-network-tag"

# ConfigParam 15, in the order config.election_params! takes it.
ELECTION_PARAM_NAMES = (
    "elected_for",
    "elections_start_before",
    "elections_end_before",
    "stake_held_for",
)
# Operators deploy, fund and authorize their controllers after the chain is
# live and before the first election opens; this is the least time they get.
MIN_FIRST_ELECTION_LEAD_SECONDS = 3600


class TestnetError(Exception):
    """A refusal: the input is not what the ceremony or the operator expects."""


# ---------------------------------------------------------------- profile


def load_profile(path: Path = PROFILE_PATH) -> dict[str, Any]:
    profile = json.loads(Path(path).read_text())
    if profile.get("schema_version") != 1:
        raise TestnetError(f"{path}: unsupported schema_version")
    global_id = profile.get("global_id", {}).get("value")
    check_global_id(global_id)
    genesis = profile.get("genesis", {})
    if genesis.get("validators") != GENESIS_VALIDATORS:
        raise TestnetError("the canonical genesis commits exactly four validators")
    validator_schedule(profile)
    ports = profile.get("ports", {})
    required = (
        "adnl_udp",
        "quic_udp_offset",
        "console_tcp",
        "liteserver_tcp",
        "dht_udp",
        "json_rpc_loopback",
        "exporter_loopback",
    )
    for name in required:
        value = ports.get(name)
        if not isinstance(value, int) or not 0 < value < 65536:
            raise TestnetError(f"profile port {name} is missing or out of range: {value!r}")
    public = [ports["adnl_udp"], ports["adnl_udp"] + ports["quic_udp_offset"], ports["dht_udp"]]
    if ports["adnl_udp"] + ports["quic_udp_offset"] > 65535 or len(set(public)) != len(public):
        raise TestnetError("profile UDP ports collide or the derived QUIC port is out of range")
    return profile


def validator_schedule(profile: dict[str, Any]) -> dict[str, int]:
    """The initial set's lifetime and ConfigParam 15, checked against each other.

    Returns {"initial_set_valid_for": s, "elected_for": s, ...}. A schedule the
    Elector would accept but that cannot work is refused here, before a zero
    state commits to it: an election window that is empty or does not end
    before the term starts, or a first election that opens before operators
    can have their controllers ready.
    """
    genesis = profile.get("genesis", {})
    params = genesis.get("election_params", {})
    if not isinstance(params, dict) or set(params) != set(ELECTION_PARAM_NAMES):
        raise TestnetError(f"genesis election_params must name exactly {ELECTION_PARAM_NAMES}")
    values = {"initial_set_valid_for": genesis.get("initial_set_valid_for_seconds")}
    values.update({name: params[name] for name in ELECTION_PARAM_NAMES})
    for name, value in values.items():
        if not isinstance(value, int) or isinstance(value, bool) or not 0 < value < 2**32:
            raise TestnetError(f"genesis schedule {name} is missing or out of range: {value!r}")
    if (
        not values["elections_end_before"]
        < values["elections_start_before"]
        < values["elected_for"]
    ):
        raise TestnetError(
            "election params need elections_end_before < elections_start_before < elected_for"
        )
    lead = values["initial_set_valid_for"] - values["elections_start_before"]
    if lead < MIN_FIRST_ELECTION_LEAD_SECONDS:
        raise TestnetError(
            f"the first election would open {lead} s after genesis; operators need at least "
            f"{MIN_FIRST_ELECTION_LEAD_SECONDS} s to deploy and fund their controllers"
        )
    return values


def confirmed_global_id(profile: dict[str, Any]) -> int:
    """The global id a genesis may be generated with: valid, and confirmed by the owner.

    A zero state carries its global id forever; every block and every wallet
    signature commits to it. An unconfirmed value must never reach one.
    """
    entry = profile.get("global_id", {})
    if entry.get("status") != "CONFIRMED":
        raise TestnetError(
            f"global id {entry.get('value')!r} is {entry.get('status')!r}, not CONFIRMED; "
            "the owner decides it (decision D03) before any genesis"
        )
    return check_global_id(entry.get("value"))


def check_global_id(value: Any) -> int:
    """A testnet global id is a signed int32 that is neither mainnet's nor local's."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise TestnetError(f"global id must be an integer, got {value!r}")
    if not -(2**31) <= value < 2**31:
        raise TestnetError(f"global id {value} is not a signed 32-bit integer")
    if value == MAINNET_GLOBAL_ID:
        raise TestnetError("global id 1 is mainnet's replay domain")
    if value == LOCAL_GLOBAL_ID:
        raise TestnetError("global id 3 is the local development network's replay domain")
    if value == 0:
        raise TestnetError("global id 0 is unset")
    return value


# ---------------------------------------------------------------- encodings


def parse_hex(value: Any, size: int, what: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]+", value):
        raise TestnetError(f"{what} must be hexadecimal")
    data = bytes.fromhex(value)
    if len(data) != size:
        raise TestnetError(f"{what} must be {size} bytes, got {len(data)}")
    if not any(data):
        raise TestnetError(f"{what} must not be zero")
    return data


def parse_b64(value: Any, size: int, what: str) -> bytes:
    if not isinstance(value, str):
        raise TestnetError(f"{what} must be a base64 string")
    try:
        data = base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise TestnetError(f"{what} is not standard base64: {exc}") from exc
    if len(data) != size:
        raise TestnetError(f"{what} must be {size} bytes, got {len(data)}")
    return data


def b64(data: bytes) -> str:
    """Standard base64: the engine's TL JSON decoder refuses the url-safe alphabet."""
    return base64.b64encode(data).decode()


def pq_key_id(public_key: bytes) -> bytes:
    """The consensus key id the genesis generator and the node derive from a public key."""
    if len(public_key) != PQ_PUBLIC_KEY_BYTES:
        raise TestnetError("an ML-DSA-44 public key is 1312 bytes")
    algorithm = PQ_ALGORITHM_MLDSA44.to_bytes(2, "little")
    return hashlib.sha256(PQ_KEY_DOMAIN + algorithm + public_key).digest()


def adnl_short_id(ed25519_public: bytes) -> bytes:
    """The ADNL short id of an Ed25519 transport key: SHA-256 of its pub.ed25519 TL object."""
    if len(ed25519_public) != 32:
        raise TestnetError("an Ed25519 public key is 32 bytes")
    return hashlib.sha256(ED25519_PUBLIC_TL_PREFIX + ed25519_public).digest()


def ip_to_tl(ip: str) -> int:
    """An IPv4 address as the signed int32 the TL address list carries."""
    address = ipaddress.IPv4Address(ip)
    value = int(address)
    return value - 2**32 if value >= 2**31 else value


REHEARSAL_ENV = "TESTNET_REHEARSAL_ALLOW_PRIVATE"


def require_public_ipv4(ip: str) -> str:
    """Refuse an address the internet cannot reach (private, loopback, shared, reserved).

    A single-host rehearsal sets TESTNET_REHEARSAL_ALLOW_PRIVATE=1 to run the
    same ceremony on loopback; a published ceremony never does.
    """
    address = ipaddress.IPv4Address(ip)
    if not address.is_global or address.is_multicast:
        if os.environ.get(REHEARSAL_ENV) != "1":
            raise TestnetError(f"{ip} is not a public IPv4 address")
    return ip


# ---------------------------------------------------------------- files


def write_new(path: Path, data: bytes, mode: int = 0o644) -> None:
    """Create `path` with `data`; refuse an existing file or a symlink, ignore the umask."""
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, mode)
    except FileExistsError as exc:
        raise TestnetError(
            f"{path} already exists; ceremony outputs are never overwritten"
        ) from exc
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new_json(path: Path, value: Any, mode: int = 0o644) -> None:
    write_new(path, (json.dumps(value, indent=2, sort_keys=False) + "\n").encode(), mode)


def private_dir(path: Path) -> Path:
    """Create (or accept) a directory that only its owner can enter."""
    path = Path(path)
    if path.is_symlink():
        raise TestnetError(f"{path} is a symlink")
    path.mkdir(mode=0o700, parents=False, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise TestnetError(f"{path} is not a directory")
    if info.st_uid != os.geteuid():
        raise TestnetError(f"{path} is owned by another user")
    if info.st_mode & 0o077:
        raise TestnetError(f"{path} is accessible to group or others")
    return path


def empty_dir(path: Path) -> Path:
    """Create a new, empty, private directory; refuse one that already has content."""
    path = Path(path)
    if path.exists() and any(path.iterdir()):
        raise TestnetError(f"{path} is not empty; use a new directory")
    return private_dir(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
    """Run a tool and refuse on failure, keeping its stderr in the error."""
    result = subprocess.run(argv, capture_output=True, text=True, **kwargs)
    if result.returncode != 0:
        raise TestnetError(
            f"{Path(argv[0]).name} exited {result.returncode}: {result.stderr.strip() or result.stdout.strip()}"
        )
    return result


# ---------------------------------------------------------------- consensus key


def parse_consensus_key_report(text: str) -> tuple[bytes, bytes]:
    """Parse `tos-pq-consensus-key show|generate` output into (key_id, public_key).

    The tool prints `algorithm mldsa44`, `key_id <hex>` and `public <hex>`. The
    key id is recomputed from the public key, so a report that does not match
    its own key is refused rather than trusted.
    """
    fields: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            fields[parts[0]] = parts[1]
    if fields.get("algorithm") != "mldsa44":
        raise TestnetError("consensus key report does not name algorithm mldsa44")
    key_id = parse_hex(fields.get("key_id"), HASH_BYTES, "key_id")
    public = parse_hex(fields.get("public"), PQ_PUBLIC_KEY_BYTES, "public key")
    if pq_key_id(public) != key_id:
        raise TestnetError("consensus key report: key_id does not match the public key")
    return key_id, public


# ---------------------------------------------------------------- engine config


def engine_adnl_ids(config: dict[str, Any], category: int) -> list[bytes]:
    ids = []
    for entry in config.get("adnl", []):
        if entry.get("category") == category:
            ids.append(parse_b64(entry.get("id"), HASH_BYTES, "engine adnl id"))
    return ids


def validator_adnl_id(config: dict[str, Any]) -> bytes:
    """The transport identity a genesis validator publishes.

    The engine's first start creates one category-0 ADNL key (also its DHT
    identity) and one category-1 key (its full-node identity). The genesis
    record names the category-0 key: the node treats a PQ validator ADNL id as
    its own only if config.json lists it, and the category-0 key is the one
    reachable through the published address.
    """
    ids = engine_adnl_ids(config, 0)
    if len(ids) != 1:
        raise TestnetError(
            f"expected exactly one category-0 ADNL id in config.json, found {len(ids)}; "
            "was the database created by a fresh first start?"
        )
    return ids[0]


# ---------------------------------------------------------------- operator records


RECORD_FIELDS = ("operator", "controller_id", "adnl_id", "public_key", "key_id", "address")


def check_operator_record(record: dict[str, Any]) -> dict[str, Any]:
    """Validate one operator's public submission. Returns it normalized to lower-case hex."""
    if not isinstance(record, dict):
        raise TestnetError("an operator record is a JSON object")
    missing = [name for name in RECORD_FIELDS if name not in record]
    if missing:
        raise TestnetError(f"operator record lacks {missing}")
    extra = sorted(set(record) - set(RECORD_FIELDS))
    if extra:
        raise TestnetError(f"operator record has unexpected fields {extra}")
    operator = record["operator"]
    if not isinstance(operator, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", operator):
        raise TestnetError("operator must be a short lower-case name (letters, digits, dashes)")
    controller = parse_hex(record["controller_id"], HASH_BYTES, "controller_id")
    adnl = parse_hex(record["adnl_id"], HASH_BYTES, "adnl_id")
    public = parse_hex(record["public_key"], PQ_PUBLIC_KEY_BYTES, "public_key")
    key_id = parse_hex(record["key_id"], HASH_BYTES, "key_id")
    if pq_key_id(public) != key_id:
        raise TestnetError(f"{operator}: key_id does not match public_key")
    address = record["address"]
    if not isinstance(address, str) or ":" not in address:
        raise TestnetError(f"{operator}: address must be <public-ipv4>:<udp-port>")
    host, _, port = address.rpartition(":")
    require_public_ipv4(host)
    if not port.isdigit() or not 0 < int(port) < 65536:
        raise TestnetError(f"{operator}: bad port in address {address}")
    return {
        "operator": operator,
        "controller_id": controller.hex(),
        "adnl_id": adnl.hex(),
        "public_key": public.hex(),
        "key_id": key_id.hex(),
        "address": address,
    }


def check_operator_set(records: list[Any]) -> list[dict[str, Any]]:
    if not isinstance(records, list) or len(records) != GENESIS_VALIDATORS:
        raise TestnetError("the genesis set is exactly four operator records")
    checked = [check_operator_record(r) for r in records]
    for field in ("operator", "controller_id", "adnl_id", "key_id", "address"):
        values = [r[field] for r in checked]
        if len(set(values)) != len(values):
            raise TestnetError(f"two genesis records share the same {field}")
    hosts = [r["address"].rpartition(":")[0] for r in checked]
    if len(set(hosts)) != len(hosts) and os.environ.get(REHEARSAL_ENV) != "1":
        raise TestnetError(
            "two genesis validators share one host; the testnet runs one validator per host"
        )
    return checked


REUSE_FIELDS = ("controller_id", "key_id", "adnl_id")


def check_fresh_identities(records: list[dict[str, Any]], previous: list[list[Any]]) -> None:
    """Refuse a genesis set that reuses any identity of an earlier testnet epoch.

    Every testnet epoch uses global id 2, so epochs share one replay domain. A
    reused root and consensus key give the same controller address with its
    nonce back at 0, and an authorization signed for the old epoch would verify
    on the new one. `previous` is the record lists of earlier epochs (their
    genesis-records.json, plus records the coordinator kept for validators that
    joined later); only identities in them can be checked.
    """
    seen: dict[str, set[str]] = {field: set() for field in REUSE_FIELDS}
    for epoch in previous:
        if not isinstance(epoch, list):
            raise TestnetError("a previous-epoch file is a JSON list of operator records")
        for record in epoch:
            if not isinstance(record, dict):
                raise TestnetError("a previous-epoch record is a JSON object")
            for field in REUSE_FIELDS:
                value = record.get(field)
                if isinstance(value, str):
                    seen[field].add(value.lower())
    for record in records:
        for field in REUSE_FIELDS:
            if record[field] in seen[field]:
                raise TestnetError(
                    f"{record['operator']} reuses {field} {record[field]} from an earlier testnet "
                    "epoch; a reset genesis needs fresh root and consensus keys"
                )


# ---------------------------------------------------------------- wallet identities


WALLETS_FILE = "wallets.json"
GENESIS_FILE = "genesis.json"
BOOTSTRAP_WALLET_LABEL = "bootstrap"
WALLET_PUBKEY_PREFIX = "pubkey:"
RAW_ADDRESS = re.compile(r"^-?[0-9]+:[0-9a-f]{64}$")
FIFT_PUBLIC_MARKER = "WALLET-PUBLIC-KEY"
# Prints the Ed25519 public key of the 32-byte private key file named by the
# first argument, with the same loader create-state uses for main-wallet.pk.
# Only the public key is printed.
FIFT_PUBLIC_PROGRAM = (
    f'"TosUtil.fif" include\n$1 load-keypair drop ."{FIFT_PUBLIC_MARKER} " Bx. cr\n'
)


def check_raw_address(address: str) -> str:
    """A raw `workchain:hex` address, lower-cased; anything else is refused."""
    address = str(address).lower()
    if not RAW_ADDRESS.match(address):
        raise TestnetError(f"not a raw workchain:hex address: {address!r}")
    return address


def wallet_identity(value: Any) -> str:
    """A wallet identity in one canonical spelling.

    Either `pubkey:<64 hex>` (an Ed25519 public key, for a wallet whose address
    does not depend on its key, like the bootstrap wallet at -1:111...1) or a
    raw `workchain:hex` address (for a wallet whose address is a function of its
    key). Hex is lower-cased and the workchain written as a plain integer, so
    one account spelled two ways compares equal.
    """
    if not isinstance(value, str):
        raise TestnetError(f"a wallet identity is a string, got {value!r}")
    if value[: len(WALLET_PUBKEY_PREFIX)].lower() == WALLET_PUBKEY_PREFIX:
        key = parse_hex(value[len(WALLET_PUBKEY_PREFIX) :], 32, "wallet public key")
        return WALLET_PUBKEY_PREFIX + key.hex()
    workchain, account = check_raw_address(value).split(":")
    return f"{int(workchain)}:{account}"


def check_wallet_map(value: Any, what: str) -> dict[str, str]:
    """A label -> identity map, each identity normalized."""
    if not isinstance(value, dict):
        raise TestnetError(f"{what} is a JSON object of wallet label -> identity")
    out = {}
    for label, identity in value.items():
        if not isinstance(label, str) or not label:
            raise TestnetError(f"{what} has an empty or non-string wallet label")
        out[label] = wallet_identity(identity)
    return out


def check_fresh_wallets(wallets: dict[str, str], previous: list[dict[str, str]]) -> dict[str, str]:
    """Refuse wallets that reuse a wallet identity of an earlier testnet epoch.

    Every testnet epoch uses global id 2, so epochs share one replay domain. A
    wallet whose key comes back on a new epoch accepts again any message signed
    for it on an earlier one while the message is still valid; for the
    bootstrap wallet the address is fixed, so only its key tells two epochs
    apart. `previous` is one label -> identity map per earlier epoch. An empty
    one is refused: a check that saw nothing would otherwise pass. Returns
    `wallets` normalized.
    """
    seen: dict[str, str] = {}
    for index, epoch in enumerate(previous):
        checked = check_wallet_map(epoch, "a previous epoch's wallet record")
        if not checked:
            raise TestnetError(
                f"previous epoch {index + 1} names no wallet identity; refusing to pass a check "
                "that saw nothing"
            )
        for label, identity in checked.items():
            seen.setdefault(identity, label)
    fresh = check_wallet_map(wallets, "the wallet record")
    for label, identity in fresh.items():
        if identity in seen:
            raise TestnetError(
                f"wallet {label} reuses {identity} (wallet {seen[identity]} of an earlier testnet "
                "epoch); a reset needs fresh wallet keys"
            )
    return fresh


def parse_fift_public_key(text: str) -> bytes:
    """The public key FIFT_PUBLIC_PROGRAM prints: exactly one marker line with 32 bytes."""
    lines = [line.split() for line in text.splitlines() if line.startswith(FIFT_PUBLIC_MARKER)]
    if len(lines) != 1 or len(lines[0]) != 2:
        raise TestnetError("fift did not print exactly one wallet public key")
    return parse_hex(lines[0][1], 32, "wallet public key")


def wallet_public_key(fift: Path, fift_lib: Path, key: Path, runner: Any = None) -> bytes:
    """The Ed25519 public key of a wallet private key file, derived with fift.

    The private key is read by fift in place; it is never copied or printed.
    """
    key = Path(key)
    if key.is_symlink() or not key.is_file():
        raise TestnetError(f"{key} is not a regular file")
    if key.stat().st_size != 32:
        raise TestnetError(f"{key} is not a 32-byte private key")
    runner = runner or run
    with tempfile.TemporaryDirectory(prefix="wallet-pub-") as work:
        script = Path(work) / "wallet-public.fif"
        script.write_text(FIFT_PUBLIC_PROGRAM)
        result = runner(
            [str(fift), "-I", str(fift_lib), "-s", str(script), str(key.resolve())],
            timeout=60,
        )
    return parse_fift_public_key(result.stdout)


def previous_wallets(ceremony: Path, derive_public: Any = None) -> dict[str, str]:
    """The wallet identities an earlier epoch's ceremony directory records.

    Reads wallets.json and genesis.json's main_wallet_public_key. A ceremony
    from before either existed gives its bootstrap key through
    secret/main-wallet.pk, from which `derive_public(path) -> bytes` takes the
    public key. A directory that yields nothing is refused.
    """
    ceremony = Path(ceremony)
    if not ceremony.is_dir():
        raise TestnetError(f"previous ceremony {ceremony} is not a directory")
    wallets: dict[str, str] = {}
    path = ceremony / WALLETS_FILE
    if path.is_file():
        wallets = check_wallet_map(json.loads(path.read_text()), str(path))
    genesis_path = ceremony / GENESIS_FILE
    genesis = json.loads(genesis_path.read_text()) if genesis_path.is_file() else {}
    if not isinstance(genesis, dict):
        raise TestnetError(f"{genesis_path} is not a JSON object")
    bootstrap = None
    if "main_wallet_public_key" in genesis:
        key = parse_hex(genesis["main_wallet_public_key"], 32, f"{genesis_path} main wallet key")
        bootstrap = WALLET_PUBKEY_PREFIX + key.hex()
    elif BOOTSTRAP_WALLET_LABEL not in wallets:
        secret = ceremony / "secret" / "main-wallet.pk"
        if secret.exists():
            if derive_public is None:
                raise TestnetError(f"{secret} needs fift to derive its public key")
            bootstrap = WALLET_PUBKEY_PREFIX + bytes(derive_public(secret)).hex()
    if bootstrap is not None:
        if wallets.get(BOOTSTRAP_WALLET_LABEL, bootstrap) != bootstrap:
            raise TestnetError(
                f"previous ceremony {ceremony}: {WALLETS_FILE} and {GENESIS_FILE} disagree "
                "on the bootstrap wallet key"
            )
        wallets[BOOTSTRAP_WALLET_LABEL] = bootstrap
    if not wallets:
        raise TestnetError(
            f"previous ceremony {ceremony} records no wallet identity (no {WALLETS_FILE}, "
            f"no main_wallet_public_key in {GENESIS_FILE}, no secret/main-wallet.pk); "
            "refusing to pass a check that saw nothing"
        )
    return wallets


@contextmanager
def wallet_records_lock(ceremony: Path):
    """Serialize wallet and pool identity updates across ceremony processes."""
    ceremony = Path(ceremony)
    lock_path = ceremony / f".{WALLETS_FILE}.lock"
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        lock = os.open(lock_path, flags, 0o644)
    except OSError as exc:
        raise TestnetError(f"cannot lock {lock_path}: {exc}") from exc
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield
    finally:
        os.close(lock)


def record_wallets(ceremony: Path, wallets: dict[str, str]) -> dict[str, str]:
    """Add wallets to the ceremony's public wallets.json; never change an entry.

    A label already recorded with the same identity is accepted (a rerun); with
    a different identity it is refused. The file is replaced atomically under a
    lock, so concurrent runs against one ceremony do not lose entries. Returns
    the whole record.
    """
    ceremony = Path(ceremony)
    fresh = check_wallet_map(wallets, "the wallet record")
    path = ceremony / WALLETS_FILE
    with wallet_records_lock(ceremony):
        if path.is_symlink():
            raise TestnetError(f"{path} is a symlink")
        existing = (
            check_wallet_map(json.loads(path.read_text()), str(path)) if path.exists() else {}
        )
        merged = dict(existing)
        for label, identity in fresh.items():
            if label in existing and existing[label] != identity:
                raise TestnetError(
                    f"{path} records wallet {label} as {existing[label]}, not {identity}; "
                    "a recorded wallet identity is never changed"
                )
            merged[label] = identity
        if merged != existing or not path.exists():
            tmp = ceremony / f".{WALLETS_FILE}.{os.getpid()}.tmp"
            if tmp.exists() or tmp.is_symlink():
                tmp.unlink()
            write_new_json(tmp, merged)
            os.replace(tmp, path)
        return merged


def manifest_input(records: list[dict[str, Any]]) -> list[dict[str, str]]:
    """The exact input tos scripts/prepare-pq-genesis-manifest.py accepts (order = index)."""
    return [
        {
            "controller_id": r["controller_id"],
            "adnl_id": r["adnl_id"],
            "public_key": r["public_key"],
        }
        for r in records
    ]


def pack_manifest(records: list[dict[str, Any]]) -> bytes:
    """The 5,504-byte validator-pq.pub, computed independently of the tos packer."""
    out = b"".join(
        bytes.fromhex(r["controller_id"])
        + bytes.fromhex(r["adnl_id"])
        + bytes.fromhex(r["public_key"])
        for r in records
    )
    if len(out) != GENESIS_VALIDATORS * (HASH_BYTES * 2 + PQ_PUBLIC_KEY_BYTES):
        raise TestnetError("manifest has the wrong size")
    return out


# ---------------------------------------------------------------- genesis template


def patch_template(
    text: str, global_id: int, epoch: int, schedule: dict[str, int], auth_tag: bytes
) -> str:
    """Return the canonical template with its mainnet pins and schedule replaced
    and the AUTH network tag defined.

    `schedule` is what validator_schedule() returns, `auth_tag` what
    supplied_auth_network_tag() returns. Each replaced line must occur exactly
    once. A template that changed around these lines has not been reviewed for a
    testnet ceremony and is refused, and so is one that already defines a tag
    or selects the frozen admission candidate.
    """
    check_global_id(global_id)
    tag = check_auth_network_tag(auth_tag.hex() if isinstance(auth_tag, bytes) else auth_tag)
    if text.count(TEMPLATE_AUTH_GUARD_LINE) != 1:
        raise TestnetError("the template's AUTH network tag guard is not there exactly once")
    if f"constant {AUTH_TAG_CONSTANT}" in text or "constant quantum-admission-candidate" in text:
        raise TestnetError("the template already defines an AUTH tag or the admission candidate")
    if not isinstance(epoch, int) or epoch <= 1789434000:
        raise TestnetError("the testnet genesis epoch must be later than the mainnet template's")
    params = " ".join(str(schedule[name]) for name in ELECTION_PARAM_NAMES)
    replacements = (
        (TEMPLATE_GLOBAL_ID_LINE, f"{global_id} setglobalid   // TOS public testnet global_id"),
        (TEMPLATE_EPOCH_LINE, f"{epoch} constant mainnet_genesis_utime"),
        (
            TEMPLATE_EPOCH_ABORT_LINE,
            f'now mainnet_genesis_utime = not abort"SOURCE_DATE_EPOCH must be {epoch} for this TOS testnet genesis"',
        ),
        (TEMPLATE_ELECTION_PARAMS_LINE, f"{params} config.election_params!"),
        (TEMPLATE_INITIAL_SET_LINE, f"{schedule['initial_set_valid_for']} =: orig_vset_valid_for"),
    )
    lines = text.split("\n")
    for old, new in replacements:
        hits = [i for i, line in enumerate(lines) if line == old]
        if len(hits) != 1:
            raise TestnetError(f"template line not found exactly once: {old!r}")
        lines[hits[0]] = new
    if lines[0] != TEMPLATE_FIRST_LINE:
        raise TestnetError(f"the template's first line is not {TEMPLATE_FIRST_LINE!r}")
    lines.insert(
        1,
        f"0x{tag.hex()} constant {AUTH_TAG_CONSTANT}   // TOS public testnet AUTH network tag",
    )
    return "\n".join(lines)


# ---------------------------------------------------------------- AUTH network tag

# The public namespace ConfigParam 48 carries. tos assigns none implicitly: a
# version-16 genesis refuses to run without one (crypto/smartcont/gen-zerostate.fif),
# and tos tooling takes it as 64 hexadecimal digits in TOS_AUTH_NETWORK_TAG.
AUTH_NETWORK_TAG_ENV = "TOS_AUTH_NETWORK_TAG"
AUTH_TAG_RULE_DOMAIN = "TOS-AUTH-NETWORK-TAG-v1"
# The exact policy identity tos checks (doc/auth-policy-v1.md, crypto/fift/lib/Config.fif).
AUTH_POLICY_PROFILE = (
    b"TOS-AUTH-POLICY-v1;config=48;tag=a1;suite=1;retired=u16;sequence=u64;"
    b"deadline=u32;network=bits256;monotonic"
)
AUTH_POLICY_SPEC_HASH = hashlib.sha256(AUTH_POLICY_PROFILE).digest()
AUTH_POLICY_TAG = 0xA1
# Namespaces others already use: tos's frozen mainnet admission candidate
# (0x42 repeated) and the public test values of tos CI and its harnesses (one
# repeated byte, or bytes 00..1f). A testnet sharing one would share its replay domain.
RESERVED_AUTH_TAGS = {bytes([b]) * 32 for b in range(256)} | {bytes(range(32))}
AUTH_TAG_STATUSES = ("CHOSEN", "CONFIRMED")


def auth_network_tag_rule(network: str, global_id: int, campaign_epoch: int) -> str:
    """The ASCII string whose SHA-256 is a testnet epoch's AUTH network tag."""
    return f"{AUTH_TAG_RULE_DOMAIN};network={network};global_id={global_id};epoch={campaign_epoch}"


def derive_auth_network_tag(network: str, global_id: int, campaign_epoch: int) -> bytes:
    return hashlib.sha256(
        auth_network_tag_rule(network, global_id, campaign_epoch).encode("ascii")
    ).digest()


def check_auth_network_tag(value: Any) -> bytes:
    """A tag as tos takes it: exactly 64 hexadecimal digits, and not a reserved value."""
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise TestnetError("the AUTH network tag must be exactly 64 hexadecimal digits")
    tag = bytes.fromhex(value)
    if tag in RESERVED_AUTH_TAGS:
        raise TestnetError(
            "the AUTH network tag is a reserved value (the mainnet admission candidate's "
            "or a tos test namespace)"
        )
    return tag


def profile_auth_network_tag(profile: dict[str, Any]) -> dict[str, Any]:
    """The profile's AUTH network tag entry, checked against its derivation rule."""
    entry = profile.get("genesis", {}).get("auth_network_tag")
    if not isinstance(entry, dict):
        raise TestnetError("the profile has no genesis.auth_network_tag")
    epoch = entry.get("campaign_epoch")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
        raise TestnetError(f"genesis.auth_network_tag.campaign_epoch is invalid: {epoch!r}")
    if entry.get("status") not in AUTH_TAG_STATUSES:
        raise TestnetError(
            f"genesis.auth_network_tag.status is {entry.get('status')!r}, not one of "
            f"{AUTH_TAG_STATUSES}"
        )
    tag = check_auth_network_tag(entry.get("value"))
    global_id = check_global_id(profile.get("global_id", {}).get("value"))
    network = profile.get("network", "")
    rule = auth_network_tag_rule(network, global_id, epoch)
    if entry.get("rule") != rule or tag != derive_auth_network_tag(network, global_id, epoch):
        raise TestnetError(f"genesis.auth_network_tag is not SHA-256 of {rule!r}")
    return {"tag": tag, "rule": rule, "campaign_epoch": epoch, "status": entry["status"]}


def supplied_auth_network_tag(profile: dict[str, Any], environ: Any) -> bytes:
    """The tag the ceremony runs with: TOS_AUTH_NETWORK_TAG, equal to the profile's.

    The environment is the input tos tooling takes; the profile is what was
    announced. Both must name the same value, so neither a stale shell nor an
    edited profile changes the namespace on its own.
    """
    expected = profile_auth_network_tag(profile)
    value = environ.get(AUTH_NETWORK_TAG_ENV)
    if value is None:
        raise TestnetError(
            f"{AUTH_NETWORK_TAG_ENV} is not set; export the profile's genesis.auth_network_tag "
            f"value ({expected['tag'].hex()})"
        )
    tag = check_auth_network_tag(value)
    if tag != expected["tag"]:
        raise TestnetError(
            f"{AUTH_NETWORK_TAG_ENV} is {value.lower()}, but the profile announces "
            f"{expected['tag'].hex()} ({expected['rule']})"
        )
    return tag


# ---------------------------------------------------------------- bag of cells

BOC_MAGIC = bytes.fromhex("b5ee9c72")


class Cell:
    """An ordinary cell: data bits, references, and its representation hash."""

    __slots__ = ("data", "bits", "refs", "_hash", "_depth")

    def __init__(self, data: bytes, bits: int, refs: list[Cell]):
        self.data, self.bits, self.refs = data, bits, refs
        self._hash: bytes | None = None
        self._depth: int | None = None

    def depth(self) -> int:
        if self._depth is None:
            self._depth = 1 + max(r.depth() for r in self.refs) if self.refs else 0
        return self._depth

    def hash(self) -> bytes:
        """The representation hash (level 0), as the node's get_hash() computes it."""
        if self._hash is None:
            full, rem = divmod(self.bits, 8)
            descriptor = bytes([len(self.refs), full * 2 + (1 if rem else 0)])
            body = self.data[:full]
            if rem:
                kept = self.data[full] & (0xFF << (8 - rem)) & 0xFF
                body += bytes([kept | (0x80 >> rem)])
            digest = hashlib.sha256(descriptor + body)
            for ref in self.refs:
                digest.update(ref.depth().to_bytes(2, "big"))
            for ref in self.refs:
                digest.update(ref.hash())
            self._hash = digest.digest()
        return self._hash


def cell_from_bits(bits: str, refs: Any = ()) -> Cell:
    """An ordinary cell from a string of 0/1 and its references."""
    if len(bits) > 1023 or set(bits) - {"0", "1"} or len(refs) > 4:
        raise TestnetError("not a cell: at most 1023 bits and 4 references")
    padded = bits + "0" * (-len(bits) % 8)
    data = int(padded, 2).to_bytes(len(padded) // 8, "big") if bits else b""
    return Cell(data, len(bits), list(refs))


class Slice:
    """Reads a cell's bits and references in order."""

    def __init__(self, cell: Cell):
        self.cell, self.pos, self.ref = cell, 0, 0

    def remaining(self) -> int:
        return self.cell.bits - self.pos

    def bits(self, n: int) -> int:
        if n < 0 or self.pos + n > self.cell.bits:
            raise TestnetError("cell underflow")
        value = 0
        for i in range(self.pos, self.pos + n):
            value = (value << 1) | ((self.cell.data[i // 8] >> (7 - i % 8)) & 1)
        self.pos += n
        return value

    def bytes(self, n: int) -> bytes:
        return self.bits(8 * n).to_bytes(n, "big") if n else b""

    def take_ref(self) -> Cell:
        if self.ref >= len(self.cell.refs):
            raise TestnetError("cell has no more references")
        self.ref += 1
        return self.cell.refs[self.ref - 1]

    def end(self) -> bool:
        return self.remaining() == 0 and self.ref == len(self.cell.refs)


def serialize_boc(root: Cell) -> bytes:
    """A single-root bag of ordinary cells, without index or checksum."""
    order: list[Cell] = []
    seen: set[int] = set()

    def visit(cell: Cell) -> None:
        if id(cell) in seen:
            return
        seen.add(id(cell))
        for ref in cell.refs:
            visit(ref)
        order.append(cell)

    visit(root)
    order.reverse()
    index = {id(cell): i for i, cell in enumerate(order)}
    ref_size = 1 if len(order) < 256 else 2
    body = bytearray()
    for cell in order:
        full, rem = divmod(cell.bits, 8)
        data = cell.data[:full]
        if rem:
            data += bytes([(cell.data[full] & (0xFF << (8 - rem)) & 0xFF) | (0x80 >> rem)])
        body += bytes([len(cell.refs), full * 2 + (1 if rem else 0)]) + data
        for ref in cell.refs:
            body += index[id(ref)].to_bytes(ref_size, "big")
    count = len(order).to_bytes(ref_size, "big")
    header = bytes([ref_size, 4]) + count + (1).to_bytes(ref_size, "big") + bytes(ref_size)
    return BOC_MAGIC + header + len(body).to_bytes(4, "big") + bytes(ref_size) + bytes(body)


def parse_boc(boc: bytes) -> Cell:
    """The single root of a bag of cells. Only ordinary level-0 cells are admitted."""
    pos = 0

    def take(size: int) -> int:
        nonlocal pos
        if pos + size > len(boc):
            raise TestnetError("the bag of cells is truncated")
        value = int.from_bytes(boc[pos : pos + size], "big")
        pos += size
        return value

    if boc[:4] != BOC_MAGIC or len(boc) < 6:
        raise TestnetError("not a bag of cells")
    pos = 4
    flags = take(1)
    ref_size, off_size = flags & 7, take(1)
    if not 1 <= ref_size <= 4 or not 1 <= off_size <= 8:
        raise TestnetError("the bag of cells has a malformed header")
    count, roots, _absent, _total = take(ref_size), take(ref_size), take(ref_size), take(off_size)
    if roots != 1:
        raise TestnetError(f"the bag of cells has {roots} roots, expected one")
    root = take(ref_size)
    if flags & 0x80:
        take(count * off_size)
    raw: list[tuple[bytes, int, list[int]]] = []
    for _ in range(count):
        d1, d2 = take(1), take(1)
        if d1 & 8 or d1 >> 5:
            raise TestnetError("the bag of cells holds an exotic or higher-level cell")
        if d1 & 16:
            take(32 + 2)
        refs = d1 & 7
        if refs > 4:
            raise TestnetError("a cell has more than four references")
        size = (d2 + 1) // 2
        data = boc[pos : pos + size]
        if len(data) != size:
            raise TestnetError("the bag of cells is truncated")
        pos += size
        bits = 8 * size
        if d2 & 1:
            last = data[-1]
            if not last:
                raise TestnetError("a cell's completion tag is missing")
            bits = 8 * size - (last & -last).bit_length()
        raw.append((data, bits, [take(ref_size) for _ in range(refs)]))
    if root >= count:
        raise TestnetError("the bag of cells names a root it does not hold")
    cells: list[Cell | None] = [None] * count
    for index in range(count - 1, -1, -1):
        data, bits, refs = raw[index]
        if any(r <= index or r >= count for r in refs):
            raise TestnetError("a cell refers backwards or outside the bag")
        cells[index] = Cell(data, bits, [cells[r] for r in refs])  # type: ignore[misc]
    return cells[root]  # type: ignore[return-value]


def hashmap_items(cell: Cell, key_bits: int) -> dict[int, Slice]:
    """Every entry of a non-empty Hashmap key_bits X: key -> a slice at its value."""
    items: dict[int, Slice] = {}

    def walk(node: Cell, prefix: int, left: int) -> None:
        s = Slice(node)
        width = left.bit_length()
        if s.bits(1) == 0:  # hml_short: unary length, then the bits
            length = 0
            while s.bits(1):
                length += 1
            label = s.bits(length) if length <= left else 0
        elif s.bits(1) == 0:  # hml_long
            length = s.bits(width)
            label = s.bits(length) if length <= left else 0
        else:  # hml_same
            bit = s.bits(1)
            length = s.bits(width)
            label = ((1 << length) - 1) if bit else 0
        if length > left:
            raise TestnetError("a hashmap label is longer than its key")
        prefix, left = (prefix << length) | label, left - length
        if left == 0:
            items[prefix] = s
            return
        for branch in (0, 1):
            walk(s.take_ref(), (prefix << 1) | branch, left - 1)

    walk(cell, 0, key_bits)
    return items


# ---------------------------------------------------------------- zero state AUTH policy

SHARD_STATE_TAG = 0x9023AFE2
MC_STATE_EXTRA_TAG = 0xCC26
CONFIG_VERSION_TAG = 0xC4


def zero_state_config(boc: bytes) -> tuple[Cell, int, dict[int, Cell]]:
    """The zero state's root cell, global id and ConfigParams (number -> cell)."""
    root = parse_boc(boc)
    s = Slice(root)
    if s.bits(32) != SHARD_STATE_TAG:
        raise TestnetError("the zero state is not a ShardStateUnsplit")
    global_id = s.bits(32)
    global_id -= (global_id >> 31) << 32
    if len(root.refs) != 4:
        raise TestnetError("the zero state has no masterchain extra (McStateExtra)")
    extra = Slice(root.refs[3])
    if extra.bits(16) != MC_STATE_EXTRA_TAG:
        raise TestnetError("the zero state's McStateExtra has the wrong tag")
    if extra.bits(1):
        extra.take_ref()  # shard_hashes
    extra.bits(256)  # config_addr
    params = {}
    for number, value in hashmap_items(extra.take_ref(), 32).items():
        params[number] = value.take_ref()
    return root, global_id, params


def config_version(cell: Cell) -> tuple[int, int]:
    """ConfigParam 8: (global version, capabilities)."""
    s = Slice(cell)
    if cell.bits != 104 or cell.refs or s.bits(8) != CONFIG_VERSION_TAG:
        raise TestnetError("ConfigParam 8 is not capabilities#c4")
    return s.bits(32), s.bits(64)


def auth_policy(cell: Cell) -> dict[str, Any]:
    """ConfigParam 48 decoded as tos unpack_auth_policy reads it, or a refusal."""
    s = Slice(cell)
    if cell.bits != 601 or s.bits(8) != AUTH_POLICY_TAG:
        raise TestnetError("ConfigParam 48 is not an a1 AUTH policy record")
    network = s.bytes(32)
    sequence, retired = s.bits(64), s.bits(16)
    if retired & ~2:
        raise TestnetError(f"ConfigParam 48 retires an unknown suite ({retired:#x})")
    has_schedule = s.bits(1)
    if len(cell.refs) != has_schedule:
        raise TestnetError("ConfigParam 48 schedule reference does not match its flag")
    deadline = None
    if has_schedule:
        entries = hashmap_items(s.take_ref(), 8)
        if list(entries) != [1] or entries[1].remaining() != 32:
            raise TestnetError("ConfigParam 48 schedule is not one suite-1 deadline")
        deadline = entries[1].bits(32)
    if s.bytes(32) != AUTH_POLICY_SPEC_HASH or not s.end():
        raise TestnetError("ConfigParam 48 does not carry the v1 policy identity")
    return {"network": network, "sequence": sequence, "retired": retired, "deadline": deadline}


def zero_state_gas_credits(boc: bytes) -> dict[int, int]:
    """Refuse a newly generated genesis with a different admission credit profile."""
    params = zero_state_config(boc)[2]
    credits = {}
    for number, expected in ((20, 10000), (21, 20000)):
        if number not in params:
            raise TestnetError(f"the zero state has no ConfigParam {number}")
        prices = Slice(params[number])
        try:
            tag = prices.bits(8)
            if tag == 0xD1:  # gas_flat_pfx
                prices.bits(64)
                prices.bits(64)
                tag = prices.bits(8)
            if tag not in (0xDD, 0xDE):
                raise TestnetError(f"ConfigParam {number} has an unknown gas price tag")
            for _ in range(3 if tag == 0xDE else 2):  # special_gas_limit exists only in #de
                prices.bits(64)
            credits[number] = prices.bits(64)
            for _ in range(3):  # block_gas_limit, freeze_due_limit, delete_due_limit
                prices.bits(64)
        except TestnetError as error:
            if "unknown gas price tag" in str(error):
                raise
            raise TestnetError(f"ConfigParam {number} is malformed: {error}") from error
        if not prices.end():
            raise TestnetError(f"ConfigParam {number} has data after its gas prices")
        if credits[number] != expected:
            raise TestnetError(
                f"ConfigParam {number} gas_credit is {credits[number]}, expected {expected}"
            )
    return credits


def zero_state_auth_policy(
    boc: bytes, root_hash: bytes, global_id: int, global_version: int, tag: bytes
) -> dict[str, Any]:
    """Check a version-16 zero state's AUTH policy and return what the ceremony records.

    The conditions tos validate_auth_policy_config applies (ConfigParam 48
    present and well formed, and in both ConfigParam 9 and 10 from version 16),
    plus what this genesis must be: this tag, sequence zero, nothing retired, no
    deadline, the profile's global id and version. The parser is first checked
    against create-state's own root hash.
    """
    root, actual_global_id, params = zero_state_config(boc)
    if root.hash() != root_hash:
        raise TestnetError("the zero state's root hash differs from create-state's .rhash")
    if actual_global_id != global_id:
        raise TestnetError(f"the zero state carries global id {actual_global_id}")
    for number in (8, 9, 10, 48):
        if number not in params:
            raise TestnetError(f"the zero state has no ConfigParam {number}")
    version, capabilities = config_version(params[8])
    if version != global_version:
        raise TestnetError(f"ConfigParam 8 is version {version}, expected {global_version}")
    policy = auth_policy(params[48])
    if policy["network"] != tag:
        raise TestnetError(
            f"ConfigParam 48 carries tag {policy['network'].hex()}, expected {tag.hex()}"
        )
    if policy["sequence"] or policy["retired"] or policy["deadline"] is not None:
        raise TestnetError("an initial AUTH policy has sequence 0, nothing retired, no deadline")
    for number, name in ((9, "mandatory"), (10, "critical")):
        if 48 not in hashmap_items(params[number], 32):
            raise TestnetError(f"ConfigParam 48 is not {name} (ConfigParam {number})")
    return {
        "network_tag_hex": tag.hex(),
        "config_param_48_hash_hex": params[48].hash().hex(),
        "policy_identity_sha256": AUTH_POLICY_SPEC_HASH.hex(),
        "sequence": 0,
        "retired": 0,
        "deadline": None,
        "mandatory_and_critical": True,
        "global_version": version,
        "capabilities": capabilities,
    }


# ---------------------------------------------------------------- global config


def zero_state_entry(root_hash: bytes, file_hash: bytes) -> dict[str, Any]:
    if len(root_hash) != HASH_BYTES or len(file_hash) != HASH_BYTES:
        raise TestnetError("zero state hashes are 32 bytes each")
    if not any(root_hash) or not any(file_hash):
        raise TestnetError("zero state hashes must not be zero")
    return {
        "workchain": MASTERCHAIN,
        "shard": MASTERCHAIN_SHARD,
        "seqno": 0,
        "root_hash": b64(root_hash),
        "file_hash": b64(file_hash),
    }


def address_list(ip: str, port: int) -> dict[str, Any]:
    return {
        "@type": "adnl.addressList",
        "addrs": [{"@type": "adnl.address.udp", "ip": ip_to_tl(ip), "port": port}],
        "version": 0,
        "reinit_date": 0,
        "priority": 0,
        "expire_at": 0,
    }


def check_dht_node(node: dict[str, Any]) -> dict[str, Any]:
    """A signed dht.node as generate-random-id -m dht prints it."""
    if node.get("@type") != "dht.node":
        raise TestnetError("DHT node record is not a dht.node")
    node_id = node.get("id", {})
    if node_id.get("@type") != "pub.ed25519":
        raise TestnetError("DHT node id is not pub.ed25519")
    parse_b64(node_id.get("key"), 32, "DHT node public key")
    parse_b64(node.get("signature"), 64, "DHT node signature")
    addrs = node.get("addr_list", {}).get("addrs", [])
    if len(addrs) != 1 or addrs[0].get("@type") != "adnl.address.udp":
        raise TestnetError("DHT node must publish exactly one UDP address")
    require_public_ipv4(str(ipaddress.IPv4Address(addrs[0]["ip"] % 2**32)))
    return node


def global_config(
    zero_state: dict[str, Any], dht_nodes: list[dict[str, Any]], profile: dict[str, Any]
) -> dict[str, Any]:
    if len(dht_nodes) < 2:
        raise TestnetError(
            "publish at least two DHT nodes; one DHT host is a single point of failure"
        )
    keys = [n["id"]["key"] for n in dht_nodes]
    if len(set(keys)) != len(keys):
        raise TestnetError("two DHT node records carry the same key")
    dht = profile["dht"]
    return {
        "@type": "config.global",
        "dht": {
            "@type": "dht.config.global",
            "k": dht["k"],
            "a": dht["a"],
            "static_nodes": {"@type": "dht.nodes", "nodes": [check_dht_node(n) for n in dht_nodes]},
        },
        "validator": {
            "@type": "validator.config.global",
            "zero_state": zero_state,
            "hardforks": [],
        },
    }


def pregenesis_config(profile: dict[str, Any]) -> dict[str, Any]:
    """A global config good only for the engine's first start before genesis exists.

    validator-engine parses -C before it writes config.json on a first start,
    and refuses a zero hash, but it exits right after writing config.json and
    never uses these values. The placeholder hashes spell PREGENESIS so that a
    node accidentally started on this file cannot be mistaken for any network.
    """
    marker = hashlib.sha256(b"TOS-TESTNET-PREGENESIS-PLACEHOLDER").digest()
    return {
        "@type": "config.global",
        "dht": {
            "@type": "dht.config.global",
            "k": profile["dht"]["k"],
            "a": profile["dht"]["a"],
            "static_nodes": {"@type": "dht.nodes", "nodes": []},
        },
        "validator": {
            "@type": "validator.config.global",
            "zero_state": zero_state_entry(marker, marker),
            "hardforks": [],
        },
    }


def is_pregenesis(config: dict[str, Any]) -> bool:
    marker = b64(hashlib.sha256(b"TOS-TESTNET-PREGENESIS-PLACEHOLDER").digest())
    return config.get("validator", {}).get("zero_state", {}).get("root_hash") == marker


# ---------------------------------------------------------------- JSON-RPC


RPC_REQUEST_ID = 1
# The statuses the node answers with before a method runs (json-rpc-http-policy.h:
# authentication, unknown GET path, method, content type, rate limit), each with
# the same JSON-RPC error body. Every method error is HTTP 200.
RPC_PRE_DISPATCH_STATUSES = (401, 404, 405, 415, 429)


class RpcError(TestnetError):
    """A node's JSON-RPC 2.0 error object (tos validator-engine/json-rpc-contract.h).

    `reason` is the stable machine-readable name a client branches on, `code` the
    JSON-RPC code it travels under, `retryable` whether the same request can
    succeed later (a timeout, a node not ready, a rate limit).
    """

    def __init__(
        self, url: str, method: str, code: int, reason: str, message: str, retryable: bool
    ):
        super().__init__(f"{url} {method}: {reason or 'error'} {code}: {message}")
        self.code, self.reason, self.message, self.retryable = code, reason, message, retryable


def rpc_result(answer: Any, url: str, method: str) -> Any:
    """The result of one decoded JSON-RPC 2.0 answer, or a refusal.

    The node answers {jsonrpc: "2.0", id, result} or {jsonrpc: "2.0", id,
    error: {code, message, data: {schema_version, reason, retryable}}}, at
    HTTP 200 for every method error. Anything else (no envelope, another id,
    both or neither of result and error, an error that is not an object) is
    refused rather than read.
    """
    if not isinstance(answer, dict) or answer.get("jsonrpc") != "2.0":
        raise TestnetError(f"{url} {method}: not a JSON-RPC 2.0 answer: {str(answer)[:200]}")
    # A refusal made before the request was read (rate limit, authentication) cannot
    # know the id and answers with id null; a result always echoes the id.
    if answer.get("id") != RPC_REQUEST_ID and not ("error" in answer and answer.get("id") is None):
        raise TestnetError(f"{url} {method}: the answer is for request id {answer.get('id')!r}")
    if ("error" in answer) == ("result" in answer):
        raise TestnetError(f"{url} {method}: the answer has both or neither of result and error")
    if "result" in answer:
        return answer["result"]
    error = answer["error"]
    if (
        not isinstance(error, dict)
        or not isinstance(error.get("code"), int)
        or isinstance(error.get("code"), bool)
        or not isinstance(error.get("message"), str)
    ):
        raise TestnetError(f"{url} {method}: malformed JSON-RPC error {str(error)[:200]}")
    data = error.get("data") if isinstance(error.get("data"), dict) else {}
    reason = data.get("reason") if isinstance(data.get("reason"), str) else ""
    raise RpcError(
        url, method, error["code"], reason, error["message"], data.get("retryable") is True
    )


def rpc(url: str, method: str, /, timeout: float = 10, **params: Any) -> Any:
    """One JSON-RPC 2.0 call with named parameters. Environment proxies are
    ignored: the named node must answer.

    `url` and `method` are positional-only, so a call's own parameters may use
    those names: `runGetMethod` takes the getter as its `method` parameter.
    The node refuses positional (array) parameters; this sends none. A method
    error raises RpcError. A refusal made before the method runs (401, 404,
    405, 415, 429) carries the same error body and raises RpcError too; a
    status without a JSON-RPC body raises TestnetError.
    """
    body = json.dumps(
        {"jsonrpc": "2.0", "id": RPC_REQUEST_ID, "method": method, "params": params}
    ).encode()
    request = urllib.request.Request(url, body, {"Content-Type": "application/json"}, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            answer = json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code not in RPC_PRE_DISPATCH_STATUSES:
            raise TestnetError(f"{url} {method}: HTTP {exc.code}") from exc
        try:
            answer = json.load(exc)
        except ValueError:
            raise TestnetError(f"{url} {method}: HTTP {exc.code} without a JSON-RPC body") from exc
        if not isinstance(answer, dict) or "error" not in answer:
            raise TestnetError(f"{url} {method}: HTTP {exc.code}: {str(answer)[:200]}") from exc
    except ValueError as exc:
        raise TestnetError(f"{url} {method}: the answer is not JSON") from exc
    return rpc_result(answer, url, method)
