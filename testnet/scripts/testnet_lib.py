"""Shared helpers for the public testnet ceremony and operator scripts.

Standard library only: an operator host runs these without a tos Python
environment. Every function that writes refuses to overwrite and never follows
a symlink, because the ceremony outputs (manifest, zerostate, global config)
are published and must not change silently once produced.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
import urllib.request
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
TEMPLATE_INITIAL_SET_LINE = "131072 =: orig_vset_valid_for"

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


def patch_template(text: str, global_id: int, epoch: int, schedule: dict[str, int]) -> str:
    """Return the canonical template with its mainnet pins and schedule replaced.

    `schedule` is what validator_schedule() returns. Each replaced line must
    occur exactly once. A template that changed around these lines has not been
    reviewed for a testnet ceremony and is refused.
    """
    check_global_id(global_id)
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
    return "\n".join(lines)


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


def rpc(url: str, method: str, timeout: float = 10, **params: Any) -> Any:
    """One JSON-RPC 2.0 call. Environment proxies are ignored: the named node must answer."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(url, body, {"Content-Type": "application/json"}, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=timeout) as response:
        answer = json.load(response)
    if answer.get("error") or "result" not in answer:
        raise TestnetError(f"{url} {method}: {answer.get('error', answer)}")
    return answer["result"]
