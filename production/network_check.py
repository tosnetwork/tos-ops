"""Shared HTTP network checks and anchored consensus verification.

The existing cell and RPC codecs are reused, not copied. Network-specific
profiles and genesis-validator policies belong to the entry points.
"""

from __future__ import annotations

import base64
import ctypes as ct
import hashlib
import json
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "testnet/scripts"))
import testnet_lib as lib  # noqa: E402

SHARD = str(lib.MASTERCHAIN_SHARD)
NetworkError = lib.TestnetError
ELECTOR = "-1:" + "3" * 64


def full_id(block: dict) -> tuple:
    return tuple(str(block[k]) for k in ("workchain", "shard", "seqno", "root_hash", "file_hash"))


def decode_config34(boc_b64: str) -> dict:
    """The testnet CLI's public decoder shape, backed by the shared parser."""
    value = decode_set(lib.parse_boc(base64.b64decode(boc_b64, validate=True)))
    return {
        "utime_since": value["since"],
        "utime_until": value["until"],
        "total": value["total"],
        "main": value["main"],
        "validators": [
            {"validator_id_hex": row["id"], "consensus_key_id_hex": row["key_id"]}
            for row in value["validators"]
        ],
    }


def config_cell(rpc, url: str, param: int, height: int) -> lib.Cell:
    answer = rpc(url, "getConfigParam", param=param, seqno=height)
    return lib.parse_boc(base64.b64decode(answer["config"]["bytes"]))


def check_auth_policy(rpc, url: str, height: int, genesis: dict) -> dict:
    """The live AUTH policy at `height`: the genesis tag, mandatory and critical,
    and the version at least the genesis one. A governance replacement may move
    the sequence on; the tag never changes, so a different tag is the refusal."""
    recorded = genesis["auth_policy"]
    version, _ = lib.config_version(config_cell(rpc, url, 8, height))
    if version < int(genesis["global_version"]):
        raise lib.TestnetError(f"ConfigParam 8 is version {version} at block {height}")
    cell = config_cell(rpc, url, 48, height)
    policy = lib.auth_policy(cell)
    if policy["network"].hex() != recorded["network_tag_hex"].lower():
        raise lib.TestnetError(
            f"live ConfigParam 48 carries tag {policy['network'].hex()}, the genesis "
            f"{recorded['network_tag_hex']}"
        )
    for number, name in ((9, "mandatory"), (10, "critical")):
        if 48 not in lib.hashmap_items(config_cell(rpc, url, number, height), 32):
            raise lib.TestnetError(f"live ConfigParam 48 is not {name} (ConfigParam {number})")
    return {
        "version": version,
        "network_tag_hex": policy["network"].hex(),
        "sequence": policy["sequence"],
        "hash_hex": cell.hash().hex(),
        "unchanged_since_genesis": cell.hash().hex()
        == recorded["config_param_48_hash_hex"].lower(),
        "mandatory_and_critical": True,
    }


def check_agreement(args, identity, rpc=lib.rpc, now=time.time, audit=None):
    def event(label, evidence=None):
        if audit is not None:
            audit(label, evidence)

    event("node_count")
    if len(set(args.rpc)) < 2:
        raise lib.TestnetError("name at least two distinct nodes")
    event("node_count", {"distinct_endpoints": len(set(args.rpc))})
    event("zero_state")
    global_id = identity["global_id"]
    zero = identity["zero_state"]
    expected_zero = (str(lib.MASTERCHAIN), SHARD, "0", zero["root_hash"], zero["file_hash"])

    infos = {}
    for url in args.rpc:
        info = rpc(url, "getMasterchainInfo")
        if full_id(info["init"]) != expected_zero:
            raise lib.TestnetError(
                f"{url} runs a different zero state: it belongs to another network"
            )
        infos[url] = info
    event("zero_state", zero)
    event("common_full_block_id")
    height = min(int(info["last"]["seqno"]) for info in infos.values())
    if height < 1:
        raise lib.TestnetError("no masterchain block after the zero state yet")

    headers = {
        url: rpc(url, "getBlockHeader", workchain=lib.MASTERCHAIN, shard=SHARD, seqno=height)
        for url in args.rpc
    }
    ids = {url: full_id(h["id"]) for url, h in headers.items()}
    if len(set(ids.values())) != 1:
        raise lib.TestnetError(f"nodes disagree on masterchain block {height}: {ids}")
    event("common_full_block_id", next(iter(headers.values()))["id"])
    event("global_id")
    header = next(iter(headers.values()))
    foreign = {
        url: h["global_id"] for url, h in headers.items() if int(h["global_id"]) != global_id
    }
    if foreign:
        raise lib.TestnetError(
            f"block {height} carries wrong global ids {foreign}, expected {global_id}"
        )
    event("global_id", global_id)
    event("head_freshness")
    age = int(now()) - int(header["gen_utime"])

    # Freshness is judged per node, at each node's own head: one node behind is
    # not the network stalled, and the two need different responses.
    nodes = {}
    for url, info in infos.items():
        head = int(info["last"]["seqno"])
        own = rpc(url, "getBlockHeader", workchain=lib.MASTERCHAIN, shard=SHARD, seqno=head)
        nodes[url] = {"head": head, "age_seconds": int(now()) - int(own["gen_utime"])}
    newest = max(node["head"] for node in nodes.values())
    newest_age = min(node["age_seconds"] for node in nodes.values())
    if newest_age > args.max_age:
        raise lib.TestnetError(
            f"no node has a head younger than {args.max_age} s; the newest, {newest}, "
            f"is {newest_age} s old: progress stalled"
        )
    behind = {url: node for url, node in nodes.items() if node["age_seconds"] > args.max_age}
    if behind:
        detail = "; ".join(
            f"{url} at {node['head']} ({newest - node['head']} blocks behind, "
            f"head {node['age_seconds']} s old)"
            for url, node in behind.items()
        )
        raise lib.TestnetError(f"the network is at {newest}, but a node is behind: {detail}")

    event("head_freshness", {url: node["age_seconds"] for url, node in nodes.items()})
    summary = {
        "height": height,
        "block": dict(
            zip(("workchain", "shard", "seqno", "root_hash", "file_hash"), ids[args.rpc[0]])
        ),
        "age_seconds": age,
        "global_id": global_id,
        "nodes": len(args.rpc),
        "heads": {url: node["head"] for url, node in nodes.items()},
        "head_ages": {url: node["age_seconds"] for url, node in nodes.items()},
    }
    return summary


def require(ok, reason):
    if not ok:
        raise NetworkError(reason)


def hash_bytes(value):
    require(isinstance(value, str), "hash must be a string")
    try:
        raw = bytes.fromhex(value) if len(value) == 64 else base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise NetworkError("invalid 256-bit hash") from exc
    require(len(raw) == 32, "hash is not 256 bits")
    return raw


def identity_from_config(config, global_id):
    require(type(global_id) is int and -(1 << 31) <= global_id < (1 << 31), "invalid global id")
    validator = config.get("validator", {})
    zero = validator.get("zero_state")
    require(isinstance(zero, dict), "global config has no validator.zero_state")
    zero = normalize_id(zero)
    require(zero["seqno"] == 0, "zero-state anchor must have seqno 0")
    anchor = normalize_id(validator.get("init_block", zero))
    require(anchor["seqno"] >= 0, "negative init-block anchor")
    require(anchor["seqno"] != 0 or anchor == zero, "conflicting zero and init anchors")
    return {"global_id": global_id, "zero_state": zero, "anchor": anchor}


def normalize_id(block):
    require(int(block["workchain"]) == -1, "anchor/target is not masterchain")
    require(str(block["shard"]) in (SHARD, "8000000000000000"), "invalid masterchain shard")
    require(type(block["seqno"]) is int and 0 <= block["seqno"] < (1 << 31), "invalid seqno")
    return {
        "workchain": -1,
        "shard": SHARD,
        "seqno": block["seqno"],
        **{k: base64.b64encode(hash_bytes(block[k])).decode() for k in ("root_hash", "file_hash")},
    }


def native_id(block):
    block = normalize_id(block)
    return {
        **block,
        "shard": "8000000000000000",
        **{k: hash_bytes(block[k]).hex() for k in ("root_hash", "file_hash")},
    }


def read_dict(source, bits):
    return lib.hashmap_items(source.take_ref(), bits) if source.bits(1) else {}


def coins(source):
    return source.bits(source.bits(4) * 8)


def decode_set(cell):
    """Decode the committed set, re-deriving every PQ key identity."""
    s = lib.Slice(cell)
    tag = s.bits(8)
    require(tag in (0x11, 0x12), "invalid validator-set tag")
    since, until, total, main = s.bits(32), s.bits(32), s.bits(16), s.bits(16)
    weight_sum = s.bits(64) if tag == 0x12 else None
    if tag == 0x12:
        entries = read_dict(s, 16)
    else:
        count = s.remaining()
        tail = lib.cell_from_bits(
            format(s.bits(count), f"0{count}b") if count else "", s.cell.refs[s.ref :]
        )
        s.ref = len(s.cell.refs)
        entries = lib.hashmap_items(tail, 16)
    require(s.end() and 0 < main <= total <= 400, "invalid validator-set dimensions")
    require(sorted(entries) == list(range(total)), "validator indices are not contiguous")
    rows = []
    for i, v in sorted(entries.items()):
        kind = v.bits(8)
        if kind == 0xB3:
            validator, algorithm, key_id = v.bytes(32), v.bits(16), v.bytes(32)
            weight, adnl = v.bits(64), v.bytes(32)
            root = lib.Slice(v.take_ref())
            length = root.bits(32)
            require(length == 1312 and root.remaining() == 0, "invalid PQ public-key length")
            current, raw = lib.Slice(root.take_ref()), bytearray()
            require(root.end(), "invalid PQ bytes root")
            while len(raw) < length:
                n = min(127, length - len(raw))
                require(current.remaining() == n * 8, "invalid PQ byte chunk")
                raw.extend(current.bytes(n))
                nxt = current.take_ref() if len(raw) < length else None
                require(current.end(), "trailing PQ key data")
                if nxt is not None:
                    current = lib.Slice(nxt)
            require(algorithm == 1, "unsupported PQ algorithm")
            derived = hashlib.sha256(b"TOS-PQ-CONSENSUS-KEY-v1" + b"\x01\x00" + raw).digest()
            require(key_id == derived, "validator key id differs from public key")
            public_key = bytes(raw)
        elif kind in (0x53, 0x73):
            require(v.bits(32) == 0x8E81278A, "invalid classical public-key tag")
            public_key, weight = v.bytes(32), v.bits(64)
            adnl = v.bytes(32) if kind == 0x73 else bytes(32)
            validator, key_id, algorithm = public_key, public_key, 0
        else:
            raise NetworkError("unsupported validator descriptor")
        require(v.end() and weight > 0, "invalid validator entry")
        rows.append(
            {
                "index": i,
                "id": validator.hex(),
                "algorithm": algorithm,
                "key_id": key_id.hex(),
                "public_key": public_key.hex(),
                "adnl": adnl.hex(),
                "weight": weight,
            }
        )
    require(len({v["id"] for v in rows}) == total, "duplicate validator identity")
    require(len({v["key_id"] for v in rows}) == total, "duplicate consensus key")
    require(since < until, "invalid validator term")
    require(weight_sum is None or weight_sum == sum(v["weight"] for v in rows), "wrong set weight")
    return {
        "hash": cell.hash().hex(),
        "since": since,
        "until": until,
        "total": total,
        "main": main,
        "validators": rows,
    }


def decode_elector(data):
    """Read the Elector's retained commitment and original elected weights.

    Frozen records intentionally do not retain key material. The saved vset_hash
    commits to its complete serialized set, including keys, ADNL, ordering and term.
    """
    s = lib.Slice(data)
    for _ in range(2):
        if s.bits(1):
            s.take_ref()
    past = read_dict(s, 32)
    coins(s)
    active_id, active_hash = s.bits(32), s.bytes(32).hex()
    if s.remaining():
        if s.bits(1):
            s.take_ref()
    require(s.end(), "trailing elector data")
    result = []
    for election_id, p in past.items():
        unfreeze, held, commitment = p.bits(32), p.bits(32), p.bytes(32).hex()
        frozen = read_dict(p, 256)
        total_stake, bonuses = coins(p), coins(p)
        read_dict(p, 256)
        require(p.end(), "trailing past-election data")
        members = []
        for validator_id, v in frozen.items():
            owner, weight, stake, banned = v.bytes(32).hex(), v.bits(64), coins(v), v.bits(1)
            require(v.end(), "trailing frozen-stake data")
            members.append(
                {
                    "id": f"{validator_id:064x}",
                    "owner": owner,
                    "weight": weight,
                    "stake": stake,
                    "banned": bool(banned),
                }
            )
        result.append(
            {
                "election_id": election_id,
                "unfreeze_at": unfreeze,
                "stake_held": held,
                "hash": commitment,
                "members": members,
                "total_stake": total_stake,
                "bonuses": bonuses,
            }
        )
    return {"active_id": active_id, "active_hash": active_hash, "past": result}


def compare_elected(vset, elector):
    matching = [p for p in elector["past"] if p["hash"] == vset["hash"]]
    matched_ids = [p["election_id"] for p in matching]
    require(
        vset["hash"] == elector["active_hash"],
        f"validator set commitment matches elections {matched_ids}, not Elector active election "
        f"{elector['active_id']} ({elector['active_hash']})",
    )
    matching = [p for p in matching if p["election_id"] == elector["active_id"]]
    require(len(matching) == 1, "validator set has no unique Elector result commitment")
    past = matching[0]
    actual = {v["id"]: v["weight"] for v in vset["validators"]}
    expected = {v["id"]: v["weight"] for v in past["members"]}
    require(
        actual == expected, "Config validator members/weights differ from Elector frozen result"
    )
    return {
        "status": "PASS",
        "election_id": past["election_id"],
        "set_hash": vset["hash"],
        "members": len(actual),
        "keys_and_order_bound_by": "Elector vset_hash",
        "validators": [
            {k: row[k] for k in ("id", "algorithm", "key_id", "weight", "adnl")}
            | {"public_key_sha256": hashlib.sha256(bytes.fromhex(row["public_key"])).hexdigest()}
            for row in vset["validators"]
        ],
    }


def elector_address(cell):
    require(cell.bits == 256 and not cell.refs, "Config1 is not an Elector address")
    return "-1:" + lib.Slice(cell).bytes(32).hex()


def account_data(state_boc, address):
    """Extract StateInit data from a proven ordinary Account cell."""
    s = lib.Slice(lib.parse_boc(state_boc))
    require(s.bits(1) == 1 and s.bits(2) == 2 and s.bits(1) == 0, "invalid account address")
    wc = s.bits(8)
    wc = wc - 256 if wc >= 128 else wc
    require(f"{wc}:{s.bytes(32).hex()}" == address, "proven account names another address")
    for _ in range(2):
        s.bits(s.bits(3) * 8)
    extra = s.bits(3)
    require(extra in (0, 1), "unsupported storage-extra tag")
    if extra:
        s.bits(256)
    s.bits(32)
    if s.bits(1):
        coins(s)
    s.bits(64)
    coins(s)
    read_dict(s, 32)
    require(s.bits(1) == 1, "Elector account is not active")
    if s.bits(1):
        s.bits(5)
    if s.bits(1):
        s.bits(2)
    if s.bits(1):
        s.take_ref()
    require(s.bits(1) == 1, "Elector account has no data")
    data = s.take_ref()
    read_dict(s, 256)
    require(s.end(), "trailing proven account bits")
    return data


class PacedRpc:
    """Read-only, bounded HTTP transport; one request per 450 ms per node."""

    allowed = {
        "getMasterchainInfo",
        "getBlockHeader",
        "lookupBlock",
        "getConfigParam",
        "getAddressInformation",
        "getProofQuery",
    }

    def __init__(self, timeout=15, interval=0.45):
        self.timeout, self.interval, self.last = timeout, interval, {}
        self.evidence = []

    def __call__(self, url, method, **params):
        require(method in self.allowed, "checker refuses a non-read-only RPC")
        time.sleep(max(0, self.interval - (time.monotonic() - self.last.get(url, 0))))
        self.last[url] = time.monotonic()
        raw = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        req = urllib.request.Request(url, raw, {"Content-Type": "application/json"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=self.timeout) as response:
            body = response.read((96 << 20) + 1)
        require(len(body) <= 96 << 20, "RPC response exceeds byte budget")
        answer = json.loads(body)
        self.evidence.append(
            {
                "url": url,
                "method": method,
                "params": params,
                "response_sha256": hashlib.sha256(body).hexdigest(),
            }
        )
        return lib.rpc_result(answer, url, method)


class Material(ct.Structure):
    _fields_ = [("kind", ct.c_uint32), ("data", ct.c_void_p), ("size", ct.c_size_t)]


QUERY = ct.CFUNCTYPE(
    ct.c_int,
    ct.c_void_p,
    ct.c_void_p,
    ct.c_size_t,
    ct.c_void_p,
    ct.c_size_t,
    ct.POINTER(ct.c_size_t),
)
EMIT = ct.CFUNCTYPE(ct.c_int, ct.c_void_p, ct.c_uint32, ct.c_void_p, ct.c_size_t)


class ProofVerifier:
    """Only the existing consensus verifier decides whether a proof is valid."""

    def __init__(self, library):
        try:
            self.library = ct.CDLL(str(library))
            self.acquire = self.library.tos_proof_acquire
            self.verify = self.library.tos_proof_verify_embedded
        except (OSError, AttributeError) as exc:
            raise NetworkError(
                f"cannot load consensus proof ABI: {exc}; build target tos-proof-embedded "
                "using production/scripts/README.md#build-the-verifier"
            ) from exc
        self.acquire.restype = ct.c_int
        self.acquire.argtypes = [
            ct.c_char_p,
            ct.c_size_t,
            ct.c_char_p,
            ct.c_size_t,
            ct.c_char_p,
            ct.c_size_t,
            QUERY,
            ct.c_void_p,
            EMIT,
            ct.c_void_p,
        ]
        self.verify.restype = ct.c_int
        self.verify.argtypes = [
            ct.c_char_p,
            ct.c_size_t,
            ct.c_char_p,
            ct.c_size_t,
            ct.c_char_p,
            ct.c_size_t,
            ct.c_int64,
            ct.POINTER(Material),
            ct.c_size_t,
            ct.c_void_p,
            ct.c_size_t,
            ct.POINTER(ct.c_size_t),
            ct.c_void_p,
            ct.c_size_t,
            ct.POINTER(ct.c_size_t),
        ]

    def verify_material(self, anchor, request, parts, now):
        a, r = json.dumps(anchor).encode(), json.dumps(request).encode()
        buffers = [ct.create_string_buffer(raw) for _, raw in parts]
        entries = (Material * len(parts))(
            *[
                Material(kind, ct.cast(buf, ct.c_void_p), len(raw))
                for (kind, raw), buf in zip(parts, buffers)
            ]
        )
        output, state = ct.create_string_buffer(8 << 20), ct.create_string_buffer(1 << 20)
        used, state_used = ct.c_size_t(), ct.c_size_t()
        status = self.verify(
            a,
            len(a),
            r,
            len(r),
            None,
            0,
            int(now),
            entries,
            len(parts),
            output,
            len(output),
            ct.byref(used),
            state,
            len(state),
            ct.byref(state_used),
        )
        require(status == 0, f"anchored proof verification refused ({status})")
        require(0 < used.value <= len(output) and state_used.value == 0, "invalid verifier output")
        result = json.loads(output.raw[: used.value])
        require(
            result.get("request_sha256") == hashlib.sha256(r).hexdigest(),
            "verifier request digest differs",
        )
        require(
            result.get("status") == "verified" and result.get("interface") == "tos-proof-verify/1",
            "verifier did not return an authenticated result",
        )
        require(
            result["anchor"]["kind"] == anchor["kind"]
            and normalize_id(result["anchor"]) == normalize_id(anchor),
            "verifier anchor differs",
        )
        require(
            normalize_id(result["target"]) == normalize_id(request["target"]),
            "verifier target differs",
        )
        return result

    def fetch(self, rpc, url, anchor, target, params, now, account=ELECTOR):
        a = native_id(anchor)
        a["kind"] = "zerostate" if a["seqno"] == 0 else "key_block"
        request = {
            "mode": "historical",
            "target": native_id(target),
            "config_params": params,
            "account": account,
        }
        aa, rr = json.dumps(a).encode(), json.dumps(request).encode()
        parts, errors, budget = [], [], [0]
        deadline = time.monotonic() + 180

        @QUERY
        def query(_ctx, data, size, output, capacity, used):
            try:
                require(time.monotonic() < deadline, "proof acquisition deadline")
                reply = rpc(
                    url, "getProofQuery", query=base64.b64encode(ct.string_at(data, size)).decode()
                )
                raw = base64.b64decode(reply["reply"], validate=True)
                require(0 < len(raw) <= capacity, "proof reply exceeds native budget")
                ct.memmove(output, raw, len(raw))
                used[0] = len(raw)
                return 0
            except Exception as exc:
                errors.append(exc)
                return -1

        @EMIT
        def emit(_ctx, kind, data, size):
            try:
                budget[0] += size
                require(budget[0] <= 64 << 20 and len(parts) < 256, "proof material limit")
                parts.append((kind, ct.string_at(data, size)))
                return 0
            except Exception as exc:
                errors.append(exc)
                return -1

        status = self.acquire(aa, len(aa), rr, len(rr), None, 0, query, None, emit, None)
        if errors:
            raise errors[0]
        require(status == 0, f"proof acquisition refused ({status})")
        require(time.monotonic() < deadline, "proof acquisition deadline exceeded")
        verified = self.verify_material(a, request, parts, now)
        return verified


def fetch_proof(verifier, rpc, urls, anchor, target, params, now, account=ELECTOR):
    """Try another archival source only when no proof material was available.

    Transport failures mean no material was obtained. Native verification
    errors are not transport or RPC errors and are never retried away.
    """
    unavailable = []
    for url in urls:
        try:
            return verifier.fetch(rpc, url, anchor, target, params, now, account), url, unavailable
        except lib.RpcError as exc:
            missing = (exc.code == -32601 and exc.reason == "METHOD_NOT_FOUND") or (
                exc.reason in ("UPSTREAM_UNAVAILABLE", "STATE_NOT_FOUND", "BLOCK_NOT_FOUND")
                or (
                    exc.code == -32603
                    and exc.reason == "INTERNAL_ERROR"
                    and exc.message == "Proof response unavailable"
                )
            )
            if not missing:
                raise
            unavailable.append({"url": url, "reason": str(exc)})
        except OSError as exc:
            unavailable.append({"url": url, "reason": str(exc)})
    raise NetworkError(f"proof material unavailable from every named source: {unavailable}")


def same_cells(rpc, urls, number, height, optional=False):
    cells = []
    for url in urls:
        try:
            cells.append(config_cell(rpc, url, number, height))
        except lib.RpcError as exc:
            if optional and exc.reason == "CONFIG_PARAM_ABSENT" and exc.code == -32004:
                cells.append(None)
            else:
                raise
    hashes = [c.hash().hex() if c else None for c in cells]
    require(len(set(hashes)) == 1, f"nodes disagree on ConfigParam {number}")
    return cells[0]


def check_election_sets(sets, elector, initial, initial_hash=None):
    """A genesis set was not elected; never claim it matched a nonexistent election."""
    current = decode_set(sets[34])
    if not any(p["hash"] == current["hash"] for p in elector["past"]) and initial:
        require(current["hash"] == initial_hash, "unelected current set differs from initial set")
        require(sets.get(32) is None, "genesis-only head unexpectedly has a previous set")
        return {
            "current": {
                "status": "NOT_APPLICABLE",
                "reason": "initial unelected set; no rotation yet",
                "set_hash": current["hash"],
            },
            "previous": {"status": "NOT_APPLICABLE", "reason": "no previous set"},
        }
    compare_elected(current, elector)
    require(sets.get(32) is not None, "elected current set has no ConfigParam 32")
    previous = decode_set(sets[32])
    require(
        previous["since"] < current["since"] and previous["until"] <= current["since"],
        "Config32 is not a previous validator term",
    )
    # Retained records alone do not identify which election was previously active.
    # Check this set against the active result at its authenticated historical head.
    raise NetworkError("previous set requires its historical active Elector result")


def check_network(args, rpc=None, now=time.time, verifier=None):
    rpc = rpc or PacedRpc()
    report = {"ok": False, "checks": []}
    name = "network_identity"

    def passed(label, evidence, status="PASS"):
        report["checks"].append({"name": label, "status": status, "evidence": evidence})

    try:
        identity = identity_from_config(
            json.loads(Path(args.global_config).read_text()), args.global_id
        )
        report["identity"] = identity

        def agreement_event(label, evidence):
            nonlocal name
            name = label
            if evidence is not None:
                passed(label, evidence)

        common = check_agreement(args, identity, rpc, now, agreement_event)
        target = normalize_id({**common["block"], "seqno": int(common["block"]["seqno"])})
        height = target["seqno"]
        name = "held_init_anchor"
        require(identity["anchor"]["seqno"] < height, "common head must be after the held anchor")
        if identity["anchor"]["seqno"]:
            for url in args.rpc:
                held = rpc(
                    url,
                    "getBlockHeader",
                    workchain=-1,
                    shard=SHARD,
                    seqno=identity["anchor"]["seqno"],
                )
                require(
                    full_id(held["id"]) == full_id(identity["anchor"]),
                    "reported init block differs from held anchor",
                )
        passed("held_init_anchor", identity["anchor"])
        name = "head_freshness"
        header = rpc(args.rpc[0], "getBlockHeader", workchain=-1, shard=SHARD, seqno=height)
        require(int(header["gen_utime"]) <= now() + 60, "head timestamp is too far in the future")
        name = "configuration_agreement"
        sets = {
            n: same_cells(rpc, args.rpc, n, height, optional=n == 32)
            for n in (1, 8, 9, 10, 19, 34, 32)
        }
        name = "elector_address"
        elector_addr = elector_address(sets[1])
        passed("elector_address", {"config_param": 1, "address": elector_addr})
        # Config19 and the header must agree, not just one reporter's header.
        name = "config19"
        s = lib.Slice(sets[19])
        gid = s.bits(32)
        gid = gid - (1 << 32) if gid >= (1 << 31) else gid
        require(s.end() and gid == args.global_id, "ConfigParam 19 global id differs")
        passed("config19", gid)
        name = "config8"
        version, capabilities = lib.config_version(sets[8])
        require(version >= args.min_version, "ConfigParam 8 version below required minimum")
        passed("config8", {"version": version, "capabilities": capabilities})
        need_auth = (
            version >= 16
            or 48 in lib.hashmap_items(sets[9], 32)
            or args.expected_auth_tag is not None
            or args.expected_cp48_hash is not None
        )
        if need_auth:
            name = "auth_policy"
            require(
                args.expected_auth_tag or args.expected_cp48_hash,
                "mandatory Config48 requires an independently expected AUTH tag or CP48 hash",
            )
            sets[48] = same_cells(rpc, args.rpc, 48, height)
            policy = lib.auth_policy(sets[48])
            if args.expected_auth_tag:
                require(
                    policy["network"] == hash_bytes(args.expected_auth_tag),
                    "Config48 AUTH tag differs",
                )
            if args.expected_cp48_hash:
                require(
                    sets[48].hash() == hash_bytes(args.expected_cp48_hash), "Config48 hash differs"
                )
            for n in (9, 10):
                require(
                    48 in lib.hashmap_items(sets[n], 32), f"Config48 absent from ConfigParam {n}"
                )
            passed(
                "config48",
                {
                    "tag": policy["network"].hex(),
                    "hash": sets[48].hash().hex(),
                    "mandatory_and_critical": True,
                },
            )
        else:
            passed("config48", "not mandatory before version 16", "NOT_APPLICABLE")
        name = "anchored_finality"
        proof_url = None
        for url in args.rpc:
            try:
                rpc(url, "getProofQuery", query="Lua1iQ==")
            except lib.RpcError as exc:
                if exc.code != -32601 or exc.reason != "METHOD_NOT_FOUND":
                    raise
            else:
                proof_url = url
                break
        if proof_url is None:
            verified = None
            passed(
                name,
                "getProofQuery is not served by any named node: only cross-node equality, not anchored proof",
                "WEAKER",
            )
        else:
            if verifier is None:
                require(
                    args.proof_library and Path(args.proof_library).is_file(),
                    "proof route is served; install the consensus proof library (--proof-library); "
                    "build target tos-proof-embedded using production/scripts/README.md#build-the-verifier",
                )
                verifier = ProofVerifier(args.proof_library)
            sources = [proof_url] + [u for u in args.rpc if u != proof_url]
            verified, proof_url, source_failures = fetch_proof(
                verifier,
                rpc,
                sources,
                identity["anchor"],
                target,
                sorted(n for n, cell in sets.items() if cell),
                now(),
                elector_addr,
            )
            require(
                int(verified["target"]["gen_utime"]) == int(header["gen_utime"]),
                "reported header time differs from authenticated target",
            )
            require(
                -60 <= now() - int(verified["target"]["gen_utime"]) <= args.max_age,
                "authenticated common head is stale or in the future",
            )
            proven = {int(p["index"]): p for p in verified["config_params"]}
            require(
                set(proven) == {n for n, cell in sets.items() if cell},
                "proof omits requested config",
            )
            for n, p in proven.items():
                cell = lib.parse_boc(base64.b64decode(p["boc"], validate=True))
                require(
                    cell.hash() == sets[n].hash() and cell.hash().hex() == p["cell_hash"],
                    f"proven ConfigParam {n} differs from node equality",
                )
            require(
                verified["account"]["address"] == elector_addr and verified["account"]["active"],
                "proof does not contain the active Elector",
            )
            data = account_data(
                base64.b64decode(verified["account"]["state_boc"], validate=True), elector_addr
            )
            require(
                data.hash().hex() == verified["account"]["data_hash"],
                "proven Elector data hash differs",
            )
            passed(
                name,
                {
                    "strength": "anchor_verified",
                    "source": proof_url,
                    "unavailable_sources": source_failures,
                    "anchor": identity["anchor"],
                    "target": target,
                    "chain": verified["chain"],
                    "elector_data_hash": data.hash().hex(),
                    "method": "existing consensus core: key-block chain and exact target PQ finality",
                },
            )
        name = "elector_snapshot"
        accounts = [
            rpc(url, "getAddressInformation", address=elector_addr, seqno=height)
            for url in args.rpc
        ]
        hashes = [
            lib.parse_boc(base64.b64decode(a["data"], validate=True)).hash().hex() for a in accounts
        ]
        require(len(set(hashes)) == 1, "nodes disagree on Elector data at common head")
        for account in accounts:
            require(
                full_id(account["block_id"]) == full_id(target),
                "Elector snapshot is at another block",
            )
        if verified is None:
            data = lib.parse_boc(base64.b64decode(accounts[0]["data"], validate=True))
        else:
            require(
                data.hash().hex() == hashes[0], "public Elector state differs from proven state"
            )
        name = "elector_data"
        elector = decode_elector(data)
        passed(
            "elector_snapshot",
            {"block": target, "address": elector_addr, "data_hash": data.hash().hex()},
        )
        name = "config34_vs_elector"
        current_record = next(
            (p for p in elector["past"] if p["hash"] == sets[34].hash().hex()), None
        )
        if current_record is not None:
            passed("config34_vs_elector", compare_elected(decode_set(sets[34]), elector))
        initial = int(header["prev_key_block_seqno"]) == 0
        if verified is not None:
            initial = (
                initial and identity["anchor"]["seqno"] == 0 and not verified["chain"]["key_blocks"]
            )
        initial_hash = None
        if initial and current_record is None and identity["anchor"]["seqno"] == 0:
            # Block 1 binds the initial set without trusting a caller's "genesis" flag.
            first_header = rpc(args.rpc[0], "getBlockHeader", workchain=-1, shard=SHARD, seqno=1)
            first_id = normalize_id(first_header["id"])
            if verified is not None:
                first, _, _ = fetch_proof(
                    verifier, rpc, sources, identity["anchor"], first_id, [34], now(), elector_addr
                )
                initial_cell = lib.parse_boc(
                    base64.b64decode(first["config_params"][0]["boc"], validate=True)
                )
            else:
                initial_cell = same_cells(rpc, args.rpc, 34, 1)
            initial_hash = initial_cell.hash().hex()
        try:
            elections = check_election_sets(sets, elector, initial, initial_hash)
        except NetworkError:
            # Bind the previous result to when it was active, not merely retained.
            compare_elected(decode_set(sets[34]), elector)
            name = "config32_vs_elector"
            require(
                sets.get(32) is not None and verifier is not None and verified is not None,
                "previous set result is unavailable and cannot be proven historically",
            )
            name = "config32_vs_elector"
            old = decode_set(sets[32])
            current = decode_set(sets[34])
            require(
                old["since"] < current["since"] and old["until"] <= current["since"],
                "Config32 is not a previous validator term",
            )
            lookup = rpc(
                args.rpc[0],
                "lookupBlock",
                workchain=-1,
                shard=SHARD,
                unixtime=decode_set(sets[34])["since"] - 1,
            )
            older = normalize_id(lookup)
            require(older["seqno"] < height, "historical predecessor is not before common head")
            historical, historical_url, unavailable = fetch_proof(
                verifier, rpc, sources, identity["anchor"], older, [1, 34], now(), elector_addr
            )
            old_params = {
                p["index"]: lib.parse_boc(base64.b64decode(p["boc"], validate=True))
                for p in historical["config_params"]
            }
            old_addr = elector_address(old_params[1])
            if old_addr != elector_addr:
                historical, historical_url, unavailable = fetch_proof(
                    verifier, rpc, sources, identity["anchor"], older, [1, 34], now(), old_addr
                )
            old_cell = old_params[34]
            require(
                old_cell.hash() == sets[32].hash(),
                "Config32 differs from authenticated previous active set",
            )
            old_data = account_data(
                base64.b64decode(historical["account"]["state_boc"], validate=True), old_addr
            )
            old_elector = decode_elector(old_data)
            if (
                not any(p["hash"] == old["hash"] for p in old_elector["past"])
                and not historical["chain"]["key_blocks"]
                and identity["anchor"]["seqno"] == 0
            ):
                first_header = rpc(proof_url, "getBlockHeader", workchain=-1, shard=SHARD, seqno=1)
                first, _, _ = fetch_proof(
                    verifier,
                    rpc,
                    sources,
                    identity["anchor"],
                    normalize_id(first_header["id"]),
                    [34],
                    now(),
                    elector_addr,
                )
                initial_hash = (
                    lib.parse_boc(base64.b64decode(first["config_params"][0]["boc"], validate=True))
                    .hash()
                    .hex()
                )
            if old["hash"] == initial_hash:
                previous = {
                    "status": "NOT_APPLICABLE",
                    "reason": "authenticated previous set was initial unelected set",
                    "set_hash": old["hash"],
                    "historical_block": older,
                }
            else:
                previous = compare_elected(old, old_elector)
                previous["historical_block"] = older
            previous["source"] = historical_url
            previous["unavailable_sources"] = unavailable
            elections = {
                "current": compare_elected(decode_set(sets[34]), elector),
                "previous": previous,
            }
        for which, result in elections.items():
            if which == "current" and current_record is not None:
                continue
            passed(
                "config34_vs_elector" if which == "current" else "config32_vs_elector",
                result,
                result["status"],
            )
        name = "completion_freshness"
        require(
            int(now()) - int(header["gen_utime"]) <= args.max_age,
            "common head became stale while checking; rerun",
        )
        report["ok"] = True
        report["strength"] = "anchor_verified" if verified else "node_equality_only"
    except (NetworkError, OSError, KeyError, ValueError, TypeError, RecursionError) as exc:
        report["checks"].append({"name": name, "status": "FAIL", "reason": str(exc)})
    if hasattr(rpc, "evidence"):
        report["rpc_evidence"] = rpc.evidence
    return report
