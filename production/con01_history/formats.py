"""Independent minimal TL and BOC decoding for the frozen TOS wire schemas."""

import base64
import hashlib
import struct
import zlib
from functools import lru_cache

if not __debug__:
    raise RuntimeError("independent proof decoder requires checks enabled")


def D(s):
    return base64.b64decode(s, validate=True)


def B(b):
    return base64.b64encode(b).decode()


def H(b):
    return hashlib.sha256(b).digest()


def tag(schema):
    return struct.pack(
        "<I", zlib.crc32(schema.replace("(", "").replace(")", "").encode())
    )


SCHEMAS = {
    "blockid": "tosNode.blockIdExt workchain:int shard:long seqno:int root_hash:int256 file_hash:int256 = tosNode.BlockIdExt",
    "config": "liteServer.getConfigParams mode:# id:tosNode.blockIdExt param_list:(vector int) = liteServer.ConfigInfo",
    "proof": "liteServer.getBlockProof mode:# known_block:tosNode.blockIdExt target_block:mode.0?tosNode.blockIdExt = liteServer.PartialBlockProof",
    "ordinary": "consensus.candidateHashDataOrdinary block:tosNode.blockIdExt collated_file_hash:int256 parent:consensus.CandidateParent = consensus.CandidateHashData",
    "empty": "consensus.candidateHashDataEmpty block:tosNode.blockIdExt parent:consensus.candidateId = consensus.CandidateHashData",
    "final": "consensus.simplex.finalizeVote id:consensus.CandidateId = consensus.simplex.UnsignedVote",
    "candidateid": "consensus.candidateId slot:int hash:int256 = consensus.CandidateId",
    "data": "consensus.dataToSign session_id:int256 data:bytes = consensus.DataToSign",
    "parent": "consensus.candidateParent id:consensus.CandidateId = consensus.CandidateParent",
    "noparent": "consensus.candidateWithoutParents = consensus.CandidateParent",
}


def T(k):
    return tag(SCHEMAS[k])


def bid(b):
    return (
        T("blockid")
        + struct.pack("<iqi", int(b["workchain"]), int(b["shard"]), b["seqno"])
        + D(b["root_hash"])
        + D(b["file_hash"])
    )


def tlbytes(b):
    n = len(b)
    h = bytes([n]) if n < 254 else b"\xfe" + n.to_bytes(3, "little")
    return h + b + bytes(-(len(h) + n) % 4)


class TL:
    def __init__(self, b):
        self.b = b
        self.p = 0

    def take(self, n):
        assert n >= 0 and self.p + n <= len(self.b), "truncated TL"
        v = self.b[self.p : self.p + n]
        self.p += n
        return v

    def u(self):
        return int.from_bytes(self.take(4), "little")

    def bytes(self):
        n = self.take(1)[0]
        start = 1
        if n == 254:
            n = int.from_bytes(self.take(3), "little")
            start = 4
        assert n < 64 * 1024 * 1024
        v = self.take(n)
        assert self.take(-(start + n) % 4) == bytes(-(start + n) % 4)
        return v

    def blockid(self):
        w, s, n = struct.unpack("<iqi", self.take(16))
        return dict(
            workchain=w,
            shard=str(s),
            seqno=n,
            root_hash=B(self.take(32)),
            file_hash=B(self.take(32)),
        )


class Cell:
    def __init__(self, d1, d2, data, refs):
        self.d1 = d1
        self.d2 = d2
        self.data = data
        self.refs = refs
        self.mask = d1 >> 5
        self.exotic = bool(d1 & 8)
        self.nbits = len(data) * 8
        if d2 & 1:
            assert data and data[-1]
            self.nbits -= (data[-1] & -data[-1]).bit_length()

    def slice(self):
        return Bits(self)

    @lru_cache(None)
    def hd(self, level=0):
        level = min(level, self.mask.bit_length())
        typ = self.data[0] if self.exotic else 0
        if typ == 1:
            count = self.mask.bit_count()
            index = (self.mask & ((1 << level) - 1)).bit_count()
            if index < count:
                return self.data[2 + 32 * index : 34 + 32 * index], int.from_bytes(
                    self.data[2 + 32 * count + 2 * index : 4 + 32 * count + 2 * index],
                    "big",
                )
        previous = None
        out = None
        for lev in range(self.mask.bit_length() + 1):
            if lev and not (self.mask & (1 << (lev - 1))):
                continue
            if typ == 1 and lev != self.mask.bit_length():
                continue
            content = self.data if previous is None else previous
            d2 = self.d2 if previous is None else 64
            mask = self.mask & ((1 << lev) - 1)
            children = [r.hd(lev + (typ in (3, 4))) for r in self.refs]
            rep = (
                bytes([(self.d1 & 31) | (mask << 5), d2])
                + content
                + b"".join(d.to_bytes(2, "big") for h, d in children)
                + b"".join(h for h, d in children)
            )
            out = (H(rep), 0 if not children else 1 + max(d for h, d in children))
            previous = out[0]
            if lev >= level:
                return out
        assert out is not None
        return out

    def hash(self, level=0):
        return self.hd(level)[0]


class Bits:
    def __init__(self, c):
        self.c = c
        self.p = 0
        self.r = 0

    def u(self, n):
        assert 0 <= n and self.p + n <= self.c.nbits, "cell bit underflow"
        value = int.from_bytes(self.c.data, "big") >> (
            len(self.c.data) * 8 - self.p - n
        ) & ((1 << n) - 1)
        self.p += n
        return value

    def raw(self, n):
        return self.u(n * 8).to_bytes(n, "big")

    def ref(self):
        assert self.r < len(self.c.refs), "cell ref underflow"
        c = self.c.refs[self.r]
        self.r += 1
        return c

    def end(self):
        assert self.p == self.c.nbits and self.r == len(self.c.refs), (
            "cell trailing fields"
        )


def boc(data):
    assert len(data) <= 2 * 1024 * 1024, "BOC byte bound"
    r = TL(data)
    assert r.take(4) == bytes.fromhex("b5ee9c72")
    f = r.take(1)[0]
    size = f & 7
    off = r.take(1)[0]
    assert size and not (f & 0x18)

    def num(n):
        return int.from_bytes(r.take(n), "big")

    count, roots, absent, total = num(size), num(size), num(size), num(off)
    assert 0 < count <= 65536 and roots == 1 and absent == 0, "BOC cell/root bound"
    ri = num(size)
    if f & 128:
        r.take(count * off)
    end = r.p + total
    raw = []
    for i in range(count):
        d1, d2 = r.take(2)
        assert not (d1 & 16) and d1 & 7 <= 4, "stored cell hashes/ref count unsupported"
        payload = r.take((d2 + 1) // 2)
        refs = [num(size) for _ in range(d1 & 7)]
        raw.append((d1, d2, payload, refs))
    assert r.p == end
    if f & 64:
        r.take(
            4
        )  # CRC is transport-only; authenticated cell hashes are checked separately.
    assert r.p == len(data)
    cells = {}

    def build(i, depth=0):
        assert depth <= 256, "BOC depth bound"
        assert 0 <= i < count
        if i not in cells:
            d1, d2, p, refs = raw[i]
            assert all(j > i for j in refs), "non-topological BOC"
            cells[i] = Cell(d1, d2, p, [build(j, depth + 1) for j in refs])
        return cells[i]

    return build(ri)


def virtual(data):
    c = boc(data)
    assert c.exotic and c.data[0] == 3 and len(c.refs) == 1
    h, d = c.refs[0].hd(0)
    assert c.data[1:33] == h and int.from_bytes(c.data[33:35], "big") == d
    return c.refs[0]


def dictionary(c, n, prefix=0):
    if c.exotic:
        assert c.data[0] == 1
        return {}
    s = c.slice()
    a = s.u(1)
    if not a:
        k = 0
        while s.u(1):
            k += 1
            assert k <= n
        label = s.u(k)
    elif not s.u(1):
        k = s.u(n.bit_length())
        label = s.u(k)
    else:
        bit = s.u(1)
        k = s.u(n.bit_length())
        label = ((1 << k) - 1) * bit
    assert k <= n
    prefix = (prefix << k) | label
    n -= k
    if not n:
        return {prefix: s}
    left, right = s.ref(), s.ref()
    s.end()
    return dictionary(left, n - 1, prefix << 1) | dictionary(
        right, n - 1, (prefix << 1) | 1
    )


def pqbytes(c):
    s = c.slice()
    n = s.u(32)
    nextc = s.ref()
    s.end()
    assert n == 1312
    out = b""
    while True:
        s = nextc.slice()
        take = min(n - len(out), 127)
        out += s.raw(take)
        if len(out) < n:
            nextc = s.ref()
            s.end()
        else:
            s.end()
            break
    return out


def validators(c):
    s = c.slice()
    assert s.u(8) == 0x12
    since, until, total, main, weight = s.u(32), s.u(32), s.u(16), s.u(16), s.u(64)
    assert s.u(1) == 1
    entries = dictionary(s.ref(), 16)
    s.end()
    members = {}
    for index, v in sorted(entries.items()):
        assert v.u(8) == 0xB3
        vid = v.raw(32)
        alg = v.u(16)
        kid = v.raw(32)
        pk = pqbytes(v.ref())
        w = v.u(64)
        adnl = v.raw(32)
        v.end()
        assert (
            alg == 1
            and kid == H(b"TOS-PQ-CONSENSUS-KEY-v1" + struct.pack("<H", alg) + pk)
            and w > 0
            and vid not in members
        )
        members[vid] = dict(
            index=index, algorithm=alg, key_id=kid, pk=pk, weight=w, adnl=adnl
        )
    assert (
        total == len(members)
        and main == total
        and weight == sum(v["weight"] for v in members.values())
    )
    return dict(
        since=since,
        until=until,
        total=total,
        weight=weight,
        members=members,
        cell_hash=c.hash(),
    )


def key_config_reply(raw):
    t = TL(raw)
    assert t.take(4) == tag(
        "liteServer.configInfo mode:# id:tosNode.blockIdExt state_proof:bytes config_proof:bytes = liteServer.ConfigInfo"
    )
    mode = t.u()
    block = t.blockid()
    state = t.bytes()
    proof = t.bytes()
    assert t.p == len(raw) and mode & 0x8000 and not state
    root = virtual(proof)
    assert root.hash() == D(block["root_hash"])
    s = root.slice()
    assert s.u(32) == 0x11EF55AA and s.u(32) == 2
    assert len(root.refs) == 4
    extra = root.refs[3]
    v = extra.slice()
    assert v.u(32) == 0x4A33F6FD
    v.raw(64)
    assert v.u(1) == 1
    mc = extra.refs[3]
    x = mc.slice()
    assert x.u(16) == 0xCCA5 and x.u(1) == 1
    if x.u(1):
        x.ref()  # shard hashes
    if x.u(1):
        x.ref()  # shard fees, HashmapAugE extra follows in bits
    # Easier unambiguous ConfigParams reference: last ref of key McBlockExtra.
    cfg = mc.refs[-1]
    params = dictionary(cfg, 32)
    return block, params, root


def state_config(r):
    block = virtual(D(r["state_proof"]))
    state = virtual(D(r["config_proof"]))
    assert block.hash() == D(r["block_id"]["root_hash"])
    assert block.data[:8] == bytes.fromhex("11ef55aa00000002")
    update = block.refs[2]
    assert update.exotic and update.data[0] == 4 and update.data[33:65] == state.hash()
    assert state.data[:8] == bytes.fromhex("9023afe200000002")
    mc = state.refs[3]
    s = mc.slice()
    assert s.u(16) == 0xCC26
    if s.u(1):
        s.ref()
    s.raw(32)
    params = dictionary(s.ref(), 32)
    param = params[34].c.slice().ref()
    assert param.hash() == boc(D(r["config"]["bytes"])).hash()
    return validators(param), block


def block_header(root):
    s = root.slice()
    assert s.u(32) == 0x11EF55AA and s.u(32) == 2
    info = s.ref()
    x = info.slice()
    assert x.u(32) == 0x9BC7A987
    _version = x.u(32)
    flags = x.u(8)
    opt = x.u(8)
    seq = x.u(32)
    _vert = x.u(32)
    assert flags & 128 == 0 and flags & 64 == 0  # masterchain, no merge
    assert x.u(2) == 0
    prefixbits = x.u(6)
    wc = x.u(32)
    shard = x.u(64)
    assert prefixbits == 0 and wc == 0xFFFFFFFF and shard == 0
    utime = x.u(32)
    _start, _end = x.u(64), x.u(64)
    vhash, cc, _minref, prevkey = x.u(32), x.u(32), x.u(32), x.u(32)
    if opt & 1:
        x.raw(12)
    prev = x.ref().slice()
    prev.u(64)
    pn = prev.u(32)
    rh, fh = prev.raw(32), prev.raw(32)
    prev.end()
    return dict(
        seqno=seq,
        gen_utime=utime,
        cc=cc,
        vhash=vhash,
        key=bool(flags & 2),
        prevkey=prevkey,
        parent=dict(
            workchain=-1,
            shard="-9223372036854775808",
            seqno=pn,
            root_hash=B(rh),
            file_hash=B(fh),
        ),
    )


FORWARD = "liteServer.blockLinkForward to_key_block:Bool from:tosNode.blockIdExt to:tosNode.blockIdExt dest_proof:bytes config_proof:bytes signatures:liteServer.SignatureSet = liteServer.BlockLink"
PARTIAL = "liteServer.partialBlockProof complete:Bool from:tosNode.blockIdExt to:tosNode.blockIdExt steps:(vector liteServer.BlockLink) = liteServer.PartialBlockProof"
PQSET = "liteServer.signatureSet.simplexPq cc_seqno:int validator_set_hash:int signatures:(vector liteServer.pqSignature) session_id:int256 slot:int candidate:bytes = liteServer.SignatureSet"


def forward_proof(data, allow_partial=False):
    t = TL(data)
    assert t.take(4) == tag(PARTIAL)
    complete = t.take(4)
    assert complete == bytes.fromhex("b5757299") or (
        allow_partial and complete == bytes.fromhex("379779bc")
    ), "incomplete proof packet"
    start, end = t.blockid(), t.blockid()
    count = t.u()
    assert 0 < count < 100
    links = []
    for _ in range(count):
        assert t.take(4) == tag(FORWARD), "expected forward-only proof"
        key = t.take(4)
        assert key in (bytes.fromhex("b5757299"), bytes.fromhex("379779bc"))
        src, dst = t.blockid(), t.blockid()
        dest_proof, cfg_proof = t.bytes(), t.bytes()
        assert t.take(4) == tag(PQSET)
        cc, vhash = t.u(), t.u()
        n = t.u()
        assert 0 < n <= 100
        signatures = []
        for _ in range(n):
            signatures.append(
                dict(
                    validator_id=B(t.take(32)),
                    algorithm_id=t.u(),
                    signature=B(t.bytes()),
                )
            )
        session, slot, candidate = t.take(32), t.u(), t.bytes()
        cert = dict(
            id=dst,
            cc_seqno=cc,
            validator_set_hash=vhash,
            signatures=signatures,
            session_id=B(session),
            slot=slot,
            candidate=B(candidate),
        )
        links.append(
            dict(
                src=src,
                dst=dst,
                dest=virtual(dest_proof),
                config=virtual(cfg_proof),
                cert=cert,
            )
        )
    assert t.p == len(data)
    return start, end, links


def config_params(root):
    assert root.data[:8] == bytes.fromhex("11ef55aa00000002") and len(root.refs) == 4
    extra = root.refs[3]
    assert extra.data[:4] == bytes.fromhex("4a33f6fd") and len(extra.refs) == 4
    mc = extra.refs[3]
    x = mc.slice()
    assert x.u(16) == 0xCCA5 and x.u(1) == 1
    return dictionary(mc.refs[-1], 32)


def crc32c(data):
    c = 0xFFFFFFFF
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ (0x82F63B78 if c & 1 else 0)
    return c ^ 0xFFFFFFFF


def session(params, v, h):
    assert params[19].c.slice().ref().data == b"\0\0\0\2"
    cc = params[28].c.slice().ref().slice()
    assert cc.u(8) == 0xC2 and cc.u(7) == 0
    shuffle = cc.u(1)
    order = list(v["members"])
    if shuffle:
        assert len(order) <= 8
        digest = hashlib.sha512(
            bytes(32) + struct.pack(">QiI", 0x8000000000000000, -1, h["cc"])
        ).digest()
        indices = []
        for i in range(len(order)):
            j = ((i + 1) * int.from_bytes(digest[i * 8 : i * 8 + 8], "big")) >> 64
            indices.append(indices[j] if j < i else i)
            indices[j] = i
        order = [order[i] for i in indices]
    nodes = [(vid, v["members"][vid]) for vid in order]
    pre = struct.pack("<III", 0x79AE62D2, h["cc"], len(nodes)) + b"".join(
        vid + m["key_id"] + struct.pack("<Q", m["weight"]) + m["adnl"]
        for vid, m in nodes
    )
    assert crc32c(pre) == h["vhash"], "validator-set hash mismatch"
    c = params[29].c.slice().ref().slice()
    assert c.u(8) == 0xD7 and c.u(7) == 0
    new = c.u(1)
    rounds = c.u(8)
    delay, timeout, fast, duration, deps, block, collated = [c.u(32) for _ in range(7)]
    c.end()
    assert new == 1
    schema = "validatorSession.configNew catchain_idle_timeout:double catchain_max_deps:int round_candidates:int next_candidate_delay:double round_attempt_duration:int max_round_attempts:int max_block_size:int max_collated_data_size:int new_catchain_ids:Bool = validatorSession.Config"
    options = H(
        tag(schema)
        + struct.pack(
            "<diidiiii",
            timeout * 0.001,
            deps,
            rounds,
            delay * 0.001,
            duration,
            fast,
            block,
            collated,
        )
        + bytes.fromhex("b5757299")
    )
    c = params[30].c.slice().ref().slice()
    assert c.u(8) == 0x10 and c.u(1) == 1
    selected = c.ref()
    assert selected.data[0] in (0x21, 0x22)
    config = H(
        b"TOS-VALIDATOR-SESSION-CONFIG-v1"
        + struct.pack("<i", 2)
        + options
        + selected.hash()
    )
    group = "validator.groupNew workchain:int shard:long vertical_seqno:int last_key_block_seqno:int catchain_seqno:int config_hash:int256 members:(vector engine.validator.GroupMember) = validator.Group"
    member = "validator.groupMemberPQ validator_id:int256 key_id:int256 adnl:int256 weight:long = engine.validator.GroupMember"
    encoded = b"".join(
        tag(member) + vid + m["key_id"] + m["adnl"] + struct.pack("<Q", m["weight"])
        for vid, m in nodes
    )
    return H(
        tag(group)
        + struct.pack("<iqiii", -1, -9223372036854775808, 0, h["prevkey"], h["cc"])
        + config
        + struct.pack("<I", len(nodes))
        + encoded
    )


def signed_message(cert):
    raw = D(cert["candidate"])
    t = TL(raw)
    kind = t.take(4)
    assert kind in (T("ordinary"), T("empty"))
    assert t.take(80) == bid(cert["id"])[4:], "candidate block identity mismatch"
    if kind == T("ordinary"):
        t.take(32)
        parent = t.take(4)
        assert parent in (T("parent"), T("noparent"))
        if parent == T("parent"):
            assert t.take(4) == T("candidateid")
            t.take(36)
    else:
        t.take(36)
    assert t.p == len(raw), "candidate trailing bytes"
    vote = T("final") + T("candidateid") + struct.pack("<I", cert["slot"]) + H(raw)
    return T("data") + D(cert["session_id"]) + tlbytes(vote)
