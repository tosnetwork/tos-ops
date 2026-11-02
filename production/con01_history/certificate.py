"""Verify governing config/session/signatures; report election timing separately."""

from __future__ import annotations

import bisect
import fcntl
import hashlib
import os
import stat
import subprocess
from pathlib import Path

from . import formats as f


class Refused(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Refused(reason)


def hash_bytes(value):
    require(isinstance(value, str), "block hash encoding")
    if len(value) == 64:
        try:
            result = bytes.fromhex(value)
        except ValueError as error:
            raise Refused("block hash encoding") from error
    else:
        result = f.D(value)
        require(f.B(result) == value, "canonical block hash encoding")
    require(len(result) == 32, "block hash width")
    return result


def identity(block):
    shard = (
        -9223372036854775808
        if block["shard"] == "8000000000000000"
        else int(block["shard"])
    )
    require(
        int(block["workchain"]) == -1 and shard == -9223372036854775808,
        "masterchain block required",
    )
    require(
        type(block["seqno"]) is int and 0 <= block["seqno"] <= 5000000,
        "block sequence bound",
    )
    return (
        -1,
        shard,
        block["seqno"],
        hash_bytes(block["root_hash"]),
        hash_bytes(block["file_hash"]),
    )


class SignatureVerifier:
    """One sealed bounded OpenSSL helper; public verification input only."""

    def __init__(self, executable: Path, digest: str):
        fd = os.open(
            executable, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        )
        self.fd = -1
        copied = -1
        try:
            info = os.fstat(fd)
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1
                and info.st_uid in (0, os.geteuid())
                and not info.st_mode & 0o022
                and info.st_mode & 0o111
                and 4 <= info.st_size <= 16 * 1024 * 1024,
                "unsafe signature verifier",
            )
            raw = os.read(fd, 16 * 1024 * 1024 + 1)
            require(
                len(raw) == info.st_size
                and raw.startswith(b"\x7fELF")
                and hashlib.sha256(raw).hexdigest() == digest,
                "signature verifier pin",
            )
            copied = os.memfd_create(
                "con01-openssl", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
            )
            view = memoryview(raw)
            while view:
                n = os.write(copied, view)
                require(n > 0, "verifier snapshot write")
                view = view[n:]
            os.fchmod(copied, 0o500)
            fcntl.fcntl(
                copied,
                fcntl.F_ADD_SEALS,
                fcntl.F_SEAL_WRITE
                | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_SEAL,
            )
            self.fd = copied
            copied = -1
        finally:
            os.close(fd)
            if copied >= 0:
                os.close(copied)

    def __call__(self, public, signature, message):
        require(
            self.fd >= 0
            and len(public) == 1312
            and len(signature) == 2420
            and len(message) <= 4096,
            "signature input bound",
        )
        result = subprocess.run(
            [f"/proc/self/fd/{self.fd}"],
            input=public + signature + message,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            pass_fds=(self.fd,),
            timeout=5,
        )
        require(result.returncode == 0, "ML-DSA-44 verification rejected")

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def source_params(root, source):
    if int(source["seqno"]) == 0:
        require(
            root.data[:8] == bytes.fromhex("9023afe200000002"),
            "public zerostate header",
        )
        s = root.refs[3].slice()
        require(s.u(16) == 0xCC26, "masterchain state")
        if s.u(1):
            s.ref()
        s.raw(32)
        params = f.dictionary(s.ref(), 32)
    else:
        header = f.block_header(root)
        require(
            header["key"] and header["seqno"] == int(source["seqno"]),
            "source must be key block",
        )
        params = f.config_params(root)
    # Global id2 is authenticated by the source block/state header itself.
    # This mirrors the existing genesis decoder; no RPC identity assertion is trusted.
    if 19 not in params:

        class Global:
            c = f.Cell(0, 0, b"", [f.Cell(0, 8, b"\0\0\0\2", [])])

        params[19] = Global()
    return params


def verify_link(link, verify_signature, expected_source=None):
    if expected_source is not None:
        require(
            identity(link["src"]) == identity(expected_source),
            "retired or wrong governing key block",
        )
    source, destination, root, cert = (
        link["src"],
        link["dst"],
        link["dest"],
        link["cert"],
    )
    require(
        link["config"].hash() == f.D(source["root_hash"]), "source config root mismatch"
    )
    require(root.hash() == f.D(destination["root_hash"]), "destination root mismatch")
    require(
        identity(cert["id"]) == identity(destination), "certificate target mismatch"
    )
    header = f.block_header(root)
    require(
        header["seqno"] == int(destination["seqno"])
        and header["prevkey"] == int(source["seqno"]),
        "source is not declared governing key block",
    )
    params = source_params(link["config"], source)
    v = f.validators(params[34].c.slice().ref())
    require(
        cert["cc_seqno"] == header["cc"]
        and cert["validator_set_hash"] == header["vhash"],
        "certificate/header session coordinates",
    )
    require(
        f.D(cert["session_id"]) == f.session(params, v, header),
        "session identity mismatch",
    )
    message = f.signed_message(cert)
    seen = set()
    weight = 0
    for sig in cert["signatures"]:
        vid = f.D(sig["validator_id"])
        require(vid not in seen, "duplicate signer")
        seen.add(vid)
        require(vid in v["members"], "signer outside validator set")
        require(sig["algorithm_id"] == 1, "unsupported signature algorithm")
        member = v["members"][vid]
        verify_signature(member["pk"], f.D(sig["signature"]), message)
        weight += member["weight"]
    require(3 * weight > 2 * v["weight"], "insufficient quorum")
    timing = (
        "before_since"
        if header["gen_utime"] < v["since"]
        else ("after_until" if header["gen_utime"] > v["until"] else "within_schedule")
    )
    return dict(
        id=destination,
        header=header,
        signers=len(seen),
        signed_weight=weight,
        total_weight=v["weight"],
        validator_since=v["since"],
        validator_until=v["until"],
        term_schedule=timing,
        set_hash=v["cell_hash"].hex(),
    )


def verify_packet(raw, anchor, verify_signature):
    require(0 < len(raw) <= 2 * 1024 * 1024, "proof packet byte bound")
    try:
        start, end, links = f.forward_proof(raw, allow_partial=True)
        require(
            identity(start) == identity(anchor),
            "proof does not start at trusted anchor",
        )
        require(
            identity(links[0]["src"]) == identity(start), "first proof source mismatch"
        )
        require(identity(links[-1]["dst"]) == identity(end), "proof endpoint mismatch")
        results = []
        cursor = start
        for i, link in enumerate(links):
            require(identity(link["src"]) == identity(cursor), "proof chain gap")
            require(
                int(link["dst"]["seqno"]) > int(cursor["seqno"]),
                "nonadvancing proof link",
            )
            result = verify_link(link, verify_signature)
            require(
                i == len(links) - 1 or result["header"]["key"],
                "intermediate source is not key block",
            )
            results.append(result)
            cursor = link["dst"]
        return dict(
            start=start,
            end=end,
            complete=raw[4:8] == bytes.fromhex("b5757299"),
            links=results,
        )
    finally:
        f.Cell.hd.cache_clear()


def governing_key(keys, block_seqno):
    positions = sorted(keys)
    slot = bisect.bisect_left(positions, block_seqno) - 1
    require(slot >= 0, "no governing key before block")
    return keys[positions[slot]]
