"""Bounded retained forward-proof recomposition for native historical replay.

This is not a cryptographic verifier. ``verify`` must invoke the pinned native
historical verifier on the composed responses plus the capture's account/config
material. Cache advancement occurs only after that callback returns a verified
historical result at the exact anchor and target. No live freshness is inferred.
"""

from copy import deepcopy

from load_finality import Head, HistoryError

MAX_RESPONSE = 8 << 20
MAX_TOTAL = 64 << 20
MAX_RESPONSES = 1024
MAX_LINKS = 16384
ID_FIELDS = ("workchain", "shard", "seqno", "root_hash", "file_hash")


def require(ok, reason):
    if not ok:
        raise HistoryError(reason)


def block_identity(value):
    require(type(value) is dict, "block identity must be an object")
    workchain, seqno = value.get("workchain"), value.get("seqno")
    require(type(workchain) is int and workchain == -1, "masterchain block required")
    require(type(seqno) is int and 0 <= seqno < 1 << 32, "block seqno out of range")
    shard = value.get("shard")
    if isinstance(shard, str):
        require(len(shard) == 16 and all(c in "0123456789abcdef" for c in shard), "invalid shard")
        shard = int(shard, 16)
    else:
        require(type(shard) is int and -(1 << 63) <= shard < 1 << 64, "invalid shard")
        shard %= 1 << 64
    require(shard == 1 << 63, "full masterchain shard required")
    Head(0, value.get("root_hash"))
    Head(0, value.get("file_hash"))
    return workchain, shard, seqno, value["root_hash"], value["file_hash"]


class RetainedPrefix:
    def __init__(self, schemas, anchor):
        self.schemas = schemas
        self.anchor = block_identity(anchor)
        self.links = []
        self.key_positions = {self.anchor: 0}
        self.last_target = None

    def _decode(self, responses, start, target):
        require(
            type(responses) in (list, tuple) and 0 < len(responses) <= MAX_RESPONSES,
            "bounded nonempty response list required",
        )
        total = 0
        links = []
        cursor = start
        for index, raw in enumerate(responses):
            require(type(raw) is bytes and 0 < len(raw) <= MAX_RESPONSE, "response size limit")
            total += len(raw)
            require(total <= MAX_TOTAL, "input proof budget exceeded")
            try:
                part, consumed = self.schemas.deserialize(raw)
                require(consumed == len(raw), "trailing proof response bytes")
                require(
                    part.get("@type") == "liteServer.partialBlockProof", "unexpected proof type"
                )
                require(
                    self.schemas.serialize(part["@type"], part) == raw,
                    "noncanonical proof response",
                )
                require(
                    type(part["complete"]) is bool
                    and part["complete"] == (index == len(responses) - 1),
                    "proof completion flag mismatch",
                )
                require(block_identity(part["from"]) == cursor, "response continuity mismatch")
                steps = part["steps"]
                require(
                    type(steps) is list and steps and len(links) + len(steps) <= MAX_LINKS,
                    "proof link count limit",
                )
                for step in steps:
                    require(
                        step.get("@type") == "liteServer.blockLinkForward", "forward proof required"
                    )
                    require(type(step["to_key_block"]) is bool, "invalid key-block marker")
                    end = block_identity(step["to"])
                    require(
                        block_identity(step["from"]) == cursor and end[2] > cursor[2],
                        "link continuity mismatch",
                    )
                    cursor = end
                    links.append(step)
                require(block_identity(part["to"]) == cursor, "response endpoint mismatch")
            except (KeyError, TypeError, AttributeError, IndexError) as exc:
                raise HistoryError("malformed forward proof response") from exc
        require(cursor == target, "proof does not reach exact target")
        return links

    def _encode(self, links):
        require(0 < len(links) <= MAX_LINKS, "composed proof link count limit")
        # Native responses are bounded individually; never pack a whole run into
        # one oversized response. The conservative header allowance exceeds the
        # fixed two-block-ID partial-proof wrapper.
        groups, group, size = [], [], 256
        for step in links:
            encoded = self.schemas.serialize(step["@type"], step)
            require(len(encoded) + 256 <= MAX_RESPONSE, "proof link size limit")
            if group and (len(group) >= 16 or size + len(encoded) > MAX_RESPONSE):
                groups.append(group)
                group, size = [], 256
            group.append(step)
            size += len(encoded)
        groups.append(group)
        require(len(groups) <= MAX_RESPONSES, "composed response count limit")
        result, total = [], 0
        for index, group in enumerate(groups):
            part = {
                "@type": "liteServer.partialBlockProof",
                "complete": index == len(groups) - 1,
                "from": group[0]["from"],
                "to": group[-1]["to"],
                "steps": group,
            }
            raw = self.schemas.serialize(part["@type"], part)
            total += len(raw)
            require(
                len(raw) <= MAX_RESPONSE and total <= MAX_TOTAL, "composed proof budget exceeded"
            )
            result.append(raw)
        return tuple(result)

    def advance(self, responses, *, start, target, verify):
        """Replay one capture; callback failure leaves the prefix unchanged.

        The callback receives immutable TL response bytes and must return the
        actual native proof result. It must validate required account/config
        identity before returning; callback exceptions do not advance this cache.
        """
        start, target = block_identity(start), block_identity(target)
        require(start in self.key_positions, "authenticated retained prefix missing")
        if self.last_target is not None:
            require(
                target[2] > self.last_target[2] or target == self.last_target,
                "historical capture regressed or changed at same height",
            )
        prefix = self.links[: self.key_positions[start]]
        new = self._decode(responses, start, target)
        candidate = prefix + new
        encoded = self._encode(candidate)
        # Only the prefix ending at a key block is cached. Non-key target links
        # must never be substituted for the next capture's cached key-block head.
        last_key = max(
            (i + 1 for i, step in enumerate(candidate) if step["to_key_block"]), default=0
        )
        keys = candidate[:last_key]
        require(
            len(keys) >= len(self.links) and keys[: len(self.links)] == self.links,
            "retained key-block prefix changed",
        )
        verified = verify(encoded)
        require(
            type(verified) is dict
            and verified.get("status") == "verified"
            and verified.get("mode") == "historical",
            "native historical verification required",
        )
        require(
            block_identity(verified["anchor"]) == self.anchor
            and block_identity(verified["start"]) == self.anchor
            and block_identity(verified["target"]) == target,
            "native replay identity mismatch",
        )
        self.links = deepcopy(keys)
        self.key_positions = {self.anchor: 0}
        for index, step in enumerate(self.links):
            if step["to_key_block"]:
                self.key_positions[block_identity(step["to"])] = index + 1
        self.last_target = target
        return verified
