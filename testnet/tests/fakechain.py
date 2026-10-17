"""An asynchronous fake chain for the operations tests.

Messages are queued when sent and executed only when the test lets time pass
(`tick`), externals first, internal messages one hop per tick, so a message can
be accepted and still in flight. Answers have the node's JSON shapes
(getAddressInformation, runGetMethod, getTransactionsStd with message summaries,
compute phase and previous_transaction_id); transaction data is a real
transaction cell whose credit phase testnet_ops decodes. The external messages
it executes are real-shaped wallet v3 messages (build_external), decoded with
testnet_ops.decode_external, so the same bytes go through the coordinator's
checks and the chain.
"""

from __future__ import annotations

import base64
import hashlib
import itertools

import testnet_lib as lib
import testnet_ops as ops

NANO = 10**9
WALLET_CODE = lib.cell_from_bits("1" * 40)  # stands for wallet v3 code
POOL_CODE_PLACEHOLDER = None


def bits_of_address(address):
    return lib.cell_from_bits("") if address is None else None


def addr_bits(address):
    if address is None:
        return "00"
    workchain, account = address.split(":")
    return "100" + format(int(workchain) & 0xFF, "08b") + format(int(account, 16), "0256b")


def coins_bits(value):
    if value == 0:
        return "0000"
    size = (value.bit_length() + 7) // 8
    return format(size, "04b") + format(value, f"0{8 * size}b")


def wallet_data(seqno, subwallet, public_key):
    return lib.cell_from_bits(
        format(seqno, "032b") + format(subwallet, "032b") + format(int(public_key, 16), "0256b")
    )


def wallet_state_init(public_key, subwallet=0x504F4F4C):
    return lib.cell_from_bits("00110", [WALLET_CODE, wallet_data(0, subwallet, public_key)])


def wallet_address(public_key, subwallet=0x504F4F4C):
    return f"-1:{wallet_state_init(public_key, subwallet).hash().hex()}"


def internal_message(destination, value, bounce, init=None, body=None):
    body = body if body is not None else lib.cell_from_bits("")
    bits = "0" + "1" + ("1" if bounce else "0") + "0" + "00" + addr_bits(destination)
    bits += coins_bits(value) + "0" + "0000" + "0000" + "0" * 96
    refs = []
    if init is not None:
        bits += "11"
        refs.append(init)
    else:
        bits += "0"
    bits += "1"
    refs.append(body)
    return lib.cell_from_bits(bits, refs)


def build_external(
    wallet, global_id, seqno, valid_until, internal=None, mode=3, subwallet=0, init=None, salt=b""
):
    """A wallet v3 external message: signature (salted, never verified), signed part."""
    signature = hashlib.sha512(salt + str((wallet, seqno, valid_until)).encode()).digest()
    signed = "".join(format(b, "08b") for b in signature)
    signed += format(global_id & 0xFFFFFFFF, "032b") + format(subwallet, "032b")
    signed += format(valid_until, "032b") + format(seqno, "032b")
    refs = []
    if internal is not None:
        signed += format(mode, "08b")
        refs.append(internal)
    body = lib.cell_from_bits(signed, refs)
    bits = "10" + "00" + addr_bits(wallet) + "0000"
    root_refs = []
    if init is not None:
        bits += "11"
        root_refs.append(init)
    else:
        bits += "0"
    bits += "1"
    root_refs.append(body)
    return lib.serialize_boc(lib.cell_from_bits(bits, root_refs))


def transaction_cell(account, lt, credit):
    """A transaction cell whose description has a credit phase of `credit`."""
    bits = "0111" + format(int(account.split(":")[1], 16), "0256b") + format(lt, "064b")
    bits += "0" * 256 + "0" * 64 + "0" * 32 + "0" * 15 + "00" + "00"
    bits += "0000" + "0"  # total fees: 0, no extra currencies
    description = "0000" + "0" + "0"  # trans_ord, credit_first, no storage phase
    if credit is None:
        description += "0"
    else:
        description += "1" + "0" + coins_bits(credit) + "0"
    return lib.cell_from_bits(
        bits,
        [lib.cell_from_bits(""), lib.cell_from_bits(""), lib.cell_from_bits(description)],
    )


class Chain:
    def __init__(self, global_id=2, zero_state=None):
        self.global_id = global_id
        self.zero_state = zero_state or {"root_hash": "cm9vdA==", "file_hash": "ZmlsZQ=="}
        self.accounts = {}
        self.externals = []
        self.internals = []
        self.lt = itertools.count(1000)
        self.now = 1_800_000_000
        self.sent = []  # every sendBoc, in order
        self.behaviour = {}  # address -> callable(chain, account, message) -> (success, out)
        self.extra_out = {}  # wallet -> (destination, value): one more message per transfer

    # -- accounts

    def account(self, address):
        return self.accounts.setdefault(
            address,
            {
                "state": "uninit",
                "balance": 0,
                "seqno": 0,
                "code": None,
                "data": None,
                "txs": [],
                "public_key": None,
                "subwallet": 0,
            },
        )

    def wallet(self, address, balance, public_key="ab" * 32, subwallet=0, seqno=1):
        a = self.account(address)
        a.update(
            state="active",
            balance=balance,
            seqno=seqno,
            code=WALLET_CODE,
            public_key=public_key,
            subwallet=subwallet,
            data=wallet_data(seqno, subwallet, public_key),
        )
        return a

    # -- time

    def tick(self, steps=1):
        for _ in range(steps):
            self.now += 3
            externals, self.externals = self.externals, []
            internals, self.internals = self.internals, []
            for decoded in externals:
                self.execute_external(decoded)
            for message in internals:
                self.deliver(message)

    def settle_all(self, limit=20):
        for _ in range(limit):
            if not self.externals and not self.internals:
                return
            self.tick()

    # -- execution

    def record_tx(self, address, in_msg, out, success=True, aborted=False, credit=None):
        lt = next(self.lt)
        account = self.account(address)
        tx_hash = hashlib.sha256(f"{address}{lt}".encode()).digest()
        cell = transaction_cell(address, lt, credit)
        account["txs"].append(
            {
                "transaction_id": {"lt": str(lt), "hash": base64.b64encode(tx_hash).decode()},
                "utime": self.now,
                "data": base64.b64encode(lib.serialize_boc(cell)).decode(),
                "in_msg": in_msg,
                "out_msgs": out,
                "aborted": aborted,
                "compute": {
                    "skipped": False,
                    "success": success,
                    "exit_code": 0 if success else 33,
                },
            }
        )
        return lt

    def execute_external(self, decoded):
        address = decoded["destination"]
        account = self.account(address)
        in_msg = {
            "kind": "external",
            "hash": base64.b64encode(bytes.fromhex(decoded["external_hash"])).decode(),
        }
        if decoded["global_id"] != self.global_id:
            return  # never accepted
        if decoded["valid_until"] <= self.now:
            return
        if account["state"] != "active":
            if decoded.get("_init") is None or decoded["seqno"] != 0:
                return
            init = decoded["_init"]
            data = lib.Slice(init.refs[1])
            data.bits(64)
            account.update(
                state="active",
                code=init.refs[0],
                seqno=1,
                public_key=data.bytes(32).hex(),
                data=init.refs[1],
            )
            self.record_tx(address, in_msg, [])
            return
        if decoded["seqno"] != account["seqno"]:
            return
        account["seqno"] += 1
        account["data"] = wallet_data(account["seqno"], account["subwallet"], account["public_key"])
        internal = decoded["internal"]
        out = []
        if internal and account["balance"] >= internal["value"]:
            account["balance"] -= internal["value"] + NANO // 100
            message = self.emit(
                address,
                internal["destination"],
                internal["value"],
                internal["bounce"],
                decoded.get("_body"),
                init=decoded.get("_internal_init"),
            )
            out.append(message)
            if address in self.extra_out:
                destination, value = self.extra_out[address]
                out.append(self.emit(address, destination, value, False, None))
        self.record_tx(address, in_msg, out)

    def emit(self, source, destination, value, bounce, body, bounced=False, init=None):
        message_hash = hashlib.sha256(
            f"{source}{destination}{value}{next(self.lt)}".encode()
        ).digest()
        message = {
            "kind": "internal",
            "hash": base64.b64encode(message_hash).decode(),
            "source": source,
            "destination": destination,
            "value": str(value),
            "bounced": bounced,
            "_bounce": bounce,
            "_body": body,
            "_init": init,
        }
        self.internals.append(message)
        return message

    def deliver(self, message):
        destination = message["destination"]
        account = self.account(destination)
        value = int(message["value"])
        in_msg = {k: v for k, v in message.items() if not k.startswith("_")}
        behaviour = self.behaviour.get(destination)
        if behaviour is not None:
            behaviour(self, destination, account, message, in_msg)
            return
        account["balance"] += value
        init = message.get("_init")
        if account["state"] != "active" and init is not None:
            # A deployment: the StateInit becomes the account's code and data.
            account.update(state="active", code=init.refs[0], data=init.refs[1])
            self.record_tx(destination, in_msg, [], credit=value)
            return
        if account["state"] != "active":
            self.record_tx(destination, in_msg, [], success=False, aborted=True, credit=value)
            return
        self.record_tx(destination, in_msg, [], credit=value)

    # -- the node

    def node(self, url, lag=False, broken=False, inclusive=False):
        return ops.Node(url, NodeRpc(self, lag, broken, inclusive))

    def send(self, boc):
        decoded = ops.decode_external(boc)
        root = lib.parse_boc(boc)
        s = lib.Slice(root)
        s.bits(2)
        ops.read_address(s)
        ops.read_address(s)
        ops.read_coins(s)
        init = None
        if s.bits(1):
            init = s.take_ref() if s.bits(1) else None
        decoded["_init"] = init
        body = root.refs[-1]
        b = lib.Slice(body)
        b.bits(512 + 128)
        if decoded["internal"]:
            b.bits(8)
            internal = b.take_ref()
            decoded["_body"] = internal.refs[-1]
            decoded["_internal_init"] = internal.refs[0] if len(internal.refs) == 2 else None
        self.sent.append(decoded["external_hash"])
        self.externals.append(decoded)


class NodeRpc:
    def __init__(self, chain, lag, broken, inclusive=False):
        self.chain, self.lag, self.broken, self.inclusive = chain, lag, broken, inclusive

    def visible(self, account):
        txs = account["txs"]
        return txs[:-1] if self.lag and txs else txs

    def __call__(self, url, method, /, **params):
        chain = self.chain
        if self.broken:
            raise lib.TestnetError(f"{url} unavailable")
        if method == "getMasterchainInfo":
            return {"init": dict(chain.zero_state), "last": {"seqno": 10}}
        if method == "getBlockHeader":
            return {"global_id": chain.global_id, "gen_utime": chain.now}
        if method == "sendBoc":
            chain.send(base64.b64decode(params["boc"]))
            return {}
        account = chain.account(params["address"])
        txs = self.visible(account)
        if method == "getAddressInformation":
            last = txs[-1]["transaction_id"] if txs else {"lt": "0", "hash": ""}
            return {
                "state": "active" if account["state"] == "active" else "uninitialized",
                "balance": str(account["balance"]),
                "code": base64.b64encode(lib.serialize_boc(account["code"])).decode()
                if account["code"]
                else "",
                "data": base64.b64encode(lib.serialize_boc(account["data"])).decode()
                if account["data"]
                else "",
                "last_transaction_id": dict(last),
            }
        if method == "getTransactionsStd":
            hashes = [t["transaction_id"]["hash"] for t in txs]
            start = hashes.index(params["hash"])
            newest_first = list(reversed(txs[: start + 1]))
            page = newest_first[: params["limit"]]
            older = txs[: start + 1 - len(page)]
            if self.inclusive and older:
                # A cursor at the page's last transaction: the next page repeats it.
                older = txs[: start + 2 - len(page)]
            prev = older[-1]["transaction_id"] if older else {"lt": "0", "hash": ""}
            return {
                "transactions": [
                    {k: v for k, v in t.items()}
                    | {
                        "in_msg": {k: v for k, v in t["in_msg"].items() if not k.startswith("_")},
                        "out_msgs": [
                            {k: v for k, v in m.items() if not k.startswith("_")}
                            for m in t["out_msgs"]
                        ],
                    }
                    for t in page
                ],
                "previous_transaction_id": dict(prev),
            }
        if method == "runGetMethod":
            getter = params["method"]
            if getter == "seqno":
                if account["state"] != "active":
                    return {"exit_code": -13, "stack": []}
                return {"exit_code": 0, "stack": [["num", hex(account["seqno"])]]}
            handler = account.get("getters", {}).get(getter)
            if handler is None and getter == "get_roles" and account["data"] is not None:
                return roles_stack(account["data"])
            if handler is None:
                raise AssertionError(f"no getter {getter} on {params['address']}")
            return handler()
        raise AssertionError(f"unexpected {method} {params}")


def roles_stack(data):
    """get_roles of a single-nominator pool's data, top of stack first, as the node lists it."""
    s = lib.Slice(data)
    roles = []
    for _ in range(3):
        bits = "".join(str(s.bits(1)) for _ in range(267))
        roles.append(lib.cell_from_bits(bits))
    return {
        "exit_code": 0,
        "stack": [
            ["slice", {"bytes": base64.b64encode(lib.serialize_boc(cell)).decode()}]
            for cell in reversed(roles)
        ],
    }
