"""Signer adapter for tos scripts/tok01-lifecycle.py --sender-command (wallet v1 senders).

    tok01-signer.py --keys DIR --endpoint URL            (reads one request on stdin)
    tok01-signer.py --keys DIR --new                      (creates one sender key, prints its address)

TOS_ROOT names the tos checkout; its test/tostester provides the wallet v1 code and cells.
A new sender is funded (for example with testnet-elections.py fund) and then deployed by
its first message, which carries the StateInit.

The request is {"sender", "message_boc", "send_mode"}. The sender's key is DIR/<hex>.key
(32-byte Ed25519 seed, 0600), where <hex> is the sender's workchain-0 account id. The
adapter signs seqno ++ send_mode ++ ^message exactly as tostester's WalletV1 does, with the
received message cell embedded unchanged, attaches the StateInit while the wallet is not
yet active, submits through sendBoc, and answers {"submitted": true} only after the
wallet's seqno moved past the one it signed. Nothing secret is written to stdout.
"""

import argparse
import base64
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

TOS_ROOT = os.environ.get("TOS_ROOT")
if not TOS_ROOT:
    raise SystemExit(
        "set TOS_ROOT to the tos checkout the network runs (its test/tostester is used)"
    )
sys.path.insert(0, str(Path(TOS_ROOT) / "test" / "tostester" / "src"))
import nacl.signing  # noqa: E402
from contract.wallet_v1 import WalletV1Blueprint  # noqa: E402
from pytosiq_core import Builder, Cell, ExternalMsgInfo, MessageAny  # noqa: E402


def rpc(endpoint, method, **params):
    req = urllib.request.Request(
        endpoint,
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        {"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        answer = json.load(r)
    if "result" not in answer:
        raise RuntimeError(f"{method}: {answer.get('error')}")
    return answer["result"]


def raw(blueprint):
    wc, account = blueprint.address.wc, blueprint.address.hash_part
    return f"{wc}:{account.hex()}"


def load_key(keys: Path, sender: str) -> nacl.signing.SigningKey:
    wc, account = sender.split(":")
    if wc != "0":
        raise SystemExit(f"sender {sender} is not on workchain 0")
    path = keys / f"{account.lower()}.key"
    if not path.is_file():
        raise SystemExit(f"no key for sender {sender}")
    if path.stat().st_mode & 0o077:
        raise SystemExit(f"{path} is readable by others")
    return nacl.signing.SigningKey(path.read_bytes())


def signed_body(key, seqno: int, send_mode: int, message):
    """Wallet v1's external body: signature over (seqno ++ send_mode ++ ^message), then it."""
    to_sign = Builder().store_uint(seqno, 32).store_uint(send_mode, 8).store_ref(message).end_cell()
    return Builder().store_bytes(key.sign(to_sign.hash).signature).store_cell(to_sign).end_cell()


def seqno_of(endpoint, sender) -> tuple[str, int]:
    info = rpc(endpoint, "getAddressInformation", address=sender)
    state = info["state"]
    if state != "active":
        return state, 0
    data = Cell.one_from_boc(base64.b64decode(info["data"]))
    return state, data.begin_parse().load_uint(32)


def submit(args):
    request = json.loads(sys.stdin.read())
    sender = request["sender"].lower()
    key = load_key(Path(args.keys), sender)
    blueprint = WalletV1Blueprint(workchain=0, private_key=key)
    if raw(blueprint) != sender:
        raise SystemExit("the key does not belong to the sender")
    send_mode = int(request["send_mode"])
    if not 0 <= send_mode <= 255:
        raise SystemExit("send_mode out of range")
    message = Cell.one_from_boc(base64.b64decode(request["message_boc"]))
    state, seqno = seqno_of(args.endpoint, sender)
    body = signed_body(key, seqno, send_mode, message)
    init = blueprint.state_init if state != "active" else None
    external = MessageAny(info=ExternalMsgInfo(None, blueprint.address, 0), init=init, body=body)
    boc = base64.b64encode(external.serialize().to_boc()).decode()
    rpc(args.endpoint, "sendBoc", boc=boc)
    deadline = time.monotonic() + args.confirm_seconds
    while time.monotonic() < deadline:
        time.sleep(2)
        try:
            now_state, now_seqno = seqno_of(args.endpoint, sender)
        except Exception:  # noqa: BLE001 - a transient read error is retried until the deadline
            continue
        if now_state == "active" and now_seqno > seqno:
            print(json.dumps({"submitted": True}))
            return 0
    raise SystemExit(f"seqno of {sender} did not move past {seqno} within {args.confirm_seconds}s")


def new_key(args):
    keys = Path(args.keys)
    keys.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = nacl.signing.SigningKey.generate()
    blueprint = WalletV1Blueprint(workchain=0, private_key=key)
    path = keys / f"{blueprint.address.hash_part.hex()}.key"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(bytes(key))
    print(raw(blueprint))
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--keys", required=True)
    p.add_argument("--endpoint")
    p.add_argument("--new", action="store_true")
    p.add_argument("--confirm-seconds", type=int, default=90)
    args = p.parse_args()
    if args.new:
        return new_key(args)
    if not args.endpoint:
        p.error("--endpoint is required to submit")
    return submit(args)


if __name__ == "__main__":
    sys.exit(main())
