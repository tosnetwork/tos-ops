#!/usr/bin/env python3
"""Check the issuer before building an unsigned bridge-burn body. Never sends."""

import argparse
import base64
import json
import time

import settlement_issuer as issuer
import testnet_lib as lib

FINALITY_WARNING = "A recorded burn is final. Issuer restrictions and fees may change after this check; a failed unlock can leave the tokens unredeemable to this receiver."


def prepare(rpc, binding, receiver, amount, query_id, now=time.time):
    # Keep this before body construction: a failed or stale read emits no BOC.
    observation = issuer.read_issuer(rpc, binding, receiver, now)
    received, fee = issuer.received_amount(amount, observation)
    issuer.require(type(query_id) is int and 0 <= query_id < 2**64, "invalid burn query id")
    size = (amount.bit_length() + 7) // 8
    bits = f"{0x595F07BC:032b}{query_id:064b}{size:04b}{amount:0{size * 8}b}" + "00" + "1"
    destination = lib.cell_from_bits(f"{int(observation['receiver'], 16):0160b}")
    body = lib.cell_from_bits(bits, [destination])
    return dict(
        schema="tos-token-redemption-prepared/1",
        destination=binding["wallet"],
        master=binding["master"],
        source_token=observation["token"],
        receiver=observation["receiver"],
        amount_atomic=str(amount),
        received_atomic=str(received),
        issuer_fee_atomic=str(fee),
        query_id=query_id,
        body_boc=base64.b64encode(lib.serialize_boc(body)).decode(),
        body_hash=body.hash().hex(),
        issuer=observation,
        warning=FINALITY_WARNING,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc", required=True)
    parser.add_argument("--binding", required=True)
    parser.add_argument("--receiver", required=True)
    parser.add_argument("--amount", required=True, type=int)
    parser.add_argument("--query-id", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        with open(args.binding) as stream:
            binding = json.load(stream, object_pairs_hook=issuer.source.pairs)
        result = prepare(
            issuer.source.RPC(args.rpc), binding, args.receiver, args.amount, args.query_id
        )
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, lib.TestnetError) as error:
        # Do not print untrusted RPC bodies or produce a partially usable document.
        detail = str(error) if isinstance(error, issuer.Invalid) else type(error).__name__
        print("redemption refused; no burn body built: " + detail)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
