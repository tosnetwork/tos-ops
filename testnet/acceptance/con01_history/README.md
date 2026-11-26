# Independent historical consensus proof audit

This read-only Epoch-6 auditor authenticates key-block transitions from an explicitly pinned genesis, including partial proof packets. It independently decodes TL/BOC, derives the governing ConfigParam34/session and verifies ML-DSA-44 with OpenSSL. It imports neither the node checker nor the native proof verifier. Public fixtures contain no private wallet or privacy-pool material.

The old observer first rejected block264347 because its timestamp was one second past the current validator set's planned end. Both native verification and the independent OpenSSL signatures accept that actual certificate: the authenticated source configuration still selects that set. The planned end is reported as `term_schedule=after_until`, rather than overriding authenticated current-set selection. This does **not** excuse a missed election. Duplicate/unknown signers, wrong algorithm, insufficient weight, wrong full block identity, source configuration, governing key or session remain rejected.

## Upstream and scope

At TOS main b17f01baad87d140d402e901a708ef9dfa15dc7d, `crypto/block/mc-config.cpp:2175` selects `cur_validators_`; `crypto/block/check-proof.cpp:489` verifies the source configuration and certificate. Fetched upstream ton-blockchain/ton commit857b8a57a178e6ae0fe7fa86e7d81c5233de8560 has the same current-set fallback at `mc-config.cpp:1861` and native proof verification at `check-proof.cpp:489`. The extra wall-clock rejection exists only in our external observer (`verify.py:21`); this tool is absent upstream. No consensus implementation is changed or upstream issue opened.

`collect` obtains an archival genesis prefix and independently matching suffixes from three named RPC sources. A join key is taken only from the verified genesis chain. Archive data does not become three historical observations. Neither this report nor a restored cryptographic chain closes live collection gaps, qualifies missed handovers, proves every intervening certificate, or supersedes the original CON-01 verdict. Preserve the original streams, checkpoint and verdict unchanged. Use a fresh output directory for every audit.

## Build and reproduce

Requires Linux, `/proc`, memfd/sealing support, Python3, and OpenSSL3.5 or newer with ML-DSA support. The verifier uses the same libc `memfd_create` syscall when a standalone Python build omits its `os` binding; unavailable kernel/libc support still refuses, never falling back to an unsealed file. Python optimization is refused because wire decoding uses assertions. Build against a trusted pinned OpenSSL installation:

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror \
  -I "$OPENSSL_PREFIX/include" testnet/acceptance/con01_history/mldsa_verify.c \
  "$OPENSSL_PREFIX/lib/libcrypto.a" -ldl -pthread -o "$AUDIT_HELPER"
chmod 500 "$AUDIT_HELPER"
sha256sum "$AUDIT_HELPER"
export CON01_SIGNATURE_VERIFIER="$AUDIT_HELPER"
export CON01_SIGNATURE_VERIFIER_SHA256=REPLACE_WITH_EXACT_DIGEST
/usr/bin/python3 -m unittest discover -s testnet/tests -p test_con01_history.py -v
/usr/bin/python3 testnet/tests/con01_history_controls.py --out "$NEW_CONTROL_DIRECTORY"
```

The backend must be a regular, singly linked ELF owned by root or the executing user, with no group/other writes. Its exact digest is checked, then a sealed executable snapshot prevents path replacement between verification calls. No signing API is present. Shared system libraries remain part of the trusted host environment.

Verify the public historical fixture:

```sh
PYTHONPATH=production /usr/bin/python3 -m con01_history.audit \
  --verifier "$AUDIT_HELPER" --verifier-sha256 "$CON01_SIGNATURE_VERIFIER_SHA256" \
  verify --anchor testnet/tests/data/con01-history/anchor.json \
  --target testnet/tests/data/con01-history/target.json \
  --proof testnet/tests/data/con01-history/expired-current-set.tl \
  --out "$NEW_REPORT_FILE"
```

For collection supply `collect --anchor PINNED_GENESIS.json --rpc node1=http://127.0.0.1:PORT1/jsonRPC --rpc node3=http://127.0.0.1:PORT3/jsonRPC --rpc node5=http://127.0.0.1:PORT5/jsonRPC --archive node5 --join-key 246589 --out NEW_DIRECTORY` instead of the `verify` subcommand. Only explicit loopback HTTP origins are permitted; establish authorized tunnels separately. The genesis must be approved independently of the RPC responses.

## Bounds and evidence

Each proof/RPC response is capped at2MiB, each chain at64 packets/64MiB/512 links. BOC parsing caps cells at65536, refs at4, depth at256. Cell hash caches are cleared per packet, including rejected input. Each signature helper runs with a5-second timeout, fixed public key/signature sizes and a message buffer smaller than4096 bytes; its EVP objects are freed on all completion paths. There is no long-lived C state, queue, key generation, transaction send or host lifecycle action. Collection is sequential with bounded response time and spacing; this is an offline/occasional audit, not an unbounded background collector.

See [EVIDENCE.md](EVIDENCE.md) for the original14 test-body guard-removal failures and fixture digests. The current runner also removes executable sealing, for15 controls; its new compatibility test must fail in the test body. A full live run verified39 links from genesis to block690220, using3 archival packets and matching three-source suffixes. The separately pinned native C++ verifier accepted that exact full chain and the original block264347 certificate. Timing incidents remain explicit in the independent report. This is cryptographic repair evidence, not a 24-hour operational acceptance claim.

Checklist: CS-4 (existed / not applied: the external observer imposed an expiry condition absent from native current-set selection). Sibling review found the same condition in the original offline/live observer and current-term operational wrapper; original qualification artifacts remain frozen, while this revision provides a distinct historical audit. The existing `testnet/scripts/check-handover.py:49` already distinguishes extended terms, but trusts RPC headers/configuration rather than a genesis-authenticated proof chain; it is retained for that distinct scope. Current-term qualification still requires a timely election. Delayed elections also exposed operator-fee exhaustion and stale key-registration expiry; those operational defects require their own checks and remediation.
