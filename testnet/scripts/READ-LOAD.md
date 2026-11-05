# Bounded read workload

`sustained_read_load.run(packet, fresh_output_directory)` measures the declared
read request rate, errors and latency on the approved two-observer topology.
`read_client.py` supplies one bounded HTTP exchange and checks the fixed genesis
namespace on masterchain-info responses. These are read-only tools: they never
sign, send transactions or authorize financial recovery.

The runner was previously deployed from a pinned measurement capsule. Its fixed
four-worker/four-future limit could discard scheduled requests even when RPC
latency stayed within its SLO. An actual loopback test with 0.6-second replies
reproduces the failure at eight requests/second. The worker and pending limits
now both cover the 2.5-second network deadline plus 0.5 seconds of scheduling
margin: 24 at eight requests/second, at most 48 at the maximum declared rate16.
A changed deadline that would exceed48 refuses before allocating workers.

This admission budget does not guarantee an SLO on overloaded hardware. The
original90% minimum rate,1% error bound,p95<=2s,p99<=5s, body/header limits,
actual-worker-start window attribution and failure-on-namespace-change remain.
The context/result records the effective concurrency. The same pending bound
prevents an unbounded executor queue. Maximum response size remains1MiB;
calibrate process memory, threads and actual workload behavior under the
intended service limits before a new long run.

Run the synthetic tests from the repository root with its Python test environment:

```sh
python -m pytest -q testnet/tests/test_read_load_capacity.py
```

They use actual loopback HTTP with synthetic responses, never the live observer
ports. Reverting to four workers must still fail the fixed rate criterion while
latency/errors pass. Parameter and hard-ceiling controls cover resource bounds.
These tests do not reproduce the entire failed public window or establish node
capacity, native finality, financial settlement or a complete72-hour acceptance.

Keep the failed original run and its criteria unchanged. Finish independent
original-operation reconciliation and review a fresh runtime capsule before
starting another financial generation. Do not replace a running or retained
capsule in place.

The CLI requires explicit `--packet PUBLIC_PACKET.json --output NEW_DIRECTORY`.
If the packet declares an output path, it must match. There is no default old
capsule path, implicit resume or reuse of an earlier output directory. Packet
bytes and the worker budget are bounded before a new run is admitted.
