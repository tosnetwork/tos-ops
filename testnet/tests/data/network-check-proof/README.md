# Public proof fixtures

These are the existing consensus verifier's recorded public material from
`test/pq-native/data/proof-verify-real` at source revision `85c679c34`:
`anchor.json`, `historical-request.json` (named `request.json` here), and the four
`historical/` material files. No key or secret is included. The source fixture
was captured on 2026-10-05 and is not fetched again by tests.

The positive test verifies the complete chain, configuration and account state.
One negative flips a byte inside a TL-encoded 2420-byte ML-DSA-44 signature,
leaving TL structure unchanged. The other changes the proof's source root so
its link no longer starts at the held anchor. Both must be refused by the real
consensus core, not by a mock signature implementation.

`../network-check-epoch4.json` contains public Config8/9/10/19/32/34/48 cells and
Elector data at its recorded epoch-4 masterchain block. Elector data agreed
between two nodes. The checker independently authenticated the same block's
configuration and Elector account through the held zero-state anchor during the
live run. The current set is elected; the previous frozen record was already
removed. Synthetic retained-history tests reuse the recorded set cells and
explicitly construct matching past-election records, without claiming those
synthetic cells were returned by the network.
