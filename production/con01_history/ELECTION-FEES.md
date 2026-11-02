# Election fee reserve alert

Run `python3 -m con01_history.election_fees` with two distinct explicit loopback
`--rpc` origins, an independently approved full `--genesis` identity, a
`--wallets` JSON map of node labels to masterchain fee-wallet addresses, and
`--out STATUS.json` in an existing private directory. Use `PYTHONPATH=production`.
There are no signing, funding, refill, retry-payment or validator-lifecycle methods.

Both peers must report the approved genesis, identical full checkpoint IDs and
identical balances read at that checkpoint. The checkpoint must be at most60s
old and not in the future. This is corroborated RPC observation for an alert,
not a cryptographic spending authorization. RPC errors, disagreement, bad values
and stale observations produce INDETERMINATE (exit2), replacing previous health.
Below5.2TOS gives LOW_FEE_RUNWAY (exit1), including a critical flag below the1.4TOS
next-stake fee. Healthy reserves exit0. The threshold is three nominal stake
submissions plus1TOS storage, not a time guarantee; pool maintenance, recovery
and live prices can consume additional fees. Consumers must reject a report
past `valid_until_utc` (10minutes). Check service failures as well as the report.

After independent review, render the committed coordinator user units with
`python3 testnet/scripts/install-election-fee-watch.py --rpc URL_A --rpc URL_B
--wallets ABS_MANIFEST --genesis ABS_GENESIS --status ABS_STATUS --render-dir
NEW_DIRECTORY`. Paths must be absolute without whitespace/metacharacters.
Review the rendered units and `systemd-analyze --user verify` result, then use
`--apply` instead of `--render-dir` to install/enable the five-minute timer.
This installs only a coordinator user monitor, never a validator host unit.
The installer requires clean tracked module/template sources and the service
pins them to the installed Git revision. Retain that checkout while referenced.
Logs are in the user journal; status is one bounded latest file. No external
message or Telegram is sent by this tool. A low reserve requires a separately
authorized, journaled owner-funded maintenance operation, never PRI funds.

The monitor admits at most16 distinct fee wallets, limits every RPC reply to2MiB,
uses a10s request timeout and0.6s spacing, and has no queue/history/database.
The unit caps memory at128MiB and runtime at120s. Input manifests are capped at16KiB.
Balance values must be unsigned ASCII decimal u64; unknown is never zero/healthy.

Upstream comparison: this coordinator/Python and Rust fee-observability path is
TOS-specific, absent from fetched ton-blockchain/ton857b8a57. No inherited core
or consensus implementation is changed. Checklist: OB-1 (existed / not applied:
previous monitoring observed chain heads but did not warn on election fee runway).

Validation:15 regressions GREEN and15 matching disposable guard removals RED;
`testnet/tests/election_fee_controls.py` plus `election-fee-controls.json` reproduce
those controls. Exact bounded failure excerpts and receipt hashes are retained
in ELECTION-FEE-EVIDENCE.md. A real two-source read on Epoch-6 found all four fee
wallets at about8.11TOS. This is an observation, not authorization to top up.
