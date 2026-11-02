# Executed election fee alert controls

15tests GREEN;15 corresponding guard removals RED in test bodies. Reproduce with `testnet/tests/election_fee_controls.py --out NEW_DIRECTORY`. Raw receipts at `/tos/build/e6-election-lifecycle/fee-watch/controls-r1/` on the authorized test host, retained through2027-02-01UTC; existing authorized SSH access. No chain writes or private inputs.

## test_early_warning_before_stake_exhaustion

Exit1, excerpt SHA-256 `b32d6bc6c5cd6ddc2b29b2c8c23fa0e420d94d966f37a3a95082ba4e03c057c0`.

```text
FAIL: test_early_warning_before_stake_exhaustion (__main__.FeeWatch)
AssertionError: 'HEALTHY_FEE_RESERVE' != 'LOW_FEE_RUNWAY'
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_exact_threshold_is_healthy

Exit1, excerpt SHA-256 `5ed1ff64a399aa7763c1ebdb40735279fc5a64d4a139a72e4cda281a9afa0f3c`.

```text
FAIL: test_exact_threshold_is_healthy (__main__.FeeWatch)
AssertionError: 'LOW_FEE_RUNWAY' != 'HEALTHY_FEE_RESERVE'
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_low_balance_is_critical

Exit1, excerpt SHA-256 `22ec1c98cb564548d4d01c7a2a3c3b79af5be542bfdaf3c04871a7dbcd322595`.

```text
FAIL: test_low_balance_is_critical (__main__.FeeWatch)
AssertionError: False is not true
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_disagreement_never_reports_health

Exit1, excerpt SHA-256 `0a7d3bc86062efe911c5334966e1e1c70013c23bd62b3a873dec9163ccfa3869`.

```text
FAIL: test_disagreement_never_reports_health (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_stale_or_future_sources_refuse

Exit1, excerpt SHA-256 `aa00bc2f3b900577b1035b449538c56f0829b5caf0c5f028c83c52c3b999df06`.

```text
FAIL: test_stale_or_future_sources_refuse (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_wrong_genesis_refuses

Exit1, excerpt SHA-256 `b9cb4cd8044a00c5401834ca9df6093204945766c4c860ff9f55947ff19bf705`.

```text
FAIL: test_wrong_genesis_refuses (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_wrong_checkpoint_refuses

Exit1, excerpt SHA-256 `7a165368ac3b2084ffb2a6c90a5a55156b11fae1619b377ef6feb6a1dfc5c74c`.

```text
FAIL: test_wrong_checkpoint_refuses (__main__.FeeWatch)
AssertionError: "full-id" does not match "account read not bound to common checkpoint"
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_account_checkpoint_is_not_just_height

Exit1, excerpt SHA-256 `4270cbf8fb6f18198f978195dfc1615a928373ba0527be92a32315c2036b9177`.

```text
FAIL: test_account_checkpoint_is_not_just_height (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_malformed_amount_cannot_be_a_healthy_reserve

Exit1, excerpt SHA-256 `19617eb1dadcf0b5ed1be6ecc61e52a25e2133d1cea94b15d5ef8d8d856fbea5`.

```text
FAIL: test_malformed_amount_cannot_be_a_healthy_reserve (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_one_rpc_cannot_masquerade_as_two

Exit1, excerpt SHA-256 `1dc01b909c02515d23c3c9b3455a53b6a6b793dc1f83613c69bfd65982324499`.

```text
FAIL: test_one_rpc_cannot_masquerade_as_two (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_duplicate_wallets_refuse

Exit1, excerpt SHA-256 `fc11c0064b60356b4e4179382849ea9eca0662dff2dac56bf4177666a54877db`.

```text
FAIL: test_duplicate_wallets_refuse (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_non_read_method_refuses_before_network

Exit1, excerpt SHA-256 `18869850480c4c2aa7982f8062a5b7b4fd258960d84c372bcf849bc143ea8dd4`.

```text
Ran 1 test in 0.003s
FAILED (errors=1)
```

## test_reply_byte_bound_is_checked_before_json

Exit1, excerpt SHA-256 `903bba788e8d0a6bbde0742022ed8defd86851e47b23070e9bd36a007d005a05`.

```text
ERROR: test_reply_byte_bound_is_checked_before_json (__main__.FeeWatch)
Ran 1 test in 0.015s
FAILED (errors=1)
```

## test_manifest_population_is_bounded_before_reads

Exit1, excerpt SHA-256 `0c2066903d07f0691e78a27b26beb65153c7753d842d2a70d2448d3de34d3bea`.

```text
FAIL: test_manifest_population_is_bounded_before_reads (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_status_replaces_previous_health_on_unknown_read

Exit1, excerpt SHA-256 `264215fe207da4cfc5fa9fae5e16c2282c4121c0d85cddd19dbd6875dd9513c3`.

```text
ERROR: test_status_replaces_previous_health_on_unknown_read (__main__.FeeWatch)
Ran 1 test in 0.004s
FAILED (errors=1)
```
