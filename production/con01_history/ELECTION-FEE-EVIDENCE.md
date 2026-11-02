# Executed election fee alert controls

16tests GREEN;16 corresponding guard removals RED in test bodies. Reproduce with `testnet/tests/election_fee_controls.py --out NEW_DIRECTORY`. Raw receipts at `/tos/build/e6-election-lifecycle/fee-watch/controls-r2/` on the authorized test host, retained through2027-02-01UTC; existing authorized SSH access. No chain writes or private inputs.

## test_early_warning_before_stake_exhaustion

Exit1, excerpt SHA-256 `87a04166ce09b98f806d0a3df0f56a4534a0396d7ae2617000f38457a5bb97bb`.

```text
FAIL: test_early_warning_before_stake_exhaustion (__main__.FeeWatch)
AssertionError: 'HEALTHY_FEE_RESERVE' != 'LOW_FEE_RUNWAY'
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_exact_threshold_is_healthy

Exit1, excerpt SHA-256 `c3693dbb7d9b3def352be6986e456576d08a4d3b2daca8f0c4f0c664d93b1728`.

```text
FAIL: test_exact_threshold_is_healthy (__main__.FeeWatch)
AssertionError: 'LOW_FEE_RUNWAY' != 'HEALTHY_FEE_RESERVE'
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_low_balance_is_critical

Exit1, excerpt SHA-256 `96c7b783cb1c9dff56b8c68f89a27d36c1ca5e167ba146fb22068a519585a80f`.

```text
FAIL: test_low_balance_is_critical (__main__.FeeWatch)
AssertionError: False is not true
Ran 1 test in 0.000s
FAILED (failures=1)
```

## test_disagreement_never_reports_health

Exit1, excerpt SHA-256 `019579921e87bf2bd5d5f8f8f47c121d7af126c8da157ad6d6e9af12a6ce9f23`.

```text
FAIL: test_disagreement_never_reports_health (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_stale_or_future_sources_refuse

Exit1, excerpt SHA-256 `d98b1a61cc306c3d0aa8ee38f48162e38d8b3fb3eca0587f9d7e5968aa72916d`.

```text
FAIL: test_stale_or_future_sources_refuse (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_wrong_genesis_refuses

Exit1, excerpt SHA-256 `eca467e8fb2090bbd83b6608db43d597e5b813b32293210dab5e6241614e6e33`.

```text
FAIL: test_wrong_genesis_refuses (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_wrong_checkpoint_refuses

Exit1, excerpt SHA-256 `72ebf95c9d39bf1afa6e69092fb826d6208c8a1fb91bb335586a1195e3f04d4f`.

```text
FAIL: test_wrong_checkpoint_refuses (__main__.FeeWatch)
AssertionError: "full-id" does not match "account read not bound to common checkpoint"
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_account_checkpoint_is_not_just_height

Exit1, excerpt SHA-256 `1b10a9dcf5cec7e342205958625cf05659005f0a46f9ab29be911439a310d464`.

```text
FAIL: test_account_checkpoint_is_not_just_height (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_malformed_amount_cannot_be_a_healthy_reserve

Exit1, excerpt SHA-256 `a277ba118eab89143ed69542b89d54306cfeb0421b18cdc59341bee07a30e596`.

```text
FAIL: test_malformed_amount_cannot_be_a_healthy_reserve (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_one_rpc_cannot_masquerade_as_two

Exit1, excerpt SHA-256 `3d5530e53ae6e5d5d3888a051881c4017bdf834853c42d30ea7f829b86ee84ea`.

```text
FAIL: test_one_rpc_cannot_masquerade_as_two (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_duplicate_wallets_refuse

Exit1, excerpt SHA-256 `b9f10819dfb136fa95d59869a86bcd1c918141eaf29ec8621adf9d18f5a9ee13`.

```text
FAIL: test_duplicate_wallets_refuse (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_non_read_method_refuses_before_network

Exit1, excerpt SHA-256 `3729763e955581444a0be397532a51ef023b1ae6679f0f9a39c36550fcd4c67a`.

```text
Ran 1 test in 0.003s
FAILED (errors=1)
```

## test_reply_byte_bound_is_checked_before_json

Exit1, excerpt SHA-256 `c55dda1b0496996156ca5cc618a25df21d9f2da9fc8c708fb080d69783b3d5e8`.

```text
ERROR: test_reply_byte_bound_is_checked_before_json (__main__.FeeWatch)
Ran 1 test in 0.015s
FAILED (errors=1)
```

## test_manifest_population_is_bounded_before_reads

Exit1, excerpt SHA-256 `823d225863419f00b4da2bcf437baba7b7d848512f91db5ec834fd19bff9d30f`.

```text
FAIL: test_manifest_population_is_bounded_before_reads (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_status_replaces_previous_health_on_unknown_read

Exit1, excerpt SHA-256 `8801320439aaba5aaa2b97da2138689e80360e79c55e7099cdaefa8fa6719118`.

```text
ERROR: test_status_replaces_previous_health_on_unknown_read (__main__.FeeWatch)
Ran 1 test in 0.003s
FAILED (errors=1)
```

## test_cli_nonobject_manifest_replaces_health_with_unknown

Exit1, excerpt SHA-256 `92e7b2d2e70ea33a52cb5999a5f69af76cae245e6b0f0d3d7f16b96870f87152`.

```text
ERROR: test_cli_nonobject_manifest_replaces_health_with_unknown (__main__.FeeWatch)
Ran 1 test in 0.002s
FAILED (errors=1)
```
