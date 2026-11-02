# Executed election fee alert controls

17tests GREEN;17 corresponding guard removals RED in test bodies. Reproduce with `testnet/tests/election_fee_controls.py --out NEW_DIRECTORY`. Raw receipts at `/tos/build/e6-election-lifecycle/fee-watch/controls-r4/` on the authorized test host, retained through2027-02-01UTC; existing authorized SSH access. No chain writes or private inputs.

## test_early_warning_before_stake_exhaustion

Exit1, excerpt SHA-256 `af7e7767e62c24276e8f48d4e1698190b7887b26cdb4c830c1c137a4a84527ca`.

```text
FAIL: test_early_warning_before_stake_exhaustion (__main__.FeeWatch)
AssertionError: 'HEALTHY_FEE_RESERVE' != 'LOW_FEE_RUNWAY'
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_exact_threshold_is_healthy

Exit1, excerpt SHA-256 `dd96f110c51ad55a092963c8e89d4be30b2a7a5264c183e765b105795fc04e3b`.

```text
FAIL: test_exact_threshold_is_healthy (__main__.FeeWatch)
AssertionError: 'LOW_FEE_RUNWAY' != 'HEALTHY_FEE_RESERVE'
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_low_balance_is_critical

Exit1, excerpt SHA-256 `25be61dac05615ae4ae7bd3d9907b2219f315f866002acf608a79dea93a46486`.

```text
FAIL: test_low_balance_is_critical (__main__.FeeWatch)
AssertionError: False is not true
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_disagreement_never_reports_health

Exit1, excerpt SHA-256 `d9d6118c4571b46f2fdaaf3d6688d2181adfdc9dfaf670b29bf743159d4add97`.

```text
FAIL: test_disagreement_never_reports_health (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_stale_or_future_sources_refuse

Exit1, excerpt SHA-256 `a3248a9246729a90093a043eacf7a0fd2bce1d19a4e73139a2eff015d7578358`.

```text
FAIL: test_stale_or_future_sources_refuse (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_wrong_genesis_refuses

Exit1, excerpt SHA-256 `91418c87bb3b6823f787e47ede4a11e7108c84092e182ff74aaf5ee30084c06d`.

```text
FAIL: test_wrong_genesis_refuses (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_wrong_checkpoint_refuses

Exit1, excerpt SHA-256 `231be490255ab2c6bee68ffb72c6435457253b08fc25852b4cc797b97573467d`.

```text
FAIL: test_wrong_checkpoint_refuses (__main__.FeeWatch)
AssertionError: "full-id" does not match "account read not bound to common checkpoint"
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_account_checkpoint_is_not_just_height

Exit1, excerpt SHA-256 `3a5957d9ca5ff41cb3e9eefb6a01a0b3771c8faceab30d93deef803dbda782c4`.

```text
FAIL: test_account_checkpoint_is_not_just_height (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_malformed_amount_cannot_be_a_healthy_reserve

Exit1, excerpt SHA-256 `c4505255ad28ed8837f9cf48359874cb20733a535812e832c465230148e38f53`.

```text
FAIL: test_malformed_amount_cannot_be_a_healthy_reserve (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_one_rpc_cannot_masquerade_as_two

Exit1, excerpt SHA-256 `e9c17e0fda58c5225f9850d97b1d4811fdc5d267db977d1badc72b72072eb328`.

```text
FAIL: test_one_rpc_cannot_masquerade_as_two (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_duplicate_wallets_refuse

Exit1, excerpt SHA-256 `f3e8a3f0ec6094ab5b354862260fec488c4f5b25a36c65d125a4fc59cc082f89`.

```text
FAIL: test_duplicate_wallets_refuse (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_non_read_method_refuses_before_network

Exit1, excerpt SHA-256 `0e95ca689b71122d60176e0fd9eea5719acfb0ab5eecb1c9cf6ae82a9349fbdb`.

```text
Ran 1 test in 0.004s
FAILED (errors=1)
```

## test_reply_byte_bound_is_checked_before_json

Exit1, excerpt SHA-256 `d805f7d0836522e6b503547619fcb1aa0f97249fe924b921d6cb159521dace1b`.

```text
ERROR: test_reply_byte_bound_is_checked_before_json (__main__.FeeWatch)
Ran 1 test in 0.016s
FAILED (errors=1)
```

## test_manifest_population_is_bounded_before_reads

Exit1, excerpt SHA-256 `1ac9a99793a80f8a70ddb05319b8f1e79af980cc68e1f91a1fca37331941e789`.

```text
FAIL: test_manifest_population_is_bounded_before_reads (__main__.FeeWatch)
AssertionError: Refused not raised
Ran 1 test in 0.001s
FAILED (failures=1)
```

## test_status_replaces_previous_health_on_unknown_read

Exit1, excerpt SHA-256 `dc1a9048eb489c8ed2bfafa856f41994318a9c865d084ae7ed6894dcb9b78ff6`.

```text
ERROR: test_status_replaces_previous_health_on_unknown_read (__main__.FeeWatch)
Ran 1 test in 0.005s
FAILED (errors=1)
```

## test_cli_nonobject_manifest_replaces_health_with_unknown

Exit1, excerpt SHA-256 `da0f60cbb69d0b510dc0d1971a37ece1caad1072b0f3292095d76a3aaa9f126f`.

```text
FAIL: test_cli_nonobject_manifest_replaces_health_with_unknown (__main__.FeeWatch)
AssertionError: False is not true
Ran 1 test in 0.005s
FAILED (failures=1)
```

## test_protocol_or_unexpected_read_failure_replaces_previous_health

Exit1, excerpt SHA-256 `bc2f72675f1746c4d47e9d6a4fff13d3510eef7f71ceaaf899947036f86a9a8a`.

```text
ERROR: test_protocol_or_unexpected_read_failure_replaces_previous_health (__main__.FeeWatch)
Ran 1 test in 0.004s
FAILED (errors=1)
```
