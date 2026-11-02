# Completion-time fee observation evidence

19tests PASS and19 guard removals fail in their intended test bodies. The slow-success regression failed against the previous CLI (it published healthy/exit0 after61synthetic seconds) and passes with end-of-round freshness validation. This is explicit synthetic time/RPC evidence, not cryptographic spending authorization. Raw receipts retained through2027-02-01 via existing authorized toserver SSH; JSON index pins source/runner/fixture and raw excerpt hashes.

## test_slow_successful_reads_replace_health_with_unknown

Exit 1; SHA-256 `3f02535e2735c5cb7e57f37157a04de06b696e0b46e062dee9d0f985da6e5cef`.

```text
test_slow_successful_reads_replace_health_with_unknown (__main__.FeeWatch) ... FAIL

======================================================================
FAIL: test_slow_successful_reads_replace_health_with_unknown (__main__.FeeWatch)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/tmp/con01-control-v18iq4l6/testnet/tests/test_election_fee_watch.py", line 95, in test_slow_successful_reads_replace_health_with_unknown
    self.assertEqual(code, 2)
AssertionError: 0 != 2

----------------------------------------------------------------------
Ran 1 test in 0.006s

FAILED (failures=1)
```

## test_healthy_report_timestamp_is_observation_completion

Exit 1; SHA-256 `4a997a1ba2ea680f030862fd709461f074e01b749b09da268b39b751185d7d13`.

```text
test_healthy_report_timestamp_is_observation_completion (__main__.FeeWatch) ... FAIL

======================================================================
FAIL: test_healthy_report_timestamp_is_observation_completion (__main__.FeeWatch)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/tmp/con01-control-7yxzwmlm/testnet/tests/test_election_fee_watch.py", line 103, in test_healthy_report_timestamp_is_observation_completion
    self.assertEqual(report["checked_utc"], 1005)
AssertionError: 1000 != 1005

----------------------------------------------------------------------
Ran 1 test in 0.005s

FAILED (failures=1)
```

## Reproduce

```sh
python3 -m unittest discover -s testnet/tests -p test_election_fee_watch.py
python3 testnet/tests/election_fee_controls.py --out /new/fee-controls
```

Upstream comparison: this observer and its CLI are absent at upstream857b8a57a178e6ae0fe7fa86e7d81c5233de8560; base f368c92427cda3bf6dda009bffb75214c9d0eb28. This fixes a TOS-specific advisory timestamp/freshness defect; no inherited core or signing behavior changes.
