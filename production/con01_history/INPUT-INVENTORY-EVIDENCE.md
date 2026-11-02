# Complete worker input inventory evidence

Baseline/restored61tests PASS;40 intended test-body guard removals detected. Actual source directories and worker-discovered raw segments must equal the snapshot and digest inventories. The four additional controls below cover launch and qualification, using explicitly synthetic metadata fixtures. Raw receipts retained through2027-02-01UTC via existing authorized toserver SSH; source/runner/fixture/raw hashes in INPUT-INVENTORY-EVIDENCE.json.

## qualification-extra-worker-segment

Exit 1; SHA-256 `b7df8947ffa397896cd7305b8480a68e63b1cc909c55d9004d2191e86421a3c3`.

```text
FAIL: test_unlisted_worker_segment_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.006s
FAILED (failures=1)
```

## launch-extra-worker-segment

Exit 1; SHA-256 `37e3400ea41d82208a7c1b7891da2b2894064423e9efcd2b52c92933f195f678`.

```text
FAIL: test_unlisted_worker_segment_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.005s
FAILED (failures=1)
```

## qualification-extra-source-directory

Exit 1; SHA-256 `b6690b56af02fb417031b3e59d6d1bcef77ef6e41a0d2df6f0ea23f0218081d6`.

```text
FAIL: test_extra_source_directory_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.006s
FAILED (failures=1)
```

## launch-extra-source-directory

Exit 1; SHA-256 `03c84352a7fa58fccc775594a3b16ae951800f7bf60fc19c44eecb8596f74099`.

```text
FAIL: test_extra_source_directory_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.005s
FAILED (failures=1)
```

## Reproduce

```sh
CON01_SIGNATURE_VERIFIER=/pinned/mldsa-verifier CON01_SIGNATURE_VERIFIER_SHA256=EXACT_SHA256 python3 testnet/tests/con01_rejudge_controls.py --out /new/controls
```

Upstream comparison: this observer/helper is absent at upstream857b8a57a178e6ae0fe7fa86e7d81c5233de8560; base f9e9696cc7615b9ee932b52ac02c7d2b0b01c9f3. No inherited core changes.
