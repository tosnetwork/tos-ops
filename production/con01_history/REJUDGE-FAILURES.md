# Rejudge sensitivity receipts

The baseline and restored39tests pass;18 guard removals fail in intended test bodies. Real ML-DSA certificate tests use the retained public expired-schedule packet and the pinned verifier. Judge/qualification metadata fixtures are explicitly synthetic and are not cryptographic or live observation evidence. Raw output is retained through2027-02-01 UTC on authorized toserver via existing SSH access; REJUDGE-EVIDENCE.json records sizes/digests and code hashes.

## source-key-file-binding

Exit 1; SHA-256 `3dd6ff4557f4cd0967b88b8f46518618451d73dae0ef3540737d1cef60cc3f31`.

```text
FAIL: test_cached_key_file_hash_is_bound_before_verification (test_con01_observer_crypto.ObserverCrypto)
AssertionError: True is not false : {'t': 'blk', 'src': 'node1', 'seq': 264347, 'utc': 1793404801.1, 'mode': None, 'ok': True, 'rid': ['jKuDpY+l/44DBpzm1JSHkptDBQJJ1Ux3KJK75kOb05c=', 'L8189znCk959aKJOBKKY21C8+ZjZn3AhSX9BGh2Vt34='], 'prevkey': 246589, 'gu_claim': 1793404801, 'key_claim': False, 'path': 'forward', 'cid': ['jKuDpY+l/44DBpzm1JSHkptDBQJJ1Ux3KJK75kOb05c=', 'L8189znCk959aKJOBKKY21C8+ZjZn3AhSX9BGh2Vt34='], 'parent': ['fPm39q4XcZorbKHVIIom4TrOlnaRlZZyy7uIu6UsNeo=', 'AtPwcPsYY34THc56PIOrbXusiLDzvJQYVKNmSs7aGeA='], 'parent_seq': 264346, 'gu': 1793404801, 'key': False, 'cc': 451, 'signers': 3, 'w': 864691128455135232, 'tw': 1152921504606846976, 'set': 'bd0052f670f782def5e1f0506b0b938fb6
Ran 1 test in 0.107s
FAILED (failures=1)
```

## expired-term-regression

Exit 1; SHA-256 `113a754b61e64163a4120f3954b125b9fd100351ca7a4d8e6c21e58476a6b888`.

```text
FAIL: test_expired_schedule_passes_full_observer (test_con01_observer_crypto.ObserverCrypto)
AssertionError: False is not true : {'t': 'blk', 'src': 'node1', 'seq': 264347, 'utc': 1793404801.1, 'mode': None, 'ok': False, 'rid': ['jKuDpY+l/44DBpzm1JSHkptDBQJJ1Ux3KJK75kOb05c=', 'L8189znCk959aKJOBKKY21C8+ZjZn3AhSX9BGh2Vt34='], 'prevkey': 246589, 'gu_claim': 1793404801, 'key_claim': False, 'path': 'forward', 'reason': 'term outside validity interval'}
Ran 1 test in 0.052s
FAILED (failures=1)
```

## rejected

Exit 1; SHA-256 `192abe3a8d069cd32d33cd143a4f6cfa1355ceac35d9b33bd89c982f94c11551`.

```text
FAIL: test_rejection_is_not_overwritten_by_later_success (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [{'src': 'node1', 'seq': 1, 'reason': 'invalid signature'}], 'rejected_count': 1, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'cert
Ran 1 test in 0.002s
FAILED (failures=1)
```

## stream-integrity

Exit 1; SHA-256 `c185ee53bf91f72d3145ab4c24b0de73b2106b7a42fa537aaedb2e86362e9b23`.

```text
FAIL: test_integrity_break (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [{'t': 'chain', 'src': 'node1', 'ok': False}], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified': 8, 'un
Ran 1 test in 0.002s
FAILED (failures=1)
```

## uncertified-key

Exit 1; SHA-256 `3795f5816e22e8c4022828b2dc6e7015732235eb6ea09c5eb0507affb7caf57b`.

```text
FAIL: test_uncertified_source_key_cannot_enter_trust_chain (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified': 8, 'uncovered': 0, 'uncovered_sample': [], 'unexp
Ran 1 test in 0.002s
FAILED (failures=1)
```

## third-boundary-certificate

Exit 1; SHA-256 `ae6876680f2f47c693d056d03db024330d5fe237190724da11c326d63f94760a`.

```text
FAIL: test_boundary_requires_three_certificates (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [{'src': 'node5', 'seq': 4}], 'unsupported_count': 1, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified': 8, 'uncovered': 0, 'unc
Ran 1 test in 0.002s
FAILED (failures=1)
```

## two-window-certificates

Exit 1; SHA-256 `08b8559ec1bb0b2dd5ad5ab751cb52ca8de5ae15925e4c33eccda3679c71c9c2`.

```text
FAIL: test_window_requires_two_sources (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.8, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [{'src': 'node3', 'seq': 2}, {'src': 'node5', 'seq': 2}], 'unsupported_count': 2, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certifie
Ran 1 test in 0.002s
FAILED (failures=1)
```

## three-full-ids

Exit 1; SHA-256 `dce2ed99aa184a8d120e9807ad43f6034df3dab3a97516ead1d8be0622422ee6`.

```text
FAIL: test_full_ids_require_three_sources (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified': 8, 'uncovered': 0, 'uncovered_sample': [], 'unexp
Ran 1 test in 0.002s
FAILED (failures=1)
```

## shard-inclusion

Exit 1; SHA-256 `1195cd4e2089672164f6fb730ba57426d1bd6e3d4407b0a9683cece92f91603c`.

```text
FAIL: test_shard_inclusion_requires_two_sources (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified': 8, 'uncovered': 0, 'uncovered_sample': [], 'unexp
Ran 1 test in 0.002s
FAILED (failures=1)
```

## live-observation

Exit 1; SHA-256 `f5195de45d35fa3ceb116bb6766b6acf2ce92d62f4636f10e2400afa75ee5746`.

```text
FAIL: test_missing_live_heads (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified': 8, 'uncovered': 0, 'uncovered_sample': [], 'unexp
Ran 1 test in 0.002s
FAILED (failures=1)
```

## outgoing-boundary-set

Exit 1; SHA-256 `389087fbb11d1458116efe687dec7bb68a91a68cfbeff53fcd94fdd02e7f1d5d`.

```text
FAIL: test_outgoing_boundary_set_must_match (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified': 8, 'uncovered': 0, 'uncovered_sample': [], 'unexp
Ran 1 test in 0.002s
FAILED (failures=1)
```

## incoming-next-set

Exit 1; SHA-256 `c9d9824a1576262ecb984118e5bb0173fe87d461f541491fd74ec06845e80026`.

```text
FAIL: test_incoming_set_must_certify_following_block (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified': 8, 'uncovered': 0, 'uncovered_sample': [], 'unexp
Ran 1 test in 0.002s
FAILED (failures=1)
```

## incomplete-replay

Exit 1; SHA-256 `dc0033dcd874549bf6832379634104921e91c7b5e3186bb7b389f8ecde7b31c4`.

```text
FAIL: test_incomplete_replay_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.010s
FAILED (failures=1)
```

## replay-revision

Exit 1; SHA-256 `6001766d4dd5b2d3c32cf221aabf08b93dcd6394167abe427684690c7184fa7d`.

```text
FAIL: test_changed_source_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.007s
FAILED (failures=1)
```

## control-revision

Exit 1; SHA-256 `ec71b70df68c19e9fa292b72f1d19f511d775b4f2073fb7bd22f9baa80348153`.

```text
FAIL: test_changed_control_revision_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.007s
FAILED (failures=1)
```

## all-controls-required

Exit 1; SHA-256 `4fe447e54459f2893aa4d2cf50b79e2e5a73f671571f6933acafdf4e860cea93`.

```text
FAIL: test_missing_controls_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.007s
FAILED (failures=1)
```

## snapshot-size

Exit 1; SHA-256 `bed7a71ba5455bda0f228cf920e98da27c31e9c4aedcca53ef7885f7635dfc61`.

```text
FAIL: test_frozen_size_change_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.007s
FAILED (failures=1)
```

## three-source-inventory

Exit 1; SHA-256 `3a2cfd474ff1130d2cc6642f6033f5b5a196ba7f607f5a6376d231b54fc07dde`.

```text
FAIL: test_missing_third_source_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.007s
FAILED (failures=1)
```

