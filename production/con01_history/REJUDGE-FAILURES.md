# Rejudge sensitivity receipts

Baseline/restored53tests PASS;31 guard removals fail in intended runtime test bodies. Real certificates use retained public data and the pinned verifier. Judge/qualification/launch fixtures are explicitly synthetic metadata, not live cryptographic evidence. Raw output retained through2027-02-01UTC via existing authorized toserver SSH; JSON index binds code/runner/fixture hashes and raw sizes/digests.

## source-key-file-binding

Exit 1; SHA-256 `a0263f3496fca61525f27be3aa9734ef32c1b9b49baf84a8289dd71dc625a388`.

```text
FAIL: test_cached_key_file_hash_is_bound_before_verification (test_con01_observer_crypto.ObserverCrypto)
AssertionError: True is not false : {'t': 'blk', 'src': 'node1', 'seq': 264347, 'utc': 1793404801.1, 'mode': None, 'ok': True, 'rid': ['jKuDpY+l/44DBpzm1JSHkptDBQJJ1Ux3KJK75kOb05c=', 'L8189znCk959aKJOBKKY21C8+ZjZn3AhSX9BGh2Vt34='], 'prevkey': 246589, 'gu_claim': 1793404801, 'key_claim': False, 'path': 'forward', 'cid': ['jKuDpY+l/44DBpzm1JSHkptDBQJJ1Ux3KJK75kOb05c=', 'L8189znCk959aKJOBKKY21C8+ZjZn3AhSX9BGh2Vt34='], 'parent': ['fPm39q4XcZorbKHVIIom4TrOlnaRlZZyy7uIu6UsNeo=', 'AtPwcPsYY34THc56PIOrbXusiLDzvJQYVKNmSs7aGeA='], 'parent_seq': 264346, 'gu': 1793404801, 'key': False, 'cc': 451, 'signers': 3, 'w': 864691128455135232, 'tw': 1152921504606
Ran 1 test in 0.101s
FAILED (failures=1)
```

## expired-term-regression

Exit 1; SHA-256 `d55de53005c87472ffb0ea050bfa4657c95768d55567519218fbfab39aec4d4a`.

```text
FAIL: test_expired_schedule_passes_full_observer (test_con01_observer_crypto.ObserverCrypto)
AssertionError: False is not true : {'t': 'blk', 'src': 'node1', 'seq': 264347, 'utc': 1793404801.1, 'mode': None, 'ok': False, 'rid': ['jKuDpY+l/44DBpzm1JSHkptDBQJJ1Ux3KJK75kOb05c=', 'L8189znCk959aKJOBKKY21C8+ZjZn3AhSX9BGh2Vt34='], 'prevkey': 246589, 'gu_claim': 1793404801, 'key_claim': False, 'path': 'forward', 'reason': 'term outside validity interval'}
Ran 1 test in 0.050s
FAILED (failures=1)
```

## rejected

Exit 1; SHA-256 `661bd5a96e7cf0de8ef8621a56777dc00ba39af75216360eb17071df12c71b73`.

```text
FAIL: test_rejection_is_not_overwritten_by_later_success (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [{'src': 'node1', 'seq': 1, 'reason': 'invalid signature'}], 'rejected_count': 1, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, '
Ran 1 test in 0.002s
FAILED (failures=1)
```

## stream-integrity

Exit 1; SHA-256 `6ba935c8efeb795222b7478412588ed5b264264ac26f3044aec05670ab0d03b2`.

```text
FAIL: test_integrity_break (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [{'t': 'chain', 'src': 'node1', 'ok': False}], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 
Ran 1 test in 0.002s
FAILED (failures=1)
```

## uncertified-key

Exit 1; SHA-256 `c3a22fd153b15969244c6763813a7758b3cd0d450afbf304dbee10e3004d5a35`.

```text
FAIL: test_uncertified_source_key_cannot_enter_trust_chain (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified':
Ran 1 test in 0.002s
FAILED (failures=1)
```

## third-boundary-certificate

Exit 1; SHA-256 `c86ecab068e4dc390a738872fa3b4ac881cf1dfa1fdbdf65e4cbf698da36f86a`.

```text
FAIL: test_boundary_requires_three_certificates (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [{'src': 'node5', 'seq': 4}], 'unsupported_count': 1, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo'
Ran 1 test in 0.002s
FAILED (failures=1)
```

## two-window-certificates

Exit 1; SHA-256 `06a9c189f396e249efb08fcecd56efdcc8c0e221bed3164c23544456b21eb857`.

```text
FAIL: test_window_requires_two_sources (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.8, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [{'src': 'node3', 'seq': 2}, {'src': 'node5', 'seq': 2}], 'unsupported_count': 2, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'bloc
Ran 1 test in 0.002s
FAILED (failures=1)
```

## three-full-ids

Exit 1; SHA-256 `d9672eee1f6f065ebce656d8305627f8258e5fa54d214b12bed1208c3c31f0a7`.

```text
FAIL: test_full_ids_require_three_sources (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified':
Ran 1 test in 0.002s
FAILED (failures=1)
```

## shard-inclusion

Exit 1; SHA-256 `b81e88b6d69ab581cf8e39dd90647a3f3accd7ce50aed2753008a3cdc398377f`.

```text
FAIL: test_shard_inclusion_requires_two_sources (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified':
Ran 1 test in 0.002s
FAILED (failures=1)
```

## live-observation

Exit 1; SHA-256 `a112fb21454bd06d322ae8046ed61027be6e57ce0454cbff0d9eb2e861d16ac8`.

```text
FAIL: test_missing_live_heads (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified':
Ran 1 test in 0.002s
FAILED (failures=1)
```

## outgoing-boundary-set

Exit 1; SHA-256 `0c9578d1a75a3ad8f638cb8a8b7173a727622964a956cc658c2d033927e334ee`.

```text
FAIL: test_outgoing_boundary_set_must_match (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified':
Ran 1 test in 0.002s
FAILED (failures=1)
```

## incoming-next-set

Exit 1; SHA-256 `954aebc760eab0b48f1d39a6081da47dfc4b86ee7ad7e98fa80adc3650d9e98e`.

```text
FAIL: test_incoming_set_must_certify_following_block (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified':
Ran 1 test in 0.002s
FAILED (failures=1)
```

## incomplete-replay

Exit 1; SHA-256 `3c481ef06ab7ad5f363024217737c38b739e74e2ca5176d98b9dc5eacfa6aa7d`.

```text
FAIL: test_incomplete_replay_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.012s
FAILED (failures=1)
```

## replay-revision

Exit 1; SHA-256 `f34790c7f81a3193d9b7a849c46d856535ddb8f419340fc87e69e195865a8b06`.

```text
FAIL: test_changed_source_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.012s
FAILED (failures=1)
```

## control-revision

Exit 1; SHA-256 `85448daad767f93a2eb68513d4cfb2be55801062f11cf4a64c63a122beb4421e`.

```text
FAIL: test_changed_control_revision_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.011s
FAILED (failures=1)
```

## all-controls-required

Exit 1; SHA-256 `3582ce21b001eb02f639f7bfd95704f024dc6e7718e882a8e1ef808f9c13a5aa`.

```text
FAIL: test_missing_controls_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: "complete guard controls" does not match "exact unique guard identities required"
Ran 1 test in 0.007s
FAILED (failures=1)
```

## snapshot-size

Exit 1; SHA-256 `5bbfc4268a83b43942f0fc93efa6d6b3d87e8b93b0da0eaedec6c7f864fc6c73`.

```text
FAIL: test_frozen_size_change_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.012s
FAILED (failures=1)
```

## three-source-inventory

Exit 1; SHA-256 `d60d766c8935dbceb37c59c4c98fea5261abe420937464684315e3cadee9aff1`.

```text
FAIL: test_missing_third_source_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: "three frozen original source" does not match "frozen replay input identity changed"
Ran 1 test in 0.011s
FAILED (failures=1)
```

## complete-control-inventory

Exit 1; SHA-256 `95e62d4410147faff88d9ba65c640604ce36c4e3835c32077f1318de5520cda8`.

```text
FAIL: test_incomplete_control_inventory_cannot_qualify (test_con01_qualification.QualificationMetadata) (entries=0)
AssertionError: Refused not raised
FAIL: test_incomplete_control_inventory_cannot_qualify (test_con01_qualification.QualificationMetadata) (entries=21)
AssertionError: "complete control revision inventory" does not match "new qualification output required"
Ran 1 test in 0.012s
FAILED (failures=2)
```

## complete-worker-inventory

Exit 1; SHA-256 `7cefccd0f8876d9d52387be32d4848b7d38cfdf59b72c80a66196096b0bd74fa`.

```text
FAIL: test_incomplete_replay_inventory_cannot_qualify (test_con01_qualification.QualificationMetadata) (entries=0)
AssertionError: Refused not raised
FAIL: test_incomplete_replay_inventory_cannot_qualify (test_con01_qualification.QualificationMetadata) (entries=5)
AssertionError: "complete worker revision inventory" does not match "new qualification output required"
Ran 1 test in 0.014s
FAILED (failures=2)
```

## unique-guard-identities

Exit 1; SHA-256 `fcc35f282397dcabe68362d822179063ac7b128b54a737d19a8cad6910da69c0`.

```text
FAIL: test_duplicate_guard_identities_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.011s
FAILED (failures=1)
```

## frozen-input-identities

Exit 1; SHA-256 `fcde22a26379e697fcf8a0047d4f6d122b220f52c4966139ddf04e7bcdb5082d`.

```text
FAIL: test_changed_frozen_inputs_cannot_qualify (test_con01_qualification.QualificationMetadata) (input='APPROVED-CONFIG.json')
AssertionError: Refused not raised
FAIL: test_changed_frozen_inputs_cannot_qualify (test_con01_qualification.QualificationMetadata) (input='REPLAY-CONFIG.json')
AssertionError: "frozen replay input identity" does not match "new qualification output required"
FAIL: test_changed_frozen_inputs_cannot_qualify (test_con01_qualification.QualificationMetadata) (input='SNAPSHOT.json')
AssertionError: "frozen replay input identity" does not match "new qualification output required"
FAIL: test_changed_frozen_inputs_cannot_qualify (test_con01_qualification.QualificationMetadata) (input='SEALS.jsonl')
AssertionError: "frozen replay input identity" does not match "new qualification output required"
Ran 1 test in 0.019s
FAILED (failures=4)
```

## legacy-worker-alias

Exit 1; SHA-256 `a0eb71f2120bd68649bfffe4c54223c3a45b17a2c9dd5f3889136efad22013f3`.

```text
FAIL: test_historical_worker_name_is_exact_byte_alias (test_con01_qualification.QualificationMetadata)
AssertionError: exact historical worker alias refused: complete worker revision inventory required
Ran 1 test in 0.010s
FAILED (failures=1)
```

## launch-approved-config

Exit 1; SHA-256 `b3973839a38e364c8ef97d6ca436f3c7ac1254b6cebc79f1d67092fc2e6085ac`.

```text
FAIL: test_changed_approved_config_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.008s
FAILED (failures=1)
```

## launch-frozen-inputs

Exit 1; SHA-256 `3c47cf9f6c72054009a7ae42d53d3eaae6e06f499d12d108a3d43adc798a39b4`.

```text
FAIL: test_changed_frozen_input_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.007s
FAILED (failures=1)
```

## launch-verifier

Exit 1; SHA-256 `be79a8b8eed3cc3961a5592810537b548364fc6b5a19efc8679003fb353930da`.

```text
FAIL: test_changed_verifier_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.004s
FAILED (failures=1)
```

## launch-source

Exit 1; SHA-256 `47b943898dfaea5bc110e5edfc5f33a8fe5266d785d0bd6d75d871b374106751`.

```text
FAIL: test_changed_source_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.004s
FAILED (failures=1)
```

## launch-input-inventory

Exit 1; SHA-256 `3d66fda9092f732a85383239cbcf757c903dc5503316b6ad7335346555a0b03b`.

```text
FAIL: test_incomplete_input_inventory_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.004s
FAILED (failures=1)
```

## launch-worker-inventory

Exit 1; SHA-256 `716f6a3356555980ce5ad42c160d1fed44fac6f15251239b7326542c4d647f93`.

```text
FAIL: test_incomplete_worker_inventory_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.004s
FAILED (failures=1)
```

## launch-worker-revision

Exit 1; SHA-256 `c7cf68479fb14ea5a66d94b89d4814680e69c8eb4cb9731d8a501cc5b0fb887f`.

```text
FAIL: test_changed_worker_revision_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.006s
FAILED (failures=1)
```

## launch-legacy-worker-alias

Exit 1; SHA-256 `bf0f5f36b34a60171605d421f316fbeba41b6a415f25e87e942bfb9ff7fd37cb`.

```text
FAIL: test_historical_worker_name_resumes_exact_same_bytes (test_con01_launch.LaunchMetadata)
AssertionError: exact historical worker alias refused before resume: complete worker revision inventory required
Ran 1 test in 0.003s
FAILED (failures=1)
```
