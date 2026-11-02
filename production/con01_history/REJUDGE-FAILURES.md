# Rejudge sensitivity receipts

Baseline/restored54tests PASS;32 guard removals fail in intended runtime test bodies. Real certificates use retained public data and the pinned verifier. Judge/qualification/launch fixtures are explicitly synthetic metadata, not live cryptographic evidence. Raw receipts retained through2027-02-01UTC via existing authorized toserver SSH. The JSON index pins source/runner/fixture hashes, raw sizes/digests.

## source-key-file-binding

Exit 1; SHA-256 `6a45c7a1da3b9d893339df08e2320c0e805c39893e4f7ddbb0d1d2c40e57e57b`.

```text
FAIL: test_cached_key_file_hash_is_bound_before_verification (test_con01_observer_crypto.ObserverCrypto)
AssertionError: True is not false : {'t': 'blk', 'src': 'node1', 'seq': 264347, 'utc': 1793404801.1, 'mode': None, 'ok': True, 'rid': ['jKuDpY+l/44DBpzm1JSHkptDBQJJ1Ux3KJK75kOb05c=', 'L8189znCk959aKJOBKKY21C8+ZjZn3AhSX9BGh2Vt34='], 'prevkey': 246589, 'gu_claim': 1793404801, 'key_claim': False, 'path': 'forward', 'cid': ['jKuDpY+l/44DBpzm1JSHkptDBQJJ1Ux3KJK75kOb05c=', 'L8189znCk959aKJOBKKY21C8+ZjZn3AhSX9BGh2Vt34='], 'parent': ['fPm39q4XcZorbKHVIIom4TrOlnaRlZZyy7uIu6UsNeo=', 'AtPwcPsYY34THc56PIOrbXusiLDzvJQYVKNmSs7aGeA='], 'parent_seq': 264346, 'gu': 1793404801, 'key': False, 'cc': 451, 'signers': 3, 'w': 864691128455135232, 'tw': 1152921504606
Ran 1 test in 0.108s
FAILED (failures=1)
```

## expired-term-regression

Exit 1; SHA-256 `6d78ca1bc646b8736d6858128556460aa92644f441102d3a87303a528e6d6a16`.

```text
FAIL: test_expired_schedule_passes_full_observer (test_con01_observer_crypto.ObserverCrypto)
AssertionError: False is not true : {'t': 'blk', 'src': 'node1', 'seq': 264347, 'utc': 1793404801.1, 'mode': None, 'ok': False, 'rid': ['jKuDpY+l/44DBpzm1JSHkptDBQJJ1Ux3KJK75kOb05c=', 'L8189znCk959aKJOBKKY21C8+ZjZn3AhSX9BGh2Vt34='], 'prevkey': 246589, 'gu_claim': 1793404801, 'key_claim': False, 'path': 'forward', 'reason': 'term outside validity interval'}
Ran 1 test in 0.046s
FAILED (failures=1)
```

## rejected

Exit 1; SHA-256 `544af35ef4bd9d8f9f33296e9da7f2aed92dcd6de61f31fe8ab947dc79afee7d`.

```text
FAIL: test_rejection_is_not_overwritten_by_later_success (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [{'src': 'node1', 'seq': 1, 'reason': 'invalid signature'}], 'rejected_count': 1, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, '
Ran 1 test in 0.002s
FAILED (failures=1)
```

## stream-integrity

Exit 1; SHA-256 `74240e36db72f64da0225ac8a7cf3f71980dd611448ae337ac5185efa13528d0`.

```text
FAIL: test_integrity_break (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [{'t': 'chain', 'src': 'node1', 'ok': False}], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}],
Ran 1 test in 0.002s
FAILED (failures=1)
```

## uncertified-key

Exit 1; SHA-256 `d6b716ef08977c2d80141988891e080471d758a2a767092c633c00202436a9ea`.

```text
FAIL: test_uncertified_source_key_cannot_enter_trust_chain (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified':
Ran 1 test in 0.002s
FAILED (failures=1)
```

## third-boundary-certificate

Exit 1; SHA-256 `0ee75ed7554f0c8be2c996eea29a9af8644f26a2e7bbf9a730a9a87f21d1668a`.

```text
FAIL: test_boundary_requires_three_certificates (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [{'src': 'node5', 'seq': 4}], 'unsupported_count': 1, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo'
Ran 1 test in 0.002s
FAILED (failures=1)
```

## two-window-certificates

Exit 1; SHA-256 `3cd23be879e441ff554c0dce28af100a0cbe8d143e489b989f83304a0f9290c5`.

```text
FAIL: test_window_requires_two_sources (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.8, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [{'src': 'node3', 'seq': 2}, {'src': 'node5', 'seq': 2}], 'unsupported_count': 2, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'bloc
Ran 1 test in 0.002s
FAILED (failures=1)
```

## three-full-ids

Exit 1; SHA-256 `0d38a99b74ed5af37793c7ec81ed2f0a730ff30cc0c5502f200ef643e26b1851`.

```text
FAIL: test_full_ids_require_three_sources (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified':
Ran 1 test in 0.002s
FAILED (failures=1)
```

## shard-inclusion

Exit 1; SHA-256 `686e2843a653f63fc8d7b37da3740ff7bbbf335ff77f40a33fc458e35eb62c41`.

```text
FAIL: test_shard_inclusion_requires_two_sources (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified':
Ran 1 test in 0.002s
FAILED (failures=1)
```

## live-observation

Exit 1; SHA-256 `10b7391f29632e2dc82e8d90bfe7018290e6c6ca25078f3fd3af67b3c22ae370`.

```text
FAIL: test_missing_live_heads (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified':
Ran 1 test in 0.002s
FAILED (failures=1)
```

## outgoing-boundary-set

Exit 1; SHA-256 `8279af95e4d1c842eb89acb23d3831417cba129a75f1f77024d29ba64efdd1bb`.

```text
FAIL: test_outgoing_boundary_set_must_match (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified':
Ran 1 test in 0.002s
FAILED (failures=1)
```

## incoming-next-set

Exit 1; SHA-256 `9d3b5fc20e049232599051b7325beb3ec8b1a595db5f7109158f1b1992976f02`.

```text
FAIL: test_incoming_set_must_certify_following_block (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified':
Ran 1 test in 0.002s
FAILED (failures=1)
```

## incomplete-replay

Exit 1; SHA-256 `1ca1d2a0891e03d2c294a685c6ba9f978e9d8df9c69d73e083071dd4fb69a029`.

```text
FAIL: test_incomplete_replay_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.012s
FAILED (failures=1)
```

## replay-revision

Exit 1; SHA-256 `ad9577009301286f55a32d2dcf7c1f8fdc1c7537068f7564cf2563f0bcaa81dc`.

```text
FAIL: test_changed_source_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.012s
FAILED (failures=1)
```

## control-revision

Exit 1; SHA-256 `00aceb4ff9f5c25bf3ebf0fed3ebcb70d8ddc2184b54a82f9c549aa69b7c2cb7`.

```text
FAIL: test_changed_control_revision_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.012s
FAILED (failures=1)
```

## all-controls-required

Exit 1; SHA-256 `9f53f028dc2d901af17a61e7911cb42672ae2b74bb5835e91260cc100995f3d5`.

```text
FAIL: test_missing_controls_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: "complete guard controls" does not match "exact unique guard identities required"
Ran 1 test in 0.007s
FAILED (failures=1)
```

## snapshot-size

Exit 1; SHA-256 `488a0f3a2611852957468e7deeaae44f770da15a1f0ec4c677055435becc1b00`.

```text
FAIL: test_frozen_size_change_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.012s
FAILED (failures=1)
```

## three-source-inventory

Exit 1; SHA-256 `838ecb5b2f67e15b11f0caeb6b7a1048ddb07c48e1347d7fc6097d5a495bbc71`.

```text
FAIL: test_missing_third_source_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: "three frozen original source" does not match "frozen replay input identity changed"
Ran 1 test in 0.011s
FAILED (failures=1)
```

## complete-control-inventory

Exit 1; SHA-256 `44e5bb1bc87030acad8fc947675f12f885c488b8ede1552c3f80880d551d0a0d`.

```text
FAIL: test_incomplete_control_inventory_cannot_qualify (test_con01_qualification.QualificationMetadata) (entries=0)
AssertionError: Refused not raised
FAIL: test_incomplete_control_inventory_cannot_qualify (test_con01_qualification.QualificationMetadata) (entries=21)
AssertionError: "complete control revision inventory" does not match "new qualification output required"
Ran 1 test in 0.012s
FAILED (failures=2)
```

## complete-worker-inventory

Exit 1; SHA-256 `d6fffa5e1728507055be885dab648100cea60ec3803cd6428c7248533646772b`.

```text
FAIL: test_incomplete_replay_inventory_cannot_qualify (test_con01_qualification.QualificationMetadata) (entries=0)
AssertionError: Refused not raised
FAIL: test_incomplete_replay_inventory_cannot_qualify (test_con01_qualification.QualificationMetadata) (entries=5)
AssertionError: "complete worker revision inventory" does not match "new qualification output required"
Ran 1 test in 0.014s
FAILED (failures=2)
```

## unique-guard-identities

Exit 1; SHA-256 `c1c87715fa3a859cc318ab72d058a20a615432399db930e29e9eaf8773570157`.

```text
FAIL: test_duplicate_guard_identities_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.012s
FAILED (failures=1)
```

## frozen-input-identities

Exit 1; SHA-256 `2b3b08db31c87b275e22649fe9b32ef5a2f286afa15544d651070ff1723344ab`.

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

Exit 1; SHA-256 `7a8e49ed27d066e0c7d1ea8369d827497f40de025a4ef6c3b06b1e282613e710`.

```text
FAIL: test_historical_worker_name_is_exact_byte_alias (test_con01_qualification.QualificationMetadata)
AssertionError: exact historical worker alias refused: complete worker revision inventory required
Ran 1 test in 0.010s
FAILED (failures=1)
```

## launch-approved-config

Exit 1; SHA-256 `c405afddaa8d8672165434b85ea05a75cf20a6e0cd3569fb7d2ab9bb9706435a`.

```text
FAIL: test_changed_approved_config_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.008s
FAILED (failures=1)
```

## launch-frozen-inputs

Exit 1; SHA-256 `e373cc36457bde34fcaa62e2b83dfd4d3cf8b3f2a0efd8521325ae2ed3016f62`.

```text
FAIL: test_changed_frozen_input_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: "frozen input changed" does not match "resume config representation changed before worker invocation"
Ran 1 test in 0.008s
FAILED (failures=1)
```

## launch-verifier

Exit 1; SHA-256 `e5b753cbe8037bbc26a8802a4300b017db13cd68ec23d578c1adb9639d73c768`.

```text
FAIL: test_changed_verifier_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.008s
FAILED (failures=1)
```

## launch-source

Exit 1; SHA-256 `6e579abc0fa50e207a813a9dc2d9a9fdc98ee5b959da1a03c3aad9ce65eeb3c8`.

```text
FAIL: test_changed_source_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.007s
FAILED (failures=1)
```

## launch-input-inventory

Exit 1; SHA-256 `e7d6093b60443f7eddb2819e3097ea6f24283676a58571521ee244c39847ebfa`.

```text
FAIL: test_incomplete_input_inventory_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.008s
FAILED (failures=1)
```

## launch-worker-inventory

Exit 1; SHA-256 `29f8b6cfff8a51d473989e7d1d9b0fa0980f89ab7d42c67280490815082ff26f`.

```text
FAIL: test_incomplete_worker_inventory_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.008s
FAILED (failures=1)
```

## launch-worker-revision

Exit 1; SHA-256 `e3fd4f051aefc5a228e1457848e93134cab939dd8e77228f750302d0da14dddd`.

```text
FAIL: test_changed_worker_revision_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.007s
FAILED (failures=1)
```

## launch-legacy-worker-alias

Exit 1; SHA-256 `a9fafe5fd965cdedc77c7f94a9bda5b1f871ea33ee320158f3ad1906739b9f25`.

```text
FAIL: test_historical_worker_name_resumes_exact_same_bytes (test_con01_launch.LaunchMetadata)
AssertionError: exact historical worker alias refused before resume: complete worker revision inventory required
Ran 1 test in 0.007s
FAILED (failures=1)
```

## launch-worker-config-bytes

Exit 1; SHA-256 `88752ec2b5a91fb96b9b11e2de70930998cf3d837fe003140d7aa81740c2252c`.

```text
FAIL: test_relative_output_alias_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.008s
FAILED (failures=1)
```
