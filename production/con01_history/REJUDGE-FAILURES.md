# Rejudge sensitivity receipts

Baseline/restored57tests PASS;36 guard removals fail in intended runtime test bodies. Real certificates use retained public data and the pinned verifier. Judge/qualification/launch fixtures are explicit synthetic metadata. Raw receipts retained through2027-02-01UTC via existing authorized toserver SSH; JSON index pins source/runner/fixture hashes, raw sizes/digests.

## source-key-file-binding

Exit 1; SHA-256 `84b2caa0f202c0b6d1b3df86adf17ebfde0a00b84e5a568624dcbd1f8c8b3bda`.

```text
FAIL: test_cached_key_file_hash_is_bound_before_verification (test_con01_observer_crypto.ObserverCrypto)
AssertionError: True is not false : {'t': 'blk', 'src': 'node1', 'seq': 264347, 'utc': 1793404801.1, 'mode': None, 'ok': True, 'rid': ['jKuDpY+l/44DBpzm1JSHkptDBQJJ1Ux3KJK75kOb05c=', 'L8189znCk959aKJOBKKY21C8+ZjZn3AhSX9BGh2Vt34='], 'prevkey': 246589, 'gu_claim': 1793404801, 'key_claim': False, 'path': 'forward', 'cid': ['jKuDpY+l/44DBpzm1JSHkptDBQJJ1Ux3KJK75kOb05c=', 'L8189znCk959aKJOBKKY21C8+ZjZn3AhSX9BGh2Vt34='], 'parent': ['fPm39q4XcZorbKHVIIom4TrOlnaRlZZyy7uIu6UsNeo=', 'AtPwcPsYY34THc56PIOrbXusiLDzvJQYVKNmSs7aGeA='], 'parent_seq': 264346, 'gu': 1793404801, 'key': False, 'cc': 451, 'signers': 3, 'w': 864691128455135232, 'tw': 1152921504606
Ran 1 test in 0.084s
FAILED (failures=1)
```

## expired-term-regression

Exit 1; SHA-256 `1b0b6442048df9c2cd9f421933b0fcf56935637e5f7b2b480b718d8f6d8cdffb`.

```text
FAIL: test_expired_schedule_passes_full_observer (test_con01_observer_crypto.ObserverCrypto)
AssertionError: False is not true : {'t': 'blk', 'src': 'node1', 'seq': 264347, 'utc': 1793404801.1, 'mode': None, 'ok': False, 'rid': ['jKuDpY+l/44DBpzm1JSHkptDBQJJ1Ux3KJK75kOb05c=', 'L8189znCk959aKJOBKKY21C8+ZjZn3AhSX9BGh2Vt34='], 'prevkey': 246589, 'gu_claim': 1793404801, 'key_claim': False, 'path': 'forward', 'reason': 'term outside validity interval'}
Ran 1 test in 0.041s
FAILED (failures=1)
```

## rejected

Exit 1; SHA-256 `0c43f8c81aba3035d375d967b7ff2b2a3a3c5de955c597a64ebf091cf7ecba29`.

```text
FAIL: test_rejection_is_not_overwritten_by_later_success (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [{'src': 'node1', 'seq': 1, 'reason': 'invalid signature'}], 'rejected_count': 1, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, '
Ran 1 test in 0.002s
FAILED (failures=1)
```

## stream-integrity

Exit 1; SHA-256 `4c39f37b995215df31bb454dcb93f23d60d7518041e10eff33dd4f218bec4b08`.

```text
FAIL: test_integrity_break (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [{'t': 'chain', 'src': 'node1', 'ok': False}], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}],
Ran 1 test in 0.002s
FAILED (failures=1)
```

## uncertified-key

Exit 1; SHA-256 `63ad62692739c29acad43e625638c004e84861c97779e6c88fa0300c7d49baa0`.

```text
FAIL: test_uncertified_source_key_cannot_enter_trust_chain (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified':
Ran 1 test in 0.002s
FAILED (failures=1)
```

## third-boundary-certificate

Exit 1; SHA-256 `ebc598460b28d5dbdc4bf642b7d2d409750cc1100acb500315412b8256221676`.

```text
FAIL: test_boundary_requires_three_certificates (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [{'src': 'node5', 'seq': 4}], 'unsupported_count': 1, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo'
Ran 1 test in 0.002s
FAILED (failures=1)
```

## two-window-certificates

Exit 1; SHA-256 `0ae0784f07447e981a0e977a2d30907597c0cfedebfeb7d4d29392ce41b3bc18`.

```text
FAIL: test_window_requires_two_sources (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.8, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [{'src': 'node3', 'seq': 2}, {'src': 'node5', 'seq': 2}], 'unsupported_count': 2, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'bloc
Ran 1 test in 0.002s
FAILED (failures=1)
```

## three-full-ids

Exit 1; SHA-256 `3d90a790bb3bf7ec32b1c535dfbb73b1d07aba09ff032eb038af069471eca61f`.

```text
FAIL: test_full_ids_require_three_sources (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified':
Ran 1 test in 0.001s
FAILED (failures=1)
```

## shard-inclusion

Exit 1; SHA-256 `7a7cf9380881aa9d6de46a8ebe7f7399d01ca17802d57a7603f898658b415d62`.

```text
FAIL: test_shard_inclusion_requires_two_sources (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified':
Ran 1 test in 0.002s
FAILED (failures=1)
```

## live-observation

Exit 1; SHA-256 `adc5e76b24be6521d82ee84de3efd5ad72f88ea357fba27288460747822d31d4`.

```text
FAIL: test_missing_live_heads (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified':
Ran 1 test in 0.002s
FAILED (failures=1)
```

## outgoing-boundary-set

Exit 1; SHA-256 `73de772c880b1831f30653837d81ec53a314832445af26e2570590c1aef5b2db`.

```text
FAIL: test_outgoing_boundary_set_must_match (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified':
Ran 1 test in 0.002s
FAILED (failures=1)
```

## incoming-next-set

Exit 1; SHA-256 `ba28e499fa81d40c5c9fbf6e963bf4ada964b3a235d76ca9821e59994c2eefc6`.

```text
FAIL: test_incoming_set_must_certify_following_block (test_con01_rejudge.JudgeControls)
AssertionError: 'PASS' == 'PASS' : {'bounds': {'window_s': 1, 'max_block_gap_s': 10, 'min_rate_bps': 1.5, 'live_lag_s': 30, 'min_live_fraction': 0.99, 'max_head_record_gap_s': 30, 'max_head_staleness_s': 15, 'min_sources_cert': 2, 'all_sources': 3, 'min_handovers': 1}, 'sources': ['node1', 'node3', 'node5'], 'fail': [], 'inconclusive': [], 'notes': [], 'self_conflicts': [], 'unsupported_shape': [], 'unsupported_count': 0, 'integrity': {'breaks': [], 'torn': []}, 'rejected': [], 'rejected_count': 0, 'conflicts': [], 'parent_breaks': [], 'continuously_verified_runs': [{'lo': 1, 'hi': 8, 'blocks': 8}], 'coverage': {'lo': 1, 'hi': 8, 'certified':
Ran 1 test in 0.002s
FAILED (failures=1)
```

## incomplete-replay

Exit 1; SHA-256 `16958b54c6086bc2f3bd8c098ac1fec3390b8ef72b861a4e77c9592b0d1e1344`.

```text
FAIL: test_incomplete_replay_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.011s
FAILED (failures=1)
```

## replay-revision

Exit 1; SHA-256 `a68fedb1b858cfdfb094742c9e89dfb32f727e30d036194d96ab4eac30c2e605`.

```text
FAIL: test_changed_source_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.011s
FAILED (failures=1)
```

## control-revision

Exit 1; SHA-256 `949524b02f7de1cbcd63afeb1afb2df0ec56819a2e829e961f53684a4defd63a`.

```text
FAIL: test_changed_control_revision_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.010s
FAILED (failures=1)
```

## all-controls-required

Exit 1; SHA-256 `55f2a017b63a7cf1c0052ca7f5eb5eed1410cbce596d5adc50be625208f8601c`.

```text
FAIL: test_missing_controls_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: "complete guard controls" does not match "exact unique guard identities required"
Ran 1 test in 0.006s
FAILED (failures=1)
```

## snapshot-size

Exit 1; SHA-256 `bd5be30e20d5de159f703e90cde0732f2d4d1cd82de13f1f996f50e4f11f2282`.

```text
FAIL: test_frozen_size_change_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: "frozen segment size changed" does not match "frozen segment digest changed"
Ran 1 test in 0.010s
FAILED (failures=1)
```

## three-source-inventory

Exit 1; SHA-256 `f903c7be52599a5cf717e6e7d6128bb3c9d69c417c1e9cf00f9370dcdbbaca21`.

```text
FAIL: test_missing_third_source_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: "three frozen original source" does not match "frozen replay input identity changed"
Ran 1 test in 0.010s
FAILED (failures=1)
```

## complete-control-inventory

Exit 1; SHA-256 `7fe090032f867dc7e4946bfed77a8c1509c6e260809a8c1be6acf7811bd45aa7`.

```text
FAIL: test_incomplete_control_inventory_cannot_qualify (test_con01_qualification.QualificationMetadata) (entries=0)
AssertionError: Refused not raised
FAIL: test_incomplete_control_inventory_cannot_qualify (test_con01_qualification.QualificationMetadata) (entries=22)
AssertionError: "complete control revision inventory" does not match "new qualification output required"
Ran 1 test in 0.011s
FAILED (failures=2)
```

## complete-worker-inventory

Exit 1; SHA-256 `94b09525ee9170b57d95ef81a84a6d7078f96ed39d5c1ece795bee4f208007f4`.

```text
FAIL: test_incomplete_replay_inventory_cannot_qualify (test_con01_qualification.QualificationMetadata) (entries=0)
AssertionError: Refused not raised
FAIL: test_incomplete_replay_inventory_cannot_qualify (test_con01_qualification.QualificationMetadata) (entries=5)
AssertionError: "complete worker revision inventory" does not match "new qualification output required"
Ran 1 test in 0.013s
FAILED (failures=2)
```

## unique-guard-identities

Exit 1; SHA-256 `2bb3189049a6cd97cce44b03278b8bbcb413b43c83afc4bdcbcf2534a24519df`.

```text
FAIL: test_duplicate_guard_identities_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.011s
FAILED (failures=1)
```

## frozen-input-identities

Exit 1; SHA-256 `c060ed32206f0985b4cf219a9887fe19a4c74f532b84c82beb1b034498b9ff87`.

```text
FAIL: test_changed_frozen_inputs_cannot_qualify (test_con01_qualification.QualificationMetadata) (input='APPROVED-CONFIG.json')
AssertionError: Refused not raised
FAIL: test_changed_frozen_inputs_cannot_qualify (test_con01_qualification.QualificationMetadata) (input='REPLAY-CONFIG.json')
AssertionError: "frozen replay input identity" does not match "new qualification output required"
FAIL: test_changed_frozen_inputs_cannot_qualify (test_con01_qualification.QualificationMetadata) (input='SNAPSHOT.json')
AssertionError: "frozen replay input identity" does not match "new qualification output required"
FAIL: test_changed_frozen_inputs_cannot_qualify (test_con01_qualification.QualificationMetadata) (input='SEALS.jsonl')
AssertionError: "frozen replay input identity" does not match "new qualification output required"
Ran 1 test in 0.017s
FAILED (failures=4)
```

## legacy-worker-alias

Exit 1; SHA-256 `e27c357e89118f0559cc9981e2ebdc6a78d8612b18140edb59ef203c89c68e83`.

```text
FAIL: test_historical_worker_name_is_exact_byte_alias (test_con01_qualification.QualificationMetadata)
AssertionError: exact historical worker alias refused: complete worker revision inventory required
Ran 1 test in 0.010s
FAILED (failures=1)
```

## frozen-segment-content

Exit 1; SHA-256 `bda8d1ed177a87533f6a88bb10cbb36eeaf9f99f3948250d0b954a9b000bc6b3`.

```text
FAIL: test_same_length_frozen_segment_change_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.011s
FAILED (failures=1)
```

## launch-approved-config

Exit 1; SHA-256 `ea2924f7d1ff3c4c5ce73c688b721d5637f4bfe20bd04ac6da44be915f88198c`.

```text
FAIL: test_changed_approved_config_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.008s
FAILED (failures=1)
```

## launch-frozen-inputs

Exit 1; SHA-256 `ce92eeed64b26cd18987e0d1425276330e5efcd3bad58084706f992208273c05`.

```text
FAIL: test_changed_frozen_input_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: "frozen input changed" does not match "resume config representation changed before worker invocation"
Ran 1 test in 0.008s
FAILED (failures=1)
```

## launch-verifier

Exit 1; SHA-256 `a97bee7daeafef6f15505a15571f7c49a40b55e8ada60a10e966d426bedfa838`.

```text
FAIL: test_changed_verifier_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.008s
FAILED (failures=1)
```

## launch-source

Exit 1; SHA-256 `64c0548839652f3105d47c8f81486e8c19888444fd0f5622d0aad38fc3693563`.

```text
FAIL: test_changed_source_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.008s
FAILED (failures=1)
```

## launch-input-inventory

Exit 1; SHA-256 `20cb1c2c32dfdc456057352ab5cfd6211b1ac6de972e1fa6d4f3f5bf800ea573`.

```text
FAIL: test_incomplete_input_inventory_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.008s
FAILED (failures=1)
```

## launch-worker-inventory

Exit 1; SHA-256 `035150c5b274e3cc4502eba3033d790d7bed958d3a3970b186fb5efe0fdd8001`.

```text
FAIL: test_incomplete_worker_inventory_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.008s
FAILED (failures=1)
```

## launch-worker-revision

Exit 1; SHA-256 `085f7186d9eb36112f704da6fe3d8be8fe105195fb50389f9cc70119081558f2`.

```text
FAIL: test_changed_worker_revision_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.008s
FAILED (failures=1)
```

## launch-legacy-worker-alias

Exit 1; SHA-256 `ff003e4109921ed4770bd8274a3ec6d508ce2c33fbf00649f29d5bba65617ebe`.

```text
FAIL: test_historical_worker_name_resumes_exact_same_bytes (test_con01_launch.LaunchMetadata)
AssertionError: exact historical worker alias refused before resume: complete worker revision inventory required
Ran 1 test in 0.008s
FAILED (failures=1)
```

## launch-worker-config-bytes

Exit 1; SHA-256 `4d63500fe9565808bccbf8ff79a9caa08c3b068961d3a58e5fb904c980a21876`.

```text
FAIL: test_relative_output_alias_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.008s
FAILED (failures=1)
```

## launch-frozen-segment-content

Exit 1; SHA-256 `ddc3bb72b746234fed6793fbb523e266177aa805c8a6022eaab5ada29f14ba0e`.

```text
FAIL: test_same_length_frozen_segment_change_refuses_before_worker (test_con01_launch.LaunchMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.008s
FAILED (failures=1)
```

## launch-segment-manifest-pin

Exit 1; SHA-256 `8ce4e7c5e3ca4406bead654e0c22c89952c374f9fb599d267201fd0ffbe33bfc`.

```text
FAIL: test_unchanged_frozen_inputs_resume (test_con01_launch.LaunchMetadata)
AssertionError: 'SEGMENT-HASHES.json' not found in {'APPROVED-CONFIG.json': '1b352558dddaa58a7d5f5788e96fc7dd2ad587283187cf93dc94345692582656', 'SNAPSHOT.json': '874ab4b9ab1fb67273ca30d0293e2148f9268503e03f95bb45d9ab190529607c', 'REPLAY-CONFIG.json': '8f7a4b5d77b956c7d05633100ec69c297d1c39ac4984f5c944d1c5bc4d005275', 'SEALS.jsonl': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
Ran 1 test in 0.006s
FAILED (failures=1)
```

## complete-segment-digests

Exit 1; SHA-256 `a4c693de5c6fa4caabff9294bbc715162fc25c99bfec8c9f888d5710812ee260`.

```text
FAIL: test_extra_segment_digest_cannot_qualify (test_con01_qualification.QualificationMetadata)
AssertionError: Refused not raised
Ran 1 test in 0.011s
FAILED (failures=1)
```
