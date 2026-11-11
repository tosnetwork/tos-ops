# Executed regression evidence

The 14 real-crypto tests passed. Each matching guard-removal control below failed in the test body, not setup. Public fixture hashes are in `MANIFEST.json`. The durable runner is `testnet/tests/con01_history_controls.py`; no network is used by the controls.

Raw receipts remain on the authorized test host through at least 2027-02-01. The receipt digests below identify unsanitized bounded failure excerpts; access uses the existing authorized host account. No missing historical observations are reconstructed by these tests.

## real_expired_schedule_certificate_has_valid_finality

Mutation detected, exit 1; raw excerpt SHA-256 `456ba6ab349f6507903518c79eaaaed49dc50fcfb8257b4dfda8c09878804b77`.

```text
ERROR: test_real_expired_schedule_certificate_has_valid_finality (__main__.Certificates)
con01_history.certificate.Refused: term outside validity interval
Ran 1 test in 0.034s
FAILED (errors=1)
```

## corrupted_real_signature_is_rejected

Mutation detected, exit 1; raw excerpt SHA-256 `0f00ff2df41398c5af5767bf215a11952c9ff3f9bd5148916dee1ae61393995f`.

```text
FAIL: test_corrupted_real_signature_is_rejected (__main__.Certificates)
AssertionError: Refused not raised
Ran 1 test in 0.019s
FAILED (failures=1)
```

## quorum_is_not_inferred_from_validator_membership

Mutation detected, exit 1; raw excerpt SHA-256 `037b916a0037f5634790fc6eb783f57852735e2d20f1d2c3a0b4fd0a324ea003`.

```text
FAIL: test_quorum_is_not_inferred_from_validator_membership (__main__.Certificates)
AssertionError: Refused not raised
Ran 1 test in 0.028s
FAILED (failures=1)
```

## duplicate_signer_cannot_increase_weight

Mutation detected, exit 1; raw excerpt SHA-256 `e518b94c7e21beca1eb2496e100024ee1bac6e22f69834cd5913d97a113474fb`.

```text
FAIL: test_duplicate_signer_cannot_increase_weight (__main__.Certificates)
AssertionError: Refused not raised
Ran 1 test in 0.047s
FAILED (failures=1)
```

## unknown_algorithm_is_not_accepted_as_mldsa

Mutation detected, exit 1; raw excerpt SHA-256 `c40512dc5a8a1397dc273cc2c498fdac740c59154662e69ac654c054d68f5421`.

```text
FAIL: test_unknown_algorithm_is_not_accepted_as_mldsa (__main__.Certificates)
AssertionError: Refused not raised
Ran 1 test in 0.044s
FAILED (failures=1)
```

## wrong_session_is_rejected_before_signature_backend

Mutation detected, exit 1; raw excerpt SHA-256 `7ed5e8b7c7c123edc9875f88a8b7cd2ebbcb2a89ff21eb11c6a7514d1a7c66c5`.

```text
FAIL: test_wrong_session_is_rejected_before_signature_backend (__main__.Certificates)
con01_history.certificate.Refused: ML-DSA-44 verification rejected
AssertionError: "session identity mismatch" does not match "ML-DSA-44 verification rejected"
Ran 1 test in 0.027s
FAILED (failures=1)
```

## source_root_must_match_authenticated_config

Mutation detected, exit 1; raw excerpt SHA-256 `8647d76f05eb2321fc18fbb657d4cd16eab87cf4bb7925c494369e71834a58c2`.

```text
FAIL: test_source_root_must_match_authenticated_config (__main__.Certificates)
AssertionError: Refused not raised
Ran 1 test in 0.043s
FAILED (failures=1)
```

## trusted_full_anchor_includes_file_hash

Mutation detected, exit 1; raw excerpt SHA-256 `a26f06e84e47fc510d5552880d78bbeec2ad709dbc866c1e73de064a0f2ace21`.

```text
FAIL: test_trusted_full_anchor_includes_file_hash (__main__.Certificates)
AssertionError: Refused not raised
Ran 1 test in 0.043s
FAILED (failures=1)
```

## retired_key_is_not_selected_after_authenticated_rollover

Mutation detected, exit 1; raw excerpt SHA-256 `0b2cecf7b555709837172c09f6eb175031d4b1bd9a9cd1ab16cbce056ac46a5d`.

```text
FAIL: test_retired_key_is_not_selected_after_authenticated_rollover (__main__.Certificates)
AssertionError: Refused not raised
Ran 1 test in 0.037s
FAILED (failures=1)
```

## real_partial_genesis_packet_is_not_a_complete_target_proof

Mutation detected, exit 1; raw excerpt SHA-256 `cd02fbdf7dc238b1538b51e817673a9bacfbe8f95bab3793dd7741d779f104d3`.

```text
FAIL: test_real_partial_genesis_packet_is_not_a_complete_target_proof (__main__.Certificates)
AssertionError: Refused not raised
Ran 1 test in 0.823s
FAILED (failures=1)
```

## packet_byte_limit_precedes_decoder

Mutation detected, exit 1; raw excerpt SHA-256 `b81072fc304a37f172f1c5165c829021ea4241259996accb064bf0e51ee39f68`.

```text
FAIL: test_packet_byte_limit_precedes_decoder (__main__.Certificates)
Ran 1 test in 0.017s
FAILED (failures=1)
```

## oversized_cell_count_precedes_boc_allocation

Mutation detected, exit 1; raw excerpt SHA-256 `0f4315e3cddafab0684688175963efe29db679692fdfe60741e9107e7479bb09`.

```text
FAIL: test_oversized_cell_count_precedes_boc_allocation (__main__.Certificates)
AssertionError: truncated TL
AssertionError: "cell/root bound" does not match "truncated TL"
Ran 1 test in 0.015s
FAILED (failures=1)
```

## optimized_python_refuses_assert_based_wire_decoder

Mutation detected, exit 1; raw excerpt SHA-256 `cf32f20489f06cccd62828940c2c90ba680769b36b030549cd94941b2c347621`.

```text
FAIL: test_optimized_python_refuses_assert_based_wire_decoder (__main__.Certificates)
AssertionError: 0 == 0
Ran 1 test in 0.128s
FAILED (failures=1)
```

## wrong_verifier_pin_fails_before_crypto

Mutation detected, exit 1; raw excerpt SHA-256 `5b9d0a30128cae72849490ffd220ecbdeb64cd12ec5a6e19207b4f10db29bc9f`.

```text
FAIL: test_wrong_verifier_pin_fails_before_crypto (__main__.Certificates)
AssertionError: Refused not raised
Ran 1 test in 0.016s
FAILED (failures=1)
```
