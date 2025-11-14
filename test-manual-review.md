# Python Tests List

This file lists all 87 Python tests with clickable links to their locations.

| # | Test Name | File | Status | Notes |
|---|-----------|-----|--------|-------|
| 99 | `test_parse_beef_v2_varint_fd_zero_counts_ok` | [bsv/beef/test_beef_boundary_cases.py:4](tests/bsv/beef/test_beef_boundary_cases.py#L4) | ✓ |  |
| 100 | `test_verify_valid_fails_on_inconsistent_roots_in_single_bump` | [bsv/beef/test_beef_boundary_cases.py:15](tests/bsv/beef/test_beef_boundary_cases.py#L15) | ✓ |  |
| 101 | `test_merge_raw_tx_invalid_bump_index_raises` | [bsv/beef/test_beef_boundary_cases.py:44](tests/bsv/beef/test_beef_boundary_cases.py#L44) | ✓ | match |
| 102 | `test_to_binary_dedupes_txid_only_and_raw_for_same_txid` | [bsv/beef/test_beef_boundary_cases.py:59](tests/bsv/beef/test_beef_boundary_cases.py#L59) | ✓ |  |
| 103 | `test_new_beef_from_atomic_bytes_too_short_raises` | [bsv/beef/test_beef_boundary_cases.py:79](tests/bsv/beef/test_beef_boundary_cases.py#L79) | ✓ | match |
| 104 | `test_merge_txid_only_and_make_txid_only` | [bsv/beef/test_beef_builder_methods.py:4](tests/bsv/beef/test_beef_builder_methods.py#L4) | ✓ |  |
| 105 | `test_merge_transaction_sets_bump_index_when_bump_proves_txid` | [bsv/beef/test_beef_builder_methods.py:16](tests/bsv/beef/test_beef_builder_methods.py#L16) | ✓ |  |
| 106 | `test_merge_beef_merges_bumps_and_txs` | [bsv/beef/test_beef_builder_methods.py:58](tests/bsv/beef/test_beef_builder_methods.py#L58) | ✓ |  |
| 107 | `test_merge_bump_combines_same_root_objects_and_sets_bump_index` | [bsv/beef/test_beef_builder_methods.py:87](tests/bsv/beef/test_beef_builder_methods.py#L87) | ✓ |  |
| 108 | `test_from_beef_error_case` | [bsv/beef/test_beef_comprehensive.py:19](tests/bsv/beef/test_beef_comprehensive.py#L19) | ✓ | match |
| 109 | `test_new_empty_beef_v1` | [bsv/beef/test_beef_comprehensive.py:26](tests/bsv/beef/test_beef_comprehensive.py#L26) | ✓ |  |
| 110 | `test_new_empty_beef_v2` | [bsv/beef/test_beef_comprehensive.py:36](tests/bsv/beef/test_beef_comprehensive.py#L36) | ✓ |  |
| 111 | `test_beef_transaction_finding` | [bsv/beef/test_beef_comprehensive.py:46](tests/bsv/beef/test_beef_comprehensive.py#L46) | ✓ |  |
| 112 | `test_beef_sort_txs` | [bsv/beef/test_beef_comprehensive.py:67](tests/bsv/beef/test_beef_comprehensive.py#L67) | ✓ |  |
| 113 | `test_beef_to_log_string` | [bsv/beef/test_beef_comprehensive.py:111](tests/bsv/beef/test_beef_comprehensive.py#L111) | ✓ |  |
| 114 | `test_beef_clone` | [bsv/beef/test_beef_comprehensive.py:135](tests/bsv/beef/test_beef_comprehensive.py#L135) | ✓ |  |
| 115 | `test_beef_trim_known_txids` | [bsv/beef/test_beef_comprehensive.py:174](tests/bsv/beef/test_beef_comprehensive.py#L174) | ✓ | [3~p |
| 116 | `test_beef_get_valid_txids` | [bsv/beef/test_beef_comprehensive.py:212](tests/bsv/beef/test_beef_comprehensive.py#L212) | ✓ |  |
| 117 | `test_beef_find_transaction_for_signing` | [bsv/beef/test_beef_comprehensive.py:239](tests/bsv/beef/test_beef_comprehensive.py#L239) | ✓ |  |
| 118 | `test_beef_find_atomic_transaction` | [bsv/beef/test_beef_comprehensive.py:271](tests/bsv/beef/test_beef_comprehensive.py#L271) | ✓ |  |
| 119 | `test_beef_merge_bump` | [bsv/beef/test_beef_comprehensive.py:289](tests/bsv/beef/test_beef_comprehensive.py#L289) | ✓ |  |
| 120 | `test_beef_merge_transactions` | [bsv/beef/test_beef_comprehensive.py:318](tests/bsv/beef/test_beef_comprehensive.py#L318) | ✓ |  |
| 121 | `test_beef_error_handling` | [bsv/beef/test_beef_comprehensive.py:354](tests/bsv/beef/test_beef_comprehensive.py#L354) | ✓ | match |
| 122 | `test_beef_edge_cases_txid_only` | [bsv/beef/test_beef_comprehensive.py:363](tests/bsv/beef/test_beef_comprehensive.py#L363) | ✓ |  |
| 123 | `test_beef_merge_beef_bytes` | [bsv/beef/test_beef_comprehensive.py:384](tests/bsv/beef/test_beef_comprehensive.py#L384) | ✓ | match |
| 124 | `test_beef_merge_beef_tx` | [bsv/beef/test_beef_comprehensive.py:410](tests/bsv/beef/test_beef_comprehensive.py#L410) | ✓ | match |
| 125 | `test_beef_find_atomic_transaction_with_source_transactions` | [bsv/beef/test_beef_comprehensive.py:437](tests/bsv/beef/test_beef_comprehensive.py#L437) | ✓ |  |
| 126 | `test_beef_merge_txid_only` | [bsv/beef/test_beef_comprehensive.py:475](tests/bsv/beef/test_beef_comprehensive.py#L475) | ✓ |  |
| 127 | `test_beef_find_bump_with_nil_bump_index` | [bsv/beef/test_beef_comprehensive.py:499](tests/bsv/beef/test_beef_comprehensive.py#L499) | ✓ |  |
| 128 | `test_beef_bytes_serialize_deserialize` | [bsv/beef/test_beef_comprehensive.py:522](tests/bsv/beef/test_beef_comprehensive.py#L522) | ✓ |  |
| 129 | `test_beef_add_computed_leaves` | [bsv/beef/test_beef_comprehensive.py:553](tests/bsv/beef/test_beef_comprehensive.py#L553) | ✓ |  |
| 130 | `test_beef_from_v1` | [bsv/beef/test_beef_comprehensive.py:586](tests/bsv/beef/test_beef_comprehensive.py#L586) | ✓ | [A |
| 131 | `test_beef_make_txid_only_and_bytes` | [bsv/beef/test_beef_comprehensive.py:595](tests/bsv/beef/test_beef_comprehensive.py#L595) | ✓ |  |
| 132 | `test_beef_verify` | [bsv/beef/test_beef_comprehensive.py:621](tests/bsv/beef/test_beef_comprehensive.py#L621) | ✓ |  |
| 148 | `test_to_binary_writes_header_and_zero_counts` | [bsv/beef/test_beef_serialize_methods.py:1](tests/bsv/beef/test_beef_serialize_methods.py#L1) | ✓ |  |
| 149 | `test_to_binary_atomic_prefix_and_subject` | [bsv/beef/test_beef_serialize_methods.py:11](tests/bsv/beef/test_beef_serialize_methods.py#L11) | ✓ |  |
| 150 | `test_to_binary_parents_before_children` | [bsv/beef/test_beef_serialize_methods.py:22](tests/bsv/beef/test_beef_serialize_methods.py#L22) | ✓ |  |
| 151 | `test_find_bump_returns_matching_bump` | [bsv/beef/test_beef_utils_methods.py:1](tests/bsv/beef/test_beef_utils_methods.py#L1) | ✓ |  |
| 152 | `test_add_computed_leaves_adds_row_node` | [bsv/beef/test_beef_utils_methods.py:17](tests/bsv/beef/test_beef_utils_methods.py#L17) | ✓ |  |
| 153 | `test_trim_known_txids_removes_only_txid_only_entries` | [bsv/beef/test_beef_utils_methods.py:40](tests/bsv/beef/test_beef_utils_methods.py#L40) | ✓ |  |
| 154 | `test_is_valid_allows_txid_only_when_bump_has_txid` | [bsv/beef/test_beef_validate_methods.py:1](tests/bsv/beef/test_beef_validate_methods.py#L1) | ✓ |  |
| 155 | `test_get_valid_txids_includes_txidonly_with_proof_and_chained_raw` | [bsv/beef/test_beef_validate_methods.py:32](tests/bsv/beef/test_beef_validate_methods.py#L32) | ✓ |  |
| 156 | `test_verify_valid_multiple_bumps_roots_and_txidonly` | [bsv/beef/test_beef_validate_methods.py:62](tests/bsv/beef/test_beef_validate_methods.py#L62) | ✓ |  |
| 157 | `test_verify_valid_fails_when_bump_index_mismatch` | [bsv/beef/test_beef_validate_methods.py:93](tests/bsv/beef/test_beef_validate_methods.py#L93) | ✓ |  |
| 158 | `test_long_dependency_chain_requires_bump_for_validity` | [bsv/beef/test_beef_validate_methods.py:115](tests/bsv/beef/test_beef_validate_methods.py#L115) | ✓ | NEver valid |
| 388 | `test_tx_json_standard` | [bsv/transaction/test_json.py:13](tests/bsv/transaction/test_json.py#L13) | ✓ |  |
| 389 | `test_tx_json_data_tx` | [bsv/transaction/test_json.py:55](tests/bsv/transaction/test_json.py#L55) | ✓ |  |
| 390 | `test_tx_marshal_json` | [bsv/transaction/test_json.py:95](tests/bsv/transaction/test_json.py#L95) | ✓ |  |
| 391 | `test_tx_unmarshal_json` | [bsv/transaction/test_json.py:125](tests/bsv/transaction/test_json.py#L125) | ✓ |  |
| 404 | `test_get_merkle_tree_parent_str` | [bsv/transaction/test_merkle_tree_parent.py:9](tests/bsv/transaction/test_merkle_tree_parent.py#L9) | ✓ |  |
| 405 | `test_get_merkle_tree_parent` | [bsv/transaction/test_merkle_tree_parent.py:20](tests/bsv/transaction/test_merkle_tree_parent.py#L20) | ✓ |  |
| 415 | `test_calc_input_preimage_sighash_all_forkid` | [bsv/transaction/test_signature_hash.py:11](tests/bsv/transaction/test_signature_hash.py#L11) | ✓ |  |
| 416 | `test_calc_input_signature_hash_sighash_all_forkid` | [bsv/transaction/test_signature_hash.py:30](tests/bsv/transaction/test_signature_hash.py#L30) | ✓ |  |
| 417 | `test_calc_input_preimage_legacy_sighash_all` | [bsv/transaction/test_signature_hash.py:49](tests/bsv/transaction/test_signature_hash.py#L49) | ✓ |  |
| 444 | `test_is_coinbase` | [bsv/transaction/test_transaction_detailed.py:15](tests/bsv/transaction/test_transaction_detailed.py#L15) | ✓ |  |
| 445 | `test_is_valid_txid` | [bsv/transaction/test_transaction_detailed.py:32](tests/bsv/transaction/test_transaction_detailed.py#L32) | ✓ |  |
| 446 | `test_transaction_beef` | [bsv/transaction/test_transaction_detailed.py:47](tests/bsv/transaction/test_transaction_detailed.py#L47) | ✓ |  |
| 447 | `test_transaction_ef` | [bsv/transaction/test_transaction_detailed.py:65](tests/bsv/transaction/test_transaction_detailed.py#L65) | ✓ |  |
| 448 | `test_transaction_shallow_clone` | [bsv/transaction/test_transaction_detailed.py:80](tests/bsv/transaction/test_transaction_detailed.py#L80) | ✓ |  |
| 449 | `test_transaction_clone` | [bsv/transaction/test_transaction_detailed.py:98](tests/bsv/transaction/test_transaction_detailed.py#L98) | ✓ |  |
| 450 | `test_transaction_get_fee` | [bsv/transaction/test_transaction_detailed.py:111](tests/bsv/transaction/test_transaction_detailed.py#L111) | ✓ |  |
| 451 | `test_transaction_fee` | [bsv/transaction/test_transaction_detailed.py:131](tests/bsv/transaction/test_transaction_detailed.py#L131) | ✓ |  |
| 452 | `test_transaction_atomic_beef` | [bsv/transaction/test_transaction_detailed.py:189](tests/bsv/transaction/test_transaction_detailed.py#L189) | ✓ |  |
| 453 | `test_transaction_uncomputed_fee` | [bsv/transaction/test_transaction_detailed.py:220](tests/bsv/transaction/test_transaction_detailed.py#L220) | ✓ | match |
| 454 | `test_transaction_sign_unsigned` | [bsv/transaction/test_transaction_detailed.py:236](tests/bsv/transaction/test_transaction_detailed.py#L236) | ✓ | Does not sign unsigned |
| 455 | `test_transaction_sign_unsigned_new` | [bsv/transaction/test_transaction_detailed.py:257](tests/bsv/transaction/test_transaction_detailed.py#L257) | ✓ |  |
| 456 | `test_transaction_total_output_satoshis` | [bsv/transaction/test_transaction_detailed.py:294](tests/bsv/transaction/test_transaction_detailed.py#L294) | ✓ |  |
| 457 | `test_transaction_total_input_satoshis` | [bsv/transaction/test_transaction_detailed.py:309](tests/bsv/transaction/test_transaction_detailed.py#L309) | ✓ |  |
| 458 | `test_transaction_from_reader` | [bsv/transaction/test_transaction_detailed.py:322](tests/bsv/transaction/test_transaction_detailed.py#L322) | ✓ |  |
| 459 | `test_transaction_hex_roundtrip` | [bsv/transaction/test_transaction_detailed.py:338](tests/bsv/transaction/test_transaction_detailed.py#L338) | ✓ |  |
| 460 | `test_transaction_version_and_locktime` | [bsv/transaction/test_transaction_detailed.py:352](tests/bsv/transaction/test_transaction_detailed.py#L352) | ✓ |  |
| 461 | `test_new_input_from_reader_valid` | [bsv/transaction/test_transaction_input.py:11](tests/bsv/transaction/test_transaction_input.py#L11) | ✓ |  |
| 462 | `test_new_input_from_reader_empty_bytes` | [bsv/transaction/test_transaction_input.py:26](tests/bsv/transaction/test_transaction_input.py#L26) | ✓ |  |
| 463 | `test_new_input_from_reader_invalid_too_short` | [bsv/transaction/test_transaction_input.py:32](tests/bsv/transaction/test_transaction_input.py#L32) | ✓ |  |
| 464 | `test_input_string` | [bsv/transaction/test_transaction_input.py:38](tests/bsv/transaction/test_transaction_input.py#L38) | ✓ |  |
| 465 | `test_input_serialize` | [bsv/transaction/test_transaction_input.py:52](tests/bsv/transaction/test_transaction_input.py#L52) | ✓ |  |
| 466 | `test_input_with_source_transaction` | [bsv/transaction/test_transaction_input.py:72](tests/bsv/transaction/test_transaction_input.py#L72) | ✓ |  |
| 468 | `test_new_output_from_bytes_invalid_too_short` | [bsv/transaction/test_transaction_output.py:15](tests/bsv/transaction/test_transaction_output.py#L15) | ✓ |  |
| 469 | `test_new_output_from_bytes_invalid_too_short_with_script` | [bsv/transaction/test_transaction_output.py:21](tests/bsv/transaction/test_transaction_output.py#L21) | ✓ |  |
| 470 | `test_new_output_from_bytes_valid` | [bsv/transaction/test_transaction_output.py:34](tests/bsv/transaction/test_transaction_output.py#L34) | ✓ |  |
| 471 | `test_output_string` | [bsv/transaction/test_transaction_output.py:47](tests/bsv/transaction/test_transaction_output.py#L47) | ✓ | [3~t |
| 472 | `test_output_serialize` | [bsv/transaction/test_transaction_output.py:60](tests/bsv/transaction/test_transaction_output.py#L60) | ✓ |  |
| 473 | `test_output_with_change_flag` | [bsv/transaction/test_transaction_output.py:77](tests/bsv/transaction/test_transaction_output.py#L77) | ✓ |  |
| 474 | `test_total_output_satoshis` | [bsv/transaction/test_transaction_output.py:89](tests/bsv/transaction/test_transaction_output.py#L89) | ✓ |  |
| 475 | `test_output_p2pkh_from_pubkey_hash` | [bsv/transaction/test_transaction_output.py:106](tests/bsv/transaction/test_transaction_output.py#L106) | ✓ |  |
| 476 | `test_output_op_return` | [bsv/transaction/test_transaction_output.py:126](tests/bsv/transaction/test_transaction_output.py#L126) | ✓ |  |
| 477 | `test_output_op_return_parts` | [bsv/transaction/test_transaction_output.py:146](tests/bsv/transaction/test_transaction_output.py#L146) | ✓ |  |

---

**Note:** Click on file paths to open them at the exact line number in VS Code or Cursor.

**Status Legend:**
- ✓ = Test is sufficient
- ✗ = Test needs improvement or is insufficient
- — = Not yet reviewed
