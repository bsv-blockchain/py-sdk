# Python Tests List

This file lists all 52 Python tests with clickable links to their locations.

| # | Test Name | File | Status | Notes |
|---|-----------|-----|--------|-------|
| 8 | `test_auth_fetch_certificate_exchange` | [bsv/auth/clients/test_auth_fetch_full_e2e.py:112](tests/bsv/auth/clients/test_auth_fetch_full_e2e.py#L112) | ✓ | is not None not specific enough |
| 10 | `test_auth_fetch_error_handling` | [bsv/auth/clients/test_auth_fetch_full_e2e.py:185](tests/bsv/auth/clients/test_auth_fetch_full_e2e.py#L185) | ✓ | ANY Exception not specific enough |
| 22 | `test_real_wallet_success` | [bsv/auth/test_auth_cryptononce.py:71](tests/bsv/auth/test_auth_cryptononce.py#L71) | ✓ | Unsure |
| 27 | `test_issue_uses_get_public_key_identity_true_and_wallet_signature_priority` | [bsv/auth/test_auth_master_certificate.py:115](tests/bsv/auth/test_auth_master_certificate.py#L115) | ✓ | assert cert.signature == b"WALLET_SIG" WHAT? |
| 28 | `test_issue_get_public_key_exception_then_fallback_to_public_key_attribute` | [bsv/auth/test_auth_master_certificate.py:151](tests/bsv/auth/test_auth_master_certificate.py#L151) | ✓ | assert cert.signature == b"WALLET_SIG" WHAT? |
| 30 | `test_issue_wallet_signature_fallback_to_private_key_and_verify` | [bsv/auth/test_auth_master_certificate.py:210](tests/bsv/auth/test_auth_master_certificate.py#L210) | ✓ | is not None |
| 32 | `test_unknown_message_type` | [bsv/auth/test_auth_peer_basic.py:70](tests/bsv/auth/test_auth_peer_basic.py#L70) | ✓ | No Exception type or value assertion |
| 33 | `test_invalid_version` | [bsv/auth/test_auth_peer_basic.py:77](tests/bsv/auth/test_auth_peer_basic.py#L77) | ✓ | No Exception type or value |
| 34 | `test_initial_request_missing_nonce` | [bsv/auth/test_auth_peer_basic.py:84](tests/bsv/auth/test_auth_peer_basic.py#L84) | ✓ | No Exception type or value |
| 40 | `test_handle_certificate_request_valid_signature` | [bsv/auth/test_auth_peer_certificates.py:68](tests/bsv/auth/test_auth_peer_certificates.py#L68) | ✓ | Valid signature inferred err is None? |
| 41 | `test_handle_certificate_response_valid_signature_invokes_listener` | [bsv/auth/test_auth_peer_certificates.py:90](tests/bsv/auth/test_auth_peer_certificates.py#L90) | ✓ | Unsure |
| 47 | `test_mutual_authentication_and_general_message` | [bsv/auth/test_auth_peer_handshake.py:79](tests/bsv/auth/test_auth_peer_handshake.py#L79) | ✓ | # Wait for both directions    assert got_from_bob.wait(timeout=5)    assert got_from_alice.wait(timeout=5) asserting NOT NULL but could be errors? |
| 50 | `test_verify_nonce_uniqueness` | [bsv/auth/test_auth_peer_unit.py:56](tests/bsv/auth/test_auth_peer_unit.py#L56) | ✓ | Is this expected behaviour? |
| 53 | `test_get_authenticated_session_returns_existing` | [bsv/auth/test_auth_peer_unit.py:85](tests/bsv/auth/test_auth_peer_unit.py#L85) | ✗ | auto_persist_last_session not referenced, default? |
| 95 | `test_single_process_server_management` | [bsv/auth/test_metanet_desktop_auth.py:1318](tests/bsv/auth/test_metanet_desktop_auth.py#L1318) | ✗ | Printing results without asserting |
| 99 | `test_beef_unknown_version_errors` | [bsv/beef/test_beef_hardening.py:4](tests/bsv/beef/test_beef_hardening.py#L4) | ✓ | Should assert Exception message |
| 102 | `test_beef_v2_truncated_bumps_and_txs` | [bsv/beef/test_beef_hardening.py:41](tests/bsv/beef/test_beef_hardening.py#L41) | ✓ | Missing Exception type or message |
| 107 | `test_beef_v2_bump_index_out_of_range` | [bsv/beef/test_beef_hardening.py:144](tests/bsv/beef/test_beef_hardening.py#L144) | ✓ | Should raise ValueError + Exception message |
| 114 | `test_kvstore_set_get_remove_e2e` | [bsv/beef/test_kvstore_beef_e2e.py:87](tests/bsv/beef/test_kvstore_beef_e2e.py#L87) | ✗ | assert list count decrement |
| 117 | `test_beef_v2_raw_and_bump_chain_linking_best_effort` | [bsv/beef/test_kvstore_beef_e2e.py:149](tests/bsv/beef/test_kvstore_beef_e2e.py#L149) | ✓ | [A |
| 118 | `test_sighash_rules_end_byte_matrix` | [bsv/beef/test_kvstore_beef_e2e.py:161](tests/bsv/beef/test_kvstore_beef_e2e.py#L161) | ✓ | Incomplete or misunderstood, missing sign_outputs_mode=1 ? |
| 134 | `test_kvstore_get_uses_beef_when_available` | [bsv/beef/test_kvstore_beef_e2e.py:679](tests/bsv/beef/test_kvstore_beef_e2e.py#L679) | ✗ | No mention of beef |
| 135 | `test_kvstore_remove_stringifies_spends_and_uses_input_beef` | [bsv/beef/test_kvstore_beef_e2e.py:693](tests/bsv/beef/test_kvstore_beef_e2e.py#L693) | ✗ | Unsure! |
| 136 | `test_unlocking_script_length_estimate_vs_actual_set_and_remove` | [bsv/beef/test_kvstore_beef_e2e.py:752](tests/bsv/beef/test_kvstore_beef_e2e.py#L752) | ✗ | ? |
| 140 | `test_beef_v2_txidonly_and_bad_format_varint_errors` | [bsv/beef/test_kvstore_beef_e2e.py:890](tests/bsv/beef/test_kvstore_beef_e2e.py#L890) | ✗ | Exception errors could be better |
| 141 | `test_beef_mixed_versions_and_atomic_selection_logic` | [bsv/beef/test_kvstore_beef_e2e.py:919](tests/bsv/beef/test_kvstore_beef_e2e.py#L919) | ✗ | assert exception? |
| 144 | `test_beef_v2_mixed_txidonly_and_rawtx` | [bsv/beef/test_kvstore_beef_e2e.py:1035](tests/bsv/beef/test_kvstore_beef_e2e.py#L1035) | ✗ | Unsure |
| 148 | `test_beef_v2_duplicate_txidonly_and_rawtx` | [bsv/beef/test_kvstore_beef_e2e.py:1072](tests/bsv/beef/test_kvstore_beef_e2e.py#L1072) | ✗ | Where is duplicate & raw? |
| 152 | `test_kvstore_mixed_encrypted_and_plaintext_keys` | [bsv/beef/test_kvstore_beef_e2e.py:1195](tests/bsv/beef/test_kvstore_beef_e2e.py#L1195) | ✗ | Add list count assertion? |
| 164 | `test_categorize_transaction_status_progressing` | [bsv/broadcasters/test_broadcaster_arc.py:206](tests/bsv/broadcasters/test_broadcaster_arc.py#L206) | ✓ | p[3~ |
| 184 | `test_ckd` | [bsv/hd/test_hd.py:60](tests/bsv/hd/test_hd.py#L60) | ✓ | [3~p |
| 199 | `test_recombination_with_sample_shares` | [bsv/hd/test_key_shares.py:136](tests/bsv/hd/test_key_shares.py#L136) | ✓ | Could be improved to match actual WIF |
| 267 | `test_invalid_der_raises` | [bsv/primitives/test_utils_ecdsa.py:37](tests/bsv/primitives/test_utils_ecdsa.py#L37) | ✓ | [A |
| 287 | `test_edge_cases` | [bsv/primitives/test_utils_encoding.py:270](tests/bsv/primitives/test_utils_encoding.py#L270) | ✓ | Single byte values = edge cases |
| 305 | `test_register_and_list_basket` | [bsv/registry/test_registry_client.py:20](tests/bsv/registry/test_registry_client.py#L20) | ✓ | [A |
| 306 | `test_register_protocol_and_list` | [bsv/registry/test_registry_client.py:36](tests/bsv/registry/test_registry_client.py#L36) | ✓ | No assertions |
| 307 | `test_register_certificate_and_list` | [bsv/registry/test_registry_client.py:48](tests/bsv/registry/test_registry_client.py#L48) | ✓ | No assertions |
| 308 | `test_resolve_mock` | [bsv/registry/test_registry_client.py:61](tests/bsv/registry/test_registry_client.py#L61) | ✓ | Assert list len |
| 310 | `test_walletwire_resolver_filters` | [bsv/registry/test_registry_client.py:98](tests/bsv/registry/test_registry_client.py#L98) | ✓ | Assert list len or content? |
| 338 | `test_storage_upload_download_e2e` | [bsv/storage/test_storage_e2e.py:22](tests/bsv/storage/test_storage_e2e.py#L22) | ✗ | Insufficient 'or' |
| 340 | `test_storage_list_uploads_e2e` | [bsv/storage/test_storage_e2e.py:61](tests/bsv/storage/test_storage_e2e.py#L61) | ✗ | Assert len list or content |
| 343 | `test_kvstore_set_get_encrypt_with_pushdrop_lock_before` | [bsv/transaction/test_kvstore_pushdrop_encrypt.py:11](tests/bsv/transaction/test_kvstore_pushdrop_encrypt.py#L11) | ✗ | Missing pushdrop lock before? |
| 388 | `test_input_auto_txid` | [bsv/transaction/test_transaction.py:648](tests/bsv/transaction/test_transaction.py#L648) | ✓ | What Exception, match |
| 389 | `test_transaction_fee_with_default_rate` | [bsv/transaction/test_transaction.py:670](tests/bsv/transaction/test_transaction.py#L670) | ✗ | See file, missing test tx.verify() ? |
| 413 | `test_reveal_counterparty_key_linkage` | [bsv/wallet/substrates/test_wallet_wire_getpub_linkage.py:41](tests/bsv/wallet/substrates/test_wallet_wire_getpub_linkage.py#L41) | ✓ | improve assertion |
| 414 | `test_reveal_specific_key_linkage` | [bsv/wallet/substrates/test_wallet_wire_getpub_linkage.py:51](tests/bsv/wallet/substrates/test_wallet_wire_getpub_linkage.py#L51) | ✓ | improve assertions |
| 415 | `test_get_public_key_error_frame_permission_denied` | [bsv/wallet/substrates/test_wallet_wire_getpub_linkage.py:63](tests/bsv/wallet/substrates/test_wallet_wire_getpub_linkage.py#L63) | ✓ | Specific error string match needed |
| 416 | `test_reveal_counterparty_key_linkage_error_frame_permission_denied` | [bsv/wallet/substrates/test_wallet_wire_getpub_linkage.py:71](tests/bsv/wallet/substrates/test_wallet_wire_getpub_linkage.py#L71) | ✓ | Specific error string match needed |
| 439 | `test_normalize_counterparty_throws_for_invalid` | [bsv/wallet/test_wallet_keyderiver.py:32](tests/bsv/wallet/test_wallet_keyderiver.py#L32) | ✓ | match string error? |
| 440 | `test_normalize_counterparty_self` | [bsv/wallet/test_wallet_keyderiver.py:43](tests/bsv/wallet/test_wallet_keyderiver.py#L43) | ✓ | 2nd half commented out |
| 453 | `test_protocol_name_validation` | [bsv/wallet/test_wallet_keyderiver.py:171](tests/bsv/wallet/test_wallet_keyderiver.py#L171) | ✓ | Add should not raise protocol invoice |
| 461 | `test_kv_set_get_lock_after_signed_plain` | [test_kvstore_pushdrop_e2e.py:26](tests/test_kvstore_pushdrop_e2e.py#L26) | ✓ | After signed? |

---

**Note:** Click on file paths to open them at the exact line number in VS Code or Cursor.

**Status Legend:**
- ✓ = Test is sufficient
- ✗ = Test needs improvement or is insufficient
- — = Not yet reviewed
