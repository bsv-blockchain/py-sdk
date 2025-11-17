# Python Tests List

This file lists all 120 Python tests with clickable links to their locations.

| # | Test Name | File | Status | Notes |
|---|-----------|-----|--------|-------|
| 1 | `test_fetch_with_retry_counter_at_zero` | [bsv/auth/clients/test_auth_fetch.py:121](tests/bsv/auth/clients/test_auth_fetch.py#L121) | ✓ |  |
| 2 | `test_fetch_with_unsupported_headers` | [bsv/auth/clients/test_auth_fetch.py:134](tests/bsv/auth/clients/test_auth_fetch.py#L134) | ✓ |  |
| 3 | `test_fetch_network_failure_handling` | [bsv/auth/clients/test_auth_fetch.py:156](tests/bsv/auth/clients/test_auth_fetch.py#L156) | ✓ |  |
| 4 | `test_multiple_concurrent_sessions_same_identity_key` | [bsv/auth/test_auth_session_manager.py:134](tests/bsv/auth/test_auth_session_manager.py#L134) | ✓ |  |
| 5 | `test_concurrent_session_additions` | [bsv/auth/test_auth_session_manager.py:167](tests/bsv/auth/test_auth_session_manager.py#L167) | ✓ |  |
| 6 | `test_concurrent_handshakes_same_peer` | [bsv/auth/test_concurrent_handshakes.py:54](tests/bsv/auth/test_concurrent_handshakes.py#L54) | ✓ |  |
| 7 | `test_concurrent_handshakes_different_peers` | [bsv/auth/test_concurrent_handshakes.py:97](tests/bsv/auth/test_concurrent_handshakes.py#L97) | ✓ |  |
| 8 | `test_concurrent_session_expiration` | [bsv/auth/test_session_expiry.py:49](tests/bsv/auth/test_session_expiry.py#L49) | ✓ |  |
| 9 | `test_expiration_during_active_operations` | [bsv/auth/test_session_expiry.py:99](tests/bsv/auth/test_session_expiry.py#L99) | ✓ |  |
| 10 | `test_magic_hash_should_return_a_hash` | [bsv/compat/test_bsm.py:15](tests/bsv/compat/test_bsm.py#L15) | ✓ |  |
| 11 | `test_sign_should_return_a_signature` | [bsv/compat/test_bsm.py:21](tests/bsv/compat/test_bsm.py#L21) | ✓ |  |
| 12 | `test_sign_creates_the_correct_base64_signature` | [bsv/compat/test_bsm.py:34](tests/bsv/compat/test_bsm.py#L34) | ✓ |  |
| 13 | `test_verify_should_verify_a_signed_message` | [bsv/compat/test_bsm.py:41](tests/bsv/compat/test_bsm.py#L41) | ✓ |  |
| 14 | `test_verify_should_verify_a_signed_message_in_base64` | [bsv/compat/test_bsm.py:50](tests/bsv/compat/test_bsm.py#L50) | ✓ |  |
| 15 | `test_should_make_a_new_ecies_object` | [bsv/compat/test_ecies.py:15](tests/bsv/compat/test_ecies.py#L15) | ✓ |  |
| 16 | `test_bitcore_encrypt_should_return_bytes` | [bsv/compat/test_ecies.py:20](tests/bsv/compat/test_ecies.py#L20) | ✓ |  |
| 17 | `test_bitcore_encrypt_should_return_bytes_if_fromkey_not_present` | [bsv/compat/test_ecies.py:29](tests/bsv/compat/test_ecies.py#L29) | ✓ |  |
| 18 | `test_bitcore_decrypt_should_decrypt_that_which_was_encrypted` | [bsv/compat/test_ecies.py:37](tests/bsv/compat/test_ecies.py#L37) | ✓ |  |
| 19 | `test_bitcore_decrypt_with_random_fromkey` | [bsv/compat/test_ecies.py:47](tests/bsv/compat/test_ecies.py#L47) | ✓ |  |
| 20 | `test_electrum_ecies_should_work_with_test_vectors` | [bsv/compat/test_ecies.py:56](tests/bsv/compat/test_ecies.py#L56) | ✓ |  |
| 21 | `test_get_merkle_roots_success` | [bsv/headers_client/test_headers_client.py:41](tests/bsv/headers_client/test_headers_client.py#L41) | ✓ |  |
| 22 | `test_get_merkle_roots_with_last_evaluated_key` | [bsv/headers_client/test_headers_client.py:81](tests/bsv/headers_client/test_headers_client.py#L81) | ✓ |  |
| 23 | `test_get_merkle_roots_error` | [bsv/headers_client/test_headers_client.py:108](tests/bsv/headers_client/test_headers_client.py#L108) | ✓ |  |
| 24 | `test_get_merkle_roots_empty_response` | [bsv/headers_client/test_headers_client.py:128](tests/bsv/headers_client/test_headers_client.py#L128) | ✓ |  |
| 25 | `test_get_merkle_roots_invalid_json` | [bsv/headers_client/test_headers_client.py:151](tests/bsv/headers_client/test_headers_client.py#L151) | ✓ |  |
| 26 | `test_register_webhook_success` | [bsv/headers_client/test_headers_client.py:174](tests/bsv/headers_client/test_headers_client.py#L174) | ✓ |  |
| 27 | `test_register_webhook_error` | [bsv/headers_client/test_headers_client.py:210](tests/bsv/headers_client/test_headers_client.py#L210) | ✓ |  |
| 28 | `test_unregister_webhook_success` | [bsv/headers_client/test_headers_client.py:230](tests/bsv/headers_client/test_headers_client.py#L230) | ✓ |  |
| 29 | `test_unregister_webhook_error` | [bsv/headers_client/test_headers_client.py:253](tests/bsv/headers_client/test_headers_client.py#L253) | ✓ |  |
| 30 | `test_get_webhook_success` | [bsv/headers_client/test_headers_client.py:273](tests/bsv/headers_client/test_headers_client.py#L273) | ✓ |  |
| 31 | `test_get_webhook_not_found` | [bsv/headers_client/test_headers_client.py:302](tests/bsv/headers_client/test_headers_client.py#L302) | ✓ |  |
| 32 | `test_webhook_with_multiple_error_counts` | [bsv/headers_client/test_headers_client.py:322](tests/bsv/headers_client/test_headers_client.py#L322) | ✓ |  |
| 33 | `test_is_valid_root_for_height` | [bsv/headers_client/test_headers_client.py:360](tests/bsv/headers_client/test_headers_client.py#L360) | ✓ |  |
| 34 | `test_current_height` | [bsv/headers_client/test_headers_client.py:378](tests/bsv/headers_client/test_headers_client.py#L378) | ✓ |  |
| 35 | `test_implements_chain_tracker_interface` | [bsv/headers_client/test_headers_client.py:402](tests/bsv/headers_client/test_headers_client.py#L402) | ✓ |  |
| 36 | `test_should_get_empty_contacts_when_none_exist` | [bsv/identity/test_contacts_manager.py:42](tests/bsv/identity/test_contacts_manager.py#L42) | ✓ |  |
| 37 | `test_should_get_contacts_by_identity_key` | [bsv/identity/test_contacts_manager.py:47](tests/bsv/identity/test_contacts_manager.py#L47) | ✓ |  |
| 38 | `test_should_save_new_contact` | [bsv/identity/test_contacts_manager.py:63](tests/bsv/identity/test_contacts_manager.py#L63) | ✓ |  |
| 39 | `test_should_update_existing_contact` | [bsv/identity/test_contacts_manager.py:76](tests/bsv/identity/test_contacts_manager.py#L76) | ✓ |  |
| 40 | `test_should_delete_contact` | [bsv/identity/test_contacts_manager.py:100](tests/bsv/identity/test_contacts_manager.py#L100) | ✓ |  |
| 41 | `test_should_create_instance_with_default_wallet_and_encrypt_true` | [bsv/keystore/test_local_kv_store_complete.py:66](tests/bsv/keystore/test_local_kv_store_complete.py#L66) | ✓ |  |
| 42 | `test_should_create_instance_with_provided_wallet_context_and_encrypt_false` | [bsv/keystore/test_local_kv_store_complete.py:81](tests/bsv/keystore/test_local_kv_store_complete.py#L81) | ✓ |  |
| 43 | `test_should_throw_error_if_context_is_missing_or_empty` | [bsv/keystore/test_local_kv_store_complete.py:95](tests/bsv/keystore/test_local_kv_store_complete.py#L95) | ✓ |  |
| 44 | `test_should_return_default_value_if_no_output_is_found` | [bsv/keystore/test_local_kv_store_complete.py:111](tests/bsv/keystore/test_local_kv_store_complete.py#L111) | ✓ |  |
| 45 | `test_should_return_empty_string_if_no_output_found_and_no_default_value` | [bsv/keystore/test_local_kv_store_complete.py:131](tests/bsv/keystore/test_local_kv_store_complete.py#L131) | ✓ |  |
| 46 | `test_should_create_new_encrypted_output_if_none_exists` | [bsv/keystore/test_local_kv_store_complete.py:155](tests/bsv/keystore/test_local_kv_store_complete.py#L155) | ✓ |  |
| 47 | `test_should_create_new_non_encrypted_output_if_none_exists_and_encrypt_false` | [bsv/keystore/test_local_kv_store_complete.py:183](tests/bsv/keystore/test_local_kv_store_complete.py#L183) | ✓ |  |
| 48 | `test_should_do_nothing_and_return_empty_list_if_key_does_not_exist` | [bsv/keystore/test_local_kv_store_complete.py:212](tests/bsv/keystore/test_local_kv_store_complete.py#L212) | ✓ |  |
| 49 | `test_should_remove_existing_key_by_spending_its_outputs` | [bsv/keystore/test_local_kv_store_complete.py:234](tests/bsv/keystore/test_local_kv_store_complete.py#L234) | ✓ |  |
| 50 | `test_should_build_history_from_transaction` | [bsv/overlay_tools/test_historian.py:15](tests/bsv/overlay_tools/test_historian.py#L15) | ✓ |  |
| 51 | `test_should_use_cache_when_provided` | [bsv/overlay_tools/test_historian.py:32](tests/bsv/overlay_tools/test_historian.py#L32) | ✓ |  |
| 52 | `test_should_record_success` | [bsv/overlay_tools/test_host_reputation_tracker.py:16](tests/bsv/overlay_tools/test_host_reputation_tracker.py#L16) | ✓ |  |
| 53 | `test_should_record_failure` | [bsv/overlay_tools/test_host_reputation_tracker.py:27](tests/bsv/overlay_tools/test_host_reputation_tracker.py#L27) | ✓ |  |
| 54 | `test_should_rank_hosts_by_score` | [bsv/overlay_tools/test_host_reputation_tracker.py:38](tests/bsv/overlay_tools/test_host_reputation_tracker.py#L38) | ✓ |  |
| 55 | `test_should_respect_backoff_period` | [bsv/overlay_tools/test_host_reputation_tracker.py:51](tests/bsv/overlay_tools/test_host_reputation_tracker.py#L51) | ✓ |  |
| 56 | `test_should_persist_to_storage` | [bsv/overlay_tools/test_host_reputation_tracker.py:62](tests/bsv/overlay_tools/test_host_reputation_tracker.py#L62) | ✓ |  |
| 57 | `test_should_not_fail_at_nist_vector` | [bsv/primitives/test_drbg.py:107](tests/bsv/primitives/test_drbg.py#L107) | ✓ |  |
| 58 | `test_should_throw_error_if_entropy_too_short` | [bsv/primitives/test_drbg.py:118](tests/bsv/primitives/test_drbg.py#L118) | ✓ |  |
| 59 | `test_should_verify_a_valid_proof` | [bsv/primitives/test_schnorr.py:19](tests/bsv/primitives/test_schnorr.py#L19) | ✓ |  |
| 60 | `test_should_fail_verification_if_proof_is_tampered_r_modified` | [bsv/primitives/test_schnorr.py:39](tests/bsv/primitives/test_schnorr.py#L39) | ✓ |  |
| 61 | `test_should_fail_verification_if_proof_is_tampered_z_modified` | [bsv/primitives/test_schnorr.py:56](tests/bsv/primitives/test_schnorr.py#L56) | ✓ |  |
| 62 | `test_should_fail_verification_if_proof_is_tampered_s_prime_modified` | [bsv/primitives/test_schnorr.py:73](tests/bsv/primitives/test_schnorr.py#L73) | ✓ |  |
| 63 | `test_should_fail_verification_if_inputs_are_tampered_a_modified` | [bsv/primitives/test_schnorr.py:90](tests/bsv/primitives/test_schnorr.py#L90) | ✓ |  |
| 64 | `test_should_fail_verification_if_inputs_are_tampered_b_modified` | [bsv/primitives/test_schnorr.py:106](tests/bsv/primitives/test_schnorr.py#L106) | ✓ |  |
| 65 | `test_should_fail_verification_if_inputs_are_tampered_s_modified` | [bsv/primitives/test_schnorr.py:122](tests/bsv/primitives/test_schnorr.py#L122) | ✓ |  |
| 66 | `test_should_fail_verification_if_using_wrong_private_key` | [bsv/primitives/test_schnorr.py:138](tests/bsv/primitives/test_schnorr.py#L138) | ✓ |  |
| 67 | `test_should_fail_verification_if_using_wrong_public_key` | [bsv/primitives/test_schnorr.py:153](tests/bsv/primitives/test_schnorr.py#L153) | ✓ |  |
| 68 | `test_should_fail_verification_if_shared_secret_s_is_incorrect` | [bsv/primitives/test_schnorr.py:169](tests/bsv/primitives/test_schnorr.py#L169) | ✓ |  |
| 69 | `test_should_verify_a_valid_proof_with_fixed_keys` | [bsv/primitives/test_schnorr.py:187](tests/bsv/primitives/test_schnorr.py#L187) | ✓ |  |
| 70 | `test_engine_creation` | [bsv/script/interpreter/test_engine.py:16](tests/bsv/script/interpreter/test_engine.py#L16) | ✓ |  |
| 71 | `test_engine_execute_with_simple_scripts` | [bsv/script/interpreter/test_engine.py:21](tests/bsv/script/interpreter/test_engine.py#L21) | ✓ |  |
| 72 | `test_engine_execute_with_missing_scripts` | [bsv/script/interpreter/test_engine.py:40](tests/bsv/script/interpreter/test_engine.py#L40) | ✓ |  |
| 73 | `test_engine_with_after_genesis` | [bsv/script/interpreter/test_engine.py:53](tests/bsv/script/interpreter/test_engine.py#L53) | ✓ |  |
| 74 | `test_engine_with_fork_id` | [bsv/script/interpreter/test_engine.py:68](tests/bsv/script/interpreter/test_engine.py#L68) | ✓ |  |
| 75 | `test_simple_script_execution` | [bsv/script/interpreter/test_engine_comprehensive.py:17](tests/bsv/script/interpreter/test_engine_comprehensive.py#L17) | ✓ |  |
| 76 | `test_script_with_unlocking_script` | [bsv/script/interpreter/test_engine_comprehensive.py:28](tests/bsv/script/interpreter/test_engine_comprehensive.py#L28) | ✓ |  |
| 77 | `test_invalid_script_fails` | [bsv/script/interpreter/test_engine_comprehensive.py:39](tests/bsv/script/interpreter/test_engine_comprehensive.py#L39) | ✓ |  |
| 78 | `test_missing_scripts_error` | [bsv/script/interpreter/test_engine_comprehensive.py:51](tests/bsv/script/interpreter/test_engine_comprehensive.py#L51) | ✓ |  |
| 79 | `test_arithmetic_operations` | [bsv/script/interpreter/test_engine_comprehensive.py:62](tests/bsv/script/interpreter/test_engine_comprehensive.py#L62) | ✓ |  |
| 80 | `test_stack_operations` | [bsv/script/interpreter/test_engine_comprehensive.py:73](tests/bsv/script/interpreter/test_engine_comprehensive.py#L73) | ✓ |  |
| 81 | `test_conditional_operations` | [bsv/script/interpreter/test_engine_comprehensive.py:86](tests/bsv/script/interpreter/test_engine_comprehensive.py#L86) | ✓ |  |
| 82 | `test_with_after_genesis` | [bsv/script/interpreter/test_engine_comprehensive.py:100](tests/bsv/script/interpreter/test_engine_comprehensive.py#L100) | ✓ |  |
| 83 | `test_with_fork_id` | [bsv/script/interpreter/test_engine_comprehensive.py:113](tests/bsv/script/interpreter/test_engine_comprehensive.py#L113) | ✓ |  |
| 84 | `test_should_create_locking_script_from_address` | [bsv/script/test_p2pkh_template.py:15](tests/bsv/script/test_p2pkh_template.py#L15) | ✓ |  |
| 85 | `test_should_create_locking_script_from_pubkey_hash` | [bsv/script/test_p2pkh_template.py:27](tests/bsv/script/test_p2pkh_template.py#L27) | ✓ |  |
| 86 | `test_should_throw_error_for_invalid_address` | [bsv/script/test_p2pkh_template.py:39](tests/bsv/script/test_p2pkh_template.py#L39) | ✓ |  |
| 87 | `test_should_create_unlocking_script_template` | [bsv/script/test_p2pkh_template.py:46](tests/bsv/script/test_p2pkh_template.py#L46) | ✓ |  |
| 88 | `test_should_estimate_unlocking_script_length` | [bsv/script/test_p2pkh_template.py:60](tests/bsv/script/test_p2pkh_template.py#L60) | ✓ |  |
| 89 | `test_should_create_raw_rpuzzle_locking_script` | [bsv/script/test_rpuzzle_template.py:15](tests/bsv/script/test_rpuzzle_template.py#L15) | ✓ |  |
| 90 | `test_should_create_sha256_rpuzzle_locking_script` | [bsv/script/test_rpuzzle_template.py:25](tests/bsv/script/test_rpuzzle_template.py#L25) | ✓ |  |
| 91 | `test_should_create_sha1_rpuzzle_locking_script` | [bsv/script/test_rpuzzle_template.py:36](tests/bsv/script/test_rpuzzle_template.py#L36) | ✓ |  |
| 92 | `test_should_create_hash160_rpuzzle_locking_script` | [bsv/script/test_rpuzzle_template.py:47](tests/bsv/script/test_rpuzzle_template.py#L47) | ✓ |  |
| 93 | `test_should_create_unlocking_script_template` | [bsv/script/test_rpuzzle_template.py:58](tests/bsv/script/test_rpuzzle_template.py#L58) | ✓ |  |
| 94 | `test_should_estimate_unlocking_script_length` | [bsv/script/test_rpuzzle_template.py:73](tests/bsv/script/test_rpuzzle_template.py#L73) | ✓ |  |
| 95 | `test_is_valid_root_for_height_always_returns_true` | [bsv/spv/test_gullible_headers_client.py:16](tests/bsv/spv/test_gullible_headers_client.py#L16) | ✓ |  |
| 96 | `test_current_height_returns_dummy_height` | [bsv/spv/test_gullible_headers_client.py:32](tests/bsv/spv/test_gullible_headers_client.py#L32) | ✓ |  |
| 97 | `test_implements_chain_tracker_interface` | [bsv/spv/test_gullible_headers_client.py:40](tests/bsv/spv/test_gullible_headers_client.py#L40) | ✓ |  |
| 98 | `test_verify_scripts_with_beef_transaction` | [bsv/spv/test_verify_scripts.py:22](tests/bsv/spv/test_verify_scripts.py#L22) | ✓ |  |
| 99 | `test_verify_scripts_skips_merkle_proof` | [bsv/spv/test_verify_scripts.py:32](tests/bsv/spv/test_verify_scripts.py#L32) | ✓ |  |
| 100 | `test_verify_scripts_with_invalid_script` | [bsv/spv/test_verify_scripts.py:54](tests/bsv/spv/test_verify_scripts.py#L54) | ✓ |  |
| 101 | `test_verify_scripts_with_missing_source_transaction` | [bsv/spv/test_verify_scripts.py:68](tests/bsv/spv/test_verify_scripts.py#L68) | ✓ |  |
| 102 | `test_totp_generation_and_validation` | [bsv/totp/test_totp.py:27](tests/bsv/totp/test_totp.py#L27) | ✓ |  |
| 103 | `test_should_create_with_parties` | [bsv/transaction/test_beef_party.py:14](tests/bsv/transaction/test_beef_party.py#L14) | ✓ |  |
| 104 | `test_should_add_party` | [bsv/transaction/test_beef_party.py:23](tests/bsv/transaction/test_beef_party.py#L23) | ✓ |  |
| 105 | `test_should_throw_error_if_party_already_exists` | [bsv/transaction/test_beef_party.py:30](tests/bsv/transaction/test_beef_party.py#L30) | ✓ |  |
| 106 | `test_should_get_known_txids_for_party` | [bsv/transaction/test_beef_party.py:37](tests/bsv/transaction/test_beef_party.py#L37) | ✓ |  |
| 107 | `test_should_throw_error_for_unknown_party` | [bsv/transaction/test_beef_party.py:50](tests/bsv/transaction/test_beef_party.py#L50) | ✓ |  |
| 108 | `test_should_get_trimmed_beef_for_party` | [bsv/transaction/test_beef_party.py:57](tests/bsv/transaction/test_beef_party.py#L57) | ✓ |  |
| 109 | `test_should_merge_beef_from_party` | [bsv/transaction/test_beef_party.py:66](tests/bsv/transaction/test_beef_party.py#L66) | ✓ |  |
| 110 | `test_should_create_from_transaction` | [bsv/transaction/test_beef_tx.py:15](tests/bsv/transaction/test_beef_tx.py#L15) | ✓ |  |
| 111 | `test_should_create_from_raw_bytes` | [bsv/transaction/test_beef_tx.py:24](tests/bsv/transaction/test_beef_tx.py#L24) | ✓ |  |
| 112 | `test_should_create_from_txid` | [bsv/transaction/test_beef_tx.py:32](tests/bsv/transaction/test_beef_tx.py#L32) | ✓ |  |
| 113 | `test_should_have_proof_when_bump_index_set` | [bsv/transaction/test_beef_tx.py:40](tests/bsv/transaction/test_beef_tx.py#L40) | ✓ |  |
| 114 | `test_should_update_input_txids` | [bsv/transaction/test_beef_tx.py:48](tests/bsv/transaction/test_beef_tx.py#L48) | ✓ |  |
| 115 | `test_should_create_beef_v2_instance` | [bsv/transaction/test_beef_v2.py:16](tests/bsv/transaction/test_beef_v2.py#L16) | ✓ |  |
| 116 | `test_should_serialize_beef_v2_with_transactions` | [bsv/transaction/test_beef_v2.py:22](tests/bsv/transaction/test_beef_v2.py#L22) | ✓ |  |
| 117 | `test_should_support_tx_data_format_rawtx` | [bsv/transaction/test_beef_v2.py:34](tests/bsv/transaction/test_beef_v2.py#L34) | ✓ |  |
| 118 | `test_should_support_tx_data_format_rawtx_and_bump_index` | [bsv/transaction/test_beef_v2.py:38](tests/bsv/transaction/test_beef_v2.py#L38) | ✓ |  |
| 119 | `test_should_create_beef_tx_with_bump_index` | [bsv/transaction/test_beef_v2.py:42](tests/bsv/transaction/test_beef_v2.py#L42) | ✓ |  |
| 120 | `test_should_build_beef_v2_from_raw_hexes` | [bsv/transaction/test_beef_v2.py:50](tests/bsv/transaction/test_beef_v2.py#L50) | ✓ |  |

---

**Note:** Click on file paths to open them at the exact line number in VS Code or Cursor.

**Status Legend:**
- ✓ = Test is sufficient
- ✗ = Test needs improvement or is insufficient
- — = Not yet reviewed
