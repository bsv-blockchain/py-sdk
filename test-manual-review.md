# Python Tests List

This file lists 15 Python tests that need review with clickable links to their locations.

| # | Test Name | File | Status | Notes |
|---|-----------|-----|--------|-------|
| 53 | `test_get_authenticated_session_returns_existing` | [bsv/auth/test_auth_peer_unit.py:85](tests/bsv/auth/test_auth_peer_unit.py#L85) | ✗ | auto_persist_last_session not referenced, default? |
| 95 | `test_single_process_server_management` | [bsv/auth/test_metanet_desktop_auth.py:1318](tests/bsv/auth/test_metanet_desktop_auth.py#L1318) | ✗ | Printing results without asserting |
| 114 | `test_kvstore_set_get_remove_e2e` | [bsv/beef/test_kvstore_beef_e2e.py:87](tests/bsv/beef/test_kvstore_beef_e2e.py#L87) | ✗ | assert list count decrement |
| 134 | `test_kvstore_get_uses_beef_when_available` | [bsv/beef/test_kvstore_beef_e2e.py:679](tests/bsv/beef/test_kvstore_beef_e2e.py#L679) | ✗ | No mention of beef |
| 135 | `test_kvstore_remove_stringifies_spends_and_uses_input_beef` | [bsv/beef/test_kvstore_beef_e2e.py:693](tests/bsv/beef/test_kvstore_beef_e2e.py#L693) | ✗ | Unsure! |
| 136 | `test_unlocking_script_length_estimate_vs_actual_set_and_remove` | [bsv/beef/test_kvstore_beef_e2e.py:752](tests/bsv/beef/test_kvstore_beef_e2e.py#L752) | ✗ | ? |
| 140 | `test_beef_v2_txidonly_and_bad_format_varint_errors` | [bsv/beef/test_kvstore_beef_e2e.py:890](tests/bsv/beef/test_kvstore_beef_e2e.py#L890) | ✗ | Exception errors could be better |
| 141 | `test_beef_mixed_versions_and_atomic_selection_logic` | [bsv/beef/test_kvstore_beef_e2e.py:919](tests/bsv/beef/test_kvstore_beef_e2e.py#L919) | ✗ | assert exception? |
| 144 | `test_beef_v2_mixed_txidonly_and_rawtx` | [bsv/beef/test_kvstore_beef_e2e.py:1035](tests/bsv/beef/test_kvstore_beef_e2e.py#L1035) | ✗ | Unsure |
| 148 | `test_beef_v2_duplicate_txidonly_and_rawtx` | [bsv/beef/test_kvstore_beef_e2e.py:1072](tests/bsv/beef/test_kvstore_beef_e2e.py#L1072) | ✗ | Where is duplicate & raw? |
| 152 | `test_kvstore_mixed_encrypted_and_plaintext_keys` | [bsv/beef/test_kvstore_beef_e2e.py:1195](tests/bsv/beef/test_kvstore_beef_e2e.py#L1195) | ✗ | Add list count assertion? |
| 338 | `test_storage_upload_download_e2e` | [bsv/storage/test_storage_e2e.py:22](tests/bsv/storage/test_storage_e2e.py#L22) | ✗ | Insufficient 'or' |
| 340 | `test_storage_list_uploads_e2e` | [bsv/storage/test_storage_e2e.py:61](tests/bsv/storage/test_storage_e2e.py#L61) | ✗ | Assert len list or content |
| 343 | `test_kvstore_set_get_encrypt_with_pushdrop_lock_before` | [bsv/transaction/test_kvstore_pushdrop_encrypt.py:11](tests/bsv/transaction/test_kvstore_pushdrop_encrypt.py#L11) | ✗ | Missing pushdrop lock before? |
| 389 | `test_transaction_fee_with_default_rate` | [bsv/transaction/test_transaction.py:670](tests/bsv/transaction/test_transaction.py#L670) | ✗ | See file, missing test tx.verify() ? |

---

**Note:** Click on file paths to open them at the exact line number in VS Code or Cursor.

**Status Legend:**
- ✓ = Test is sufficient
- ✗ = Test needs improvement or is insufficient
- — = Not yet reviewed
