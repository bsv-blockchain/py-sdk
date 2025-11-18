# Coverage Improvement Plan - Phase 2

**Current Status:** 73% overall coverage (16,062 statements, 3,757 missing)
**Target:** 80%+ overall coverage
**Approach:** Strategic targeting of high-impact and low-coverage files

---

## Executive Summary

After Phase 1 improvements (+7% overall), we now target:
1. **Quick Wins:** Small files with very low coverage (0-40%)
2. **High Impact:** Large files where small % gains = many statements
3. **Critical Paths:** Wallet operations, script interpreter, serializers

**Estimated Impact:** +7-10% overall coverage with ~400-500 new tests

---

## Priority 1: Quick Wins (Small Files, Low Coverage)

### 1. `bsv/wallet/serializer/relinquish_output.py` (33% - 18 statements)
**Effort:** LOW | **Impact:** MEDIUM
**Current:** 18 statements, 12 missing

```python
# New: tests/bsv/wallet/serializer/test_relinquish_output.py
class TestRelinquishOutputSerialization:
    def test_serialize_empty_args()
    def test_serialize_with_outpoint()
    def test_serialize_with_basket()
    def test_deserialize_round_trip()
    def test_serialize_result_success()
    def test_serialize_result_error()
    def test_deserialize_invalid_data()
```
**Expected:** 33% → 90%+ (gain: ~10 statements)

---

### 2. `bsv/wallet/serializer/get_network.py` (35% - 43 statements)
**Effort:** LOW | **Impact:** MEDIUM
**Current:** 43 statements, 28 missing

```python
# New: tests/bsv/wallet/serializer/test_get_network.py
class TestGetNetworkSerialization:
    def test_serialize_args_empty()
    def test_serialize_args_with_context()
    def test_deserialize_result_mainnet()
    def test_deserialize_result_testnet()
    def test_deserialize_result_regtest()
    def test_round_trip_all_networks()
    def test_invalid_network_string()
```
**Expected:** 35% → 90%+ (gain: ~25 statements)

---

### 3. `bsv/overlay_tools/overlay_admin_token_template.py` (35% - 57 statements)
**Effort:** MEDIUM | **Impact:** MEDIUM
**Current:** 57 statements, 35 missing

```python
# New: tests/bsv/overlay_tools/test_overlay_admin_token_template.py
class TestOverlayAdminTokenTemplate:
    def test_create_template()
    def test_build_locking_script()
    def test_verify_admin_token()
    def test_extract_admin_fields()
    def test_validate_signature()
    def test_invalid_token_format()
    def test_expired_token()
    def test_unauthorized_key()
```
**Expected:** 35% → 85%+ (gain: ~30 statements)

---

### 4. `bsv/utils/reader_writer.py` (39% - 114 statements)
**Effort:** MEDIUM | **Impact:** HIGH
**Current:** 114 statements, 65 missing

**Strategy:** Test both Reader and Writer classes comprehensively
```python
# Extend: tests/bsv/utils/test_reader_writer.py (if exists) or create new
class TestReaderExtended:
    def test_read_all_types()
    def test_read_with_insufficient_data()
    def test_read_varint_all_sizes()
    def test_seek_and_tell()
    def test_read_string_utf8_errors()
    
class TestWriterExtended:
    def test_write_all_types()
    def test_write_varint_boundaries()
    def test_buffer_growth()
    def test_write_negative_values()
    def test_write_large_strings()
```
**Expected:** 39% → 85%+ (gain: ~50 statements)

---

## Priority 2: Medium Impact Files (40-60% Coverage)

### 5. `bsv/script/interpreter/stack.py` (46% - 141 statements)
**Effort:** MEDIUM | **Impact:** HIGH
**Current:** 141 statements, 64 missing

```python
# Extend: tests/bsv/script/interpreter/test_stack.py
class TestStackOperations:
    def test_push_pop_operations()
    def test_dup_operations()
    def test_swap_operations()
    def test_pick_roll_operations()
    def test_depth_operations()
    def test_stack_underflow_errors()
    def test_stack_overflow_limits()
    def test_peek_operations()
    def test_verify_operations()
```
**Expected:** 46% → 80%+ (gain: ~48 statements)

---

### 6. `bsv/wallet/serializer/acquire_certificate.py` (48% - 78 statements)
**Effort:** MEDIUM | **Impact:** MEDIUM
**Current:** 78 statements, 38 missing

```python
# New: tests/bsv/wallet/serializer/test_acquire_certificate.py
class TestAcquireCertificateSerialization:
    def test_serialize_args_minimal()
    def test_serialize_args_with_fields()
    def test_serialize_args_with_certifier()
    def test_deserialize_result_success()
    def test_deserialize_result_with_keyring()
    def test_round_trip_complete_flow()
    def test_invalid_certificate_type()
    def test_missing_required_fields()
```
**Expected:** 48% → 85%+ (gain: ~30 statements)

---

### 7. `bsv/overlay_tools/ship_broadcaster.py` (49% - 163 statements)
**Effort:** HIGH | **Impact:** HIGH
**Current:** 163 statements, 75 missing

```python
# New: tests/bsv/overlay_tools/test_ship_broadcaster.py
class TestShipBroadcaster:
    def test_create_broadcaster()
    def test_broadcast_transaction()
    def test_handle_response()
    def test_retry_logic()
    def test_network_timeout()
    def test_invalid_ship_endpoint()
    def test_concurrent_broadcasts()
    def test_rate_limiting()
```
**Expected:** 49% → 75%+ (gain: ~42 statements)

---

### 8. `bsv/primitives/aescbc.py` (52% - 57 statements)
**Effort:** MEDIUM | **Impact:** MEDIUM
**Current:** 57 statements, 25 missing

```python
# New: tests/bsv/primitives/test_aescbc.py
class TestAESCBC:
    def test_encrypt_decrypt_round_trip()
    def test_encrypt_with_iv()
    def test_decrypt_with_wrong_key()
    def test_padding_operations()
    def test_block_size_validation()
    def test_key_size_variations()
    def test_empty_data_encryption()
    def test_large_data_encryption()
```
**Expected:** 52% → 90%+ (gain: ~22 statements)

---

### 9. `bsv/utils/script_chunks.py` (57% - 57 statements)
**Effort:** MEDIUM | **Impact:** MEDIUM
**Current:** 57 statements, 23 missing

```python
# Extend: tests/bsv/utils/test_script_chunks.py
class TestScriptChunksParsing:
    def test_parse_simple_script()
    def test_parse_pushdata_variants()
    def test_parse_mixed_opcodes()
    def test_parse_invalid_script()
    def test_chunk_to_bytes()
    def test_empty_script_chunks()
    def test_large_pushdata()
```
**Expected:** 57% → 90%+ (gain: ~20 statements)

---

## Priority 3: High-Impact Large Files

### 10. `bsv/wallet/wallet_impl.py` (69% - 1221 statements)
**Effort:** VERY HIGH | **Impact:** MASSIVE
**Current:** 1221 statements, 333 missing

**Strategy:** Focus on uncovered wallet operations (10% improvement = 122 statements!)
```python
# Extend: tests/bsv/wallet/test_wallet_impl.py
class TestWalletImplAdvanced:
    # Transaction Creation
    def test_create_action_with_complex_outputs()
    def test_create_action_with_pushdrop()
    def test_create_action_insufficient_funds()
    
    # Certificate Operations
    def test_acquire_certificate_flow()
    def test_list_certificates_with_filters()
    def test_prove_certificate()
    def test_relinquish_certificate()
    
    # Key Derivation
    def test_reveal_counterparty_key()
    def test_reveal_specific_secret()
    def test_derive_symmetric_key_edge_cases()
    
    # HMAC Operations
    def test_create_hmac_with_protocols()
    def test_verify_hmac_success_fail()
    
    # Discovery Operations
    def test_discover_by_identity_key()
    def test_discover_by_attributes()
    
    # Output Management
    def test_relinquish_output()
    def test_list_outputs_complex_filters()
    
    # Action Management
    def test_list_actions_with_pagination()
    def test_internalize_action_complete_flow()
    def test_abort_action()
```
**Expected:** 69% → 80%+ (gain: ~135 statements)

---

### 11. `bsv/keystore/local_kv_store.py` (62% - 698 statements)
**Effort:** VERY HIGH | **Impact:** MASSIVE
**Current:** 698 statements, 235 missing

**Strategy:** Test all CRUD operations and edge cases
```python
# Extend: tests/bsv/keystore/test_local_kv_store.py
class TestLocalKVStoreAdvanced:
    # Certificate storage
    def test_store_certificate()
    def test_retrieve_certificate()
    def test_list_certificates_filtering()
    def test_update_certificate()
    
    # Output management
    def test_store_output()
    def test_mark_output_as_spent()
    def test_list_spendable_outputs()
    
    # Transaction storage
    def test_store_transaction()
    def test_retrieve_transaction_by_id()
    def test_get_transaction_labels()
    
    # Key derivation cache
    def test_cache_derived_keys()
    def test_invalidate_cache()
    
    # Action tracking
    def test_track_action_state()
    def test_list_pending_actions()
    
    # Database migrations
    def test_schema_version_handling()
    def test_migration_from_old_format()
```
**Expected:** 62% → 75%+ (gain: ~90 statements)

---

### 12. `bsv/script/interpreter/operations.py` (64% - 747 statements)
**Effort:** VERY HIGH | **Impact:** MASSIVE
**Current:** 747 statements, 232 missing

**Strategy:** Test uncovered opcode operations
```python
# Extend: tests/bsv/script/interpreter/test_operations.py
class TestScriptOperationsExtended:
    # Arithmetic operations
    def test_op_add_sub_mul_div()
    def test_op_mod_operations()
    def test_op_negate_abs()
    def test_arithmetic_overflow()
    
    # Bitwise operations
    def test_op_and_or_xor()
    def test_op_invert()
    def test_op_lshift_rshift()
    
    # Crypto operations
    def test_op_ripemd160()
    def test_op_sha1()
    def test_op_sha256()
    def test_op_hash160_hash256()
    def test_op_checksig_variants()
    
    # Stack operations
    def test_op_2dup_3dup()
    def test_op_2over_2rot()
    def test_op_2swap()
    
    # String operations
    def test_op_cat()
    def test_op_split()
    def test_op_substr()
```
**Expected:** 64% → 80%+ (gain: ~120 statements)

---

### 13. `bsv/wallet/substrates/wallet_wire_transceiver.py` (59% - 365 statements)
**Effort:** HIGH | **Impact:** HIGH
**Current:** 365 statements, 142 missing

```python
# Extend: tests/bsv/wallet/substrates/test_wallet_wire_transceiver.py
class TestWalletWireTransceiverExtended:
    def test_send_request()
    def test_receive_response()
    def test_handle_error_response()
    def test_timeout_handling()
    def test_request_serialization()
    def test_response_deserialization()
    def test_concurrent_requests()
    def test_connection_retry()
```
**Expected:** 59% → 80%+ (gain: ~77 statements)

---

## Priority 4: Serializers (Systematic Coverage)

Complete coverage of remaining serializers (all small-medium files):
- `bsv/wallet/serializer/certificate.py` (60% - 65 statements) → 90%
- `bsv/wallet/serializer/relinquish_certificate.py` (67% - 15 statements) → 95%
- `bsv/wallet/serializer/decrypt.py` (67% - 9 statements) → 100%
- `bsv/wallet/serializer/encrypt.py` (67% - 9 statements) → 100%
- `bsv/wallet/serializer/identity_certificate.py` (68% - 48 statements) → 90%

**Combined Effort:** MEDIUM | **Impact:** MEDIUM (gain: ~60 statements)

---

## Implementation Strategy

### Phase 2A: Quick Wins (Week 1)
**Files:** 1-4 from Priority 1
**Tests:** ~150 new tests
**Expected Gain:** +2-3% overall coverage
**Effort:** 8-12 hours

### Phase 2B: Medium Impact (Week 2)
**Files:** 5-9 from Priority 2
**Tests:** ~200 new tests
**Expected Gain:** +2-3% overall coverage
**Effort:** 12-16 hours

### Phase 2C: High Impact (Week 3-4)
**Files:** 10-13 from Priority 3
**Tests:** ~300 new tests
**Expected Gain:** +4-5% overall coverage
**Effort:** 20-30 hours

### Phase 2D: Serializers (Ongoing)
**Files:** Priority 4 serializers
**Tests:** ~100 new tests
**Expected Gain:** +1% overall coverage
**Effort:** 8-12 hours

---

## Testing Patterns for Phase 2

### 1. Wallet Operation Testing
```python
# Pattern: Mock dependencies, test flow
@pytest.fixture
def mock_wallet_dependencies():
    with patch('bsv.wallet.wallet_impl.KeyDeriver'), \
         patch('bsv.wallet.wallet_impl.LocalKVStore'):
        yield

def test_wallet_operation(mock_wallet_dependencies):
    wallet = WalletImpl(private_key)
    result = wallet.some_operation(args)
    assert result is not None
```

### 2. Serializer Testing
```python
# Pattern: Round-trip + edge cases
@pytest.mark.parametrize("data", [
    minimal_case,
    full_case,
    edge_case_1,
    edge_case_2,
])
def test_serializer_round_trip(data):
    serialized = serialize_func(data)
    deserialized = deserialize_func(serialized)
    assert deserialized == expected_output(data)
```

### 3. Script Operation Testing
```python
# Pattern: Execute operation, verify stack
def test_script_operation():
    stack = Stack()
    stack.push(item1)
    stack.push(item2)
    
    operation(stack, engine)
    
    assert stack.depth() == expected_depth
    assert stack.peek(0) == expected_result
```

### 4. Error Path Testing
```python
# Pattern: Force error conditions
def test_error_handling():
    with pytest.raises(SpecificError, match="expected message"):
        function_under_test(invalid_input)
```

---

## Success Metrics

- **Overall Coverage:** 73% → 80%+ (target: 82%)
- **New Tests:** ~750 tests total in Phase 2
- **Critical Modules:** Wallet (75%+), Script Interpreter (75%+), Serializers (85%+)
- **Zero Coverage Files:** Eliminate all 0% files
- **Low Coverage (<50%):** Reduce from 15 files to <5 files

---

## Notes

1. **`bsv/utils.py` (0% coverage):** This appears to be a deprecated monolithic file. Should be removed or migrated to submodules (already done).

2. **Integration Tests:** Consider adding integration tests for complete workflows:
   - Create transaction → Sign → Broadcast
   - Acquire certificate → Prove → Relinquish
   - Create action → Internalize → Track

3. **Performance Tests:** For cache and keystore operations, add performance benchmarks.

4. **Mutation Testing:** After reaching 80%, consider mutation testing to verify test quality.

