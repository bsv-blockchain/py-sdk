# Python SDK Coverage Improvement Plan

**Current Coverage:** 66% (14,833/22,314 statements covered)
**Target:** 75%+ (additional ~2,000 statements to cover)

## Executive Summary

This plan focuses on increasing test coverage by targeting files with the lowest coverage first, as they offer the biggest impact. The strategy includes:
1. **Negative testing** - Test error conditions, edge cases, and invalid inputs
2. **Mutation testing** - Variations of existing tests with different parameters
3. **Branch coverage** - Ensure all conditional paths are tested

## Priority 1: Zero Coverage Files (1,289 statements - HIGH IMPACT)

### 1. `bsv/utils.py` (0% coverage - 357 statements)
**Impact:** Critical utility file with many helper functions

**Missing Coverage:**
- `unsigned_to_varint()` / `varint_to_unsigned()` - varint encoding/decoding
- `hex_to_bytes()` / `bytes_to_hex()` - hex conversions
- `encode_pushdrop_token()` / `decode_pushdrop_token()` - token operations
- Transaction utility functions
- Script utility functions

**Test Strategy:**
```python
# New test file: tests/bsv/test_utils_legacy.py
- Test varint encoding/decoding with edge cases (0, 1, 252, 253, 65535, 65536, max values)
- Test hex conversions with invalid inputs (odd length, non-hex chars)
- Test pushdrop token operations with various token structures
- Test transaction utilities with malformed data
- Negative tests: None inputs, empty bytes, oversized values
```

### 2. `bsv/auth/peer_clean.py` (0% coverage - 932 statements)
**Impact:** Large authentication module, likely alternative implementation

**Note:** This file appears to be an alternative/legacy implementation of peer functionality. 
- Review if this file should be removed or if it's actively used
- If used, create comprehensive peer authentication tests
- If legacy, mark for deprecation and exclude from coverage

**Test Strategy:**
- Determine file status (active/legacy/deprecated)
- If active: Create `tests/bsv/auth/test_peer_clean.py` with peer lifecycle tests
- If legacy: Add to `.coveragerc` exclude list

## Priority 2: Very Low Coverage (< 20%, 592 statements)

### 3. `bsv/wallet/serializer/list_outputs.py` (4% - 114 statements)
**Current:** Only imports tested
**Missing:** All serialization/deserialization logic

**Test Strategy:**
```python
# Extend: tests/bsv/wallet/test_serializer.py
class TestListOutputsSerialization:
    def test_serialize_list_outputs_args_minimal():
        # Test with minimal valid args
        
    def test_serialize_list_outputs_args_with_basket():
        # Test with basket parameter
        
    def test_serialize_list_outputs_args_with_tags():
        # Test with tags list
        
    def test_serialize_list_outputs_args_with_all_options():
        # Test with all optional parameters
        
    def test_deserialize_list_outputs_result():
        # Test deserialization of valid result
        
    def test_deserialize_list_outputs_result_empty():
        # Test with empty output list
        
    def test_deserialize_list_outputs_result_multiple():
        # Test with multiple outputs
        
    # Negative tests
    def test_serialize_invalid_tags_type():
        # Test with non-list tags
        
    def test_deserialize_corrupted_data():
        # Test with malformed binary data
```

### 4. `bsv/identity/client.py` (13% - 172 statements)
**Current:** Only basic initialization tested
**Missing:** All client methods (authenticate, get_identity, resolve, etc.)

**Test Strategy:**
```python
# Extend: tests/bsv/identity/test_identity_client.py
class TestIdentityClientMethods:
    def test_authenticate_with_valid_credentials():
    def test_authenticate_with_invalid_credentials():
    def test_get_identity_by_key():
    def test_get_identity_not_found():
    def test_resolve_identity_by_handle():
    def test_resolve_identity_invalid_handle():
    def test_create_identity():
    def test_update_identity():
    
    # Edge cases
    def test_operations_with_none_wallet():
    def test_operations_with_expired_session():
    def test_concurrent_operations():
    
    # Negative tests
    def test_network_timeout():
    def test_malformed_response():
    def test_invalid_certificate():
```

### 5. `bsv/wallet/cached_key_deriver.py` (21% - 61 statements)
**Test Strategy:**
```python
# New: tests/bsv/wallet/test_cached_key_deriver.py
class TestCachedKeyDeriver:
    def test_cache_hit():
    def test_cache_miss():
    def test_cache_eviction():
    def test_cache_size_limit():
    def test_derive_child_key_cached():
    def test_derive_multiple_keys_cache_efficiency():
    
    # Negative tests
    def test_invalid_derivation_path():
    def test_cache_with_corrupted_data():
```

## Priority 3: Low Coverage (20-40%, 1,095 statements)

### 6. `bsv/script/interpreter/opcode_parser.py` (31% - 57 statements)
**Test Strategy:**
```python
# Extend: tests/bsv/script/interpreter/test_opcode_parser.py
- Test all opcode parsing variations
- Test with invalid opcode sequences
- Test boundary conditions (OP_0 to OP_16, OP_1NEGATE)
- Test PUSHDATA1, PUSHDATA2, PUSHDATA4 variants
```

### 7. `bsv/utils/binary.py` (31% - 67 statements)
**Test Strategy:**
```python
# Extend: tests/bsv/test_utils_coverage.py
class TestBinaryOperations:
    def test_int_to_bytes_various_sizes():
    def test_bytes_to_int_signed_unsigned():
    def test_bit_operations():
    def test_byte_reversal():
    
    # Edge cases
    def test_zero_value_conversions():
    def test_max_value_conversions():
    def test_negative_numbers():
```

### 8. `bsv/wallet/serializer/relinquish_output.py` (33% - 18 statements)
### 9. `bsv/auth/requested_certificate_set.py` (35% - 76 statements)
### 10. `bsv/wallet/serializer/get_network.py` (35% - 43 statements)
### 11. `bsv/overlay_tools/overlay_admin_token_template.py` (35% - 57 statements)
### 12. `bsv/utils/reader_writer.py` (39% - 114 statements)
### 13. `bsv/auth/clients/auth_fetch.py` (41% - 395 statements)

**Consolidated Test Strategy:**
- Create dedicated test files for each module
- Focus on serialization/deserialization round-trips
- Test with mock network responses
- Test error handling and edge cases

## Priority 4: Medium Coverage (40-60%, 1,043 statements)

### Notable Files:
- `bsv/script/interpreter/stack.py` (46% - 141 statements)
- `bsv/wallet/serializer/acquire_certificate.py` (48% - 78 statements)
- `bsv/overlay_tools/ship_broadcaster.py` (49% - 163 statements)
- `bsv/primitives/aescbc.py` (52% - 57 statements)
- `bsv/utils/script_chunks.py` (57% - 57 statements)
- `bsv/wallet/substrates/serializer.py` (57% - 334 statements)

**Test Strategy:**
- Add comprehensive branch coverage tests
- Test alternative execution paths
- Mock external dependencies
- Add integration tests for complex workflows

## Testing Patterns to Apply

### 1. Negative Testing
```python
def test_function_with_none_input():
    with pytest.raises(ValueError):
        function_under_test(None)

def test_function_with_empty_input():
    with pytest.raises(ValueError):
        function_under_test("")

def test_function_with_invalid_type():
    with pytest.raises(TypeError):
        function_under_test(123)  # expects str
```

### 2. Boundary Testing
```python
def test_function_with_zero():
def test_function_with_min_value():
def test_function_with_max_value():
def test_function_with_overflow():
```

### 3. State Mutation Testing
```python
def test_function_modifies_state_correctly():
def test_function_preserves_immutability():
def test_function_with_concurrent_modifications():
```

### 4. Error Path Testing
```python
@patch('module.external_call')
def test_function_handles_network_error(mock_call):
    mock_call.side_effect = ConnectionError()
    with pytest.raises(NetworkError):
        function_under_test()
```

### 5. Parametrized Testing
```python
@pytest.mark.parametrize("input,expected", [
    (0, "zero"),
    (1, "one"),
    (-1, "negative"),
    (999999, "large"),
])
def test_function_with_various_inputs(input, expected):
    assert function_under_test(input) == expected
```

## Implementation Roadmap

### Phase 1 (Week 1): Quick Wins - Target 70%
1. Fix `bsv/utils.py` (0% → 80%): +286 statements
2. Fix `bsv/wallet/serializer/list_outputs.py` (4% → 80%): +86 statements
3. Fix `bsv/utils/binary.py` (31% → 80%): +33 statements
4. Fix `bsv/utils/reader_writer.py` (39% → 80%): +47 statements

**Expected Result:** 66% → 70% (+452 statements)

### Phase 2 (Week 2): Medium Impact - Target 73%
5. Fix `bsv/identity/client.py` (13% → 70%): +131 statements
6. Fix `bsv/auth/clients/auth_fetch.py` (41% → 65%): +95 statements
7. Fix `bsv/wallet/cached_key_deriver.py` (21% → 70%): +30 statements
8. Fix `bsv/script/interpreter/opcode_parser.py` (31% → 70%): +22 statements

**Expected Result:** 70% → 73% (+278 statements)

### Phase 3 (Week 3): Comprehensive Coverage - Target 76%
9. Medium coverage files (40-60% → 75%+)
10. Add integration tests for complex workflows
11. Add stress tests for critical paths

**Expected Result:** 73% → 76% (+700 statements)

### Phase 4 (Ongoing): Maintenance
- Review and classify `peer_clean.py` status
- Improve branch coverage on high-coverage files
- Add regression tests for bug fixes
- Monitor coverage on new code

## Success Metrics

1. **Coverage Increase:** 66% → 75%+ (Target: 17,000+ statements covered)
2. **Test Count:** +200-300 new test cases
3. **Branch Coverage:** Increase from 76% to 82%+
4. **Zero Coverage Files:** Reduce from 2 to 0 (excluding deprecated)

## Tools and Commands

### Run tests with coverage:
```bash
cd /home/sneakyfox/SDK/py-sdk
pytest --cov=bsv --cov-report=html --cov-report=term
```

### Generate coverage report:
```bash
coverage html
open htmlcov/index.html
```

### Run specific test files:
```bash
pytest tests/bsv/test_utils_coverage.py -v
pytest tests/bsv/wallet/test_serializer.py -v
```

### Check branch coverage:
```bash
pytest --cov=bsv --cov-branch --cov-report=term-missing
```

## Notes

1. **Mocking Strategy:** Use `unittest.mock` or `pytest-mock` for external dependencies
2. **Test Data:** Create fixtures in `tests/fixtures/` for reusable test data
3. **Performance:** Keep tests fast; use mocks for slow operations
4. **Maintenance:** Document complex test scenarios
5. **CI/CD:** Ensure all tests pass in CI before merging

## Risk Mitigation

1. **Breaking Changes:** All tests must be backward compatible
2. **Performance:** New tests should not significantly slow down test suite
3. **Dependencies:** Minimize new test dependencies
4. **Flaky Tests:** Avoid tests that depend on timing or external state
5. **Coverage Gaming:** Focus on meaningful tests, not just line coverage

---

**Document Version:** 1.0
**Created:** 2024-11-18
**Last Updated:** 2024-11-18
**Owner:** Test Coverage Improvement Initiative

