# Fix OP_RETURN Script Parsing - Port to v2.0 Branch

## Description of Changes

This PR ports the critical OP_RETURN parsing bug fix from v1.0.11p to the v2.0 branch (`Ver.2.xxxbetap`). The fix ensures scripts starting with `0x00 6a` (OP_FALSE OP_RETURN) are correctly parsed.

### Bug Fix: OP_RETURN Handling
- **Issue**: Scripts containing `OP_RETURN` (0x6a) were not properly terminating script parsing. When `OP_RETURN` was encountered, the parser continued to parse subsequent bytes as opcodes instead of treating them as data.
- **Fix**: Implemented proper `OP_RETURN` handling following the TypeScript SDK pattern:
  - Added conditional block tracking (`OP_IF`, `OP_NOTIF`, `OP_VERIF`, `OP_VERNOTIF` / `OP_ENDIF`)
  - `OP_RETURN` outside conditional blocks now terminates parsing and treats all remaining bytes as data
  - `OP_RETURN` inside conditional blocks is treated as a normal opcode
- **Impact**: Scripts like `006a0454657374` now correctly parse as 2 chunks instead of 3

### Code Quality Improvements
1. **Reduced Cognitive Complexity**:
   - Extracted `_update_conditional_depth()` helper method (reduces complexity in `_build_chunks()`)
   - Extracted `_handle_op_return()` helper method
   - Extracted `_read_push_data()` helper method
   - All methods now meet SonarQube complexity requirements (≤15)

2. **Code Structure**:
   - Adapted fix to work with v2.0 branch structure (uses `script_bytes` instead of `_bytes`)
   - Maintains backward compatibility with existing v2.0 code

3. **Test Improvements**:
   - Added comprehensive `test_op_return_chunk_parsing()` test that verifies the bug fix
   - Test located in `tests/bsv/script/test_scripts.py` (v2.0 test structure)

## Linked Issues / Tickets

Ports fix from: v1.0.11p branch
Related to: https://github.com/bsv-blockchain/py-sdk/issues/135

## Testing Procedure

### Unit Tests Added
- ✅ **`test_op_return_chunk_parsing()`**: Comprehensive test covering:
  - OP_FALSE OP_RETURN with data (the bug case: `006a0454657374`)
  - OP_RETURN with data (no OP_FALSE prefix)
  - OP_RETURN with no data
  - OP_FALSE OP_RETURN with no data

### Test Results
```bash
pytest tests/bsv/script/test_scripts.py::test_op_return_chunk_parsing -v
# Result: PASSED
```

### Manual Testing
- ✅ Verified fix works with original reproduction script
- ✅ Tested against v2.0.0b1 structure
- ✅ Verified all existing tests still pass
- ✅ Tested edge cases (empty scripts, conditional blocks, etc.)

### Test Coverage
- All OP_RETURN scenarios covered
- Conditional block handling verified
- Backward compatibility confirmed (all existing tests pass)

## Checklist

- ✅ I have performed a self-review of my own code
- ✅ I have made corresponding changes to the documentation (code comments added)
- ✅ My changes generate no new warnings
- ⚠️ I have updated CHANGELOG.md with my changes (pending - should be updated)
- ✅ I have run the linter
  - Black: All files formatted
  - Ruff: All checks passed

## Additional Notes

### Implementation Details
- Follows TypeScript SDK implementation pattern for consistency
- Maintains backward compatibility with v2.0 branch structure
- Properly handles edge cases (malformed conditionals, empty scripts, etc.)
- Ported from v1.0.11p branch with adaptations for v2.0 codebase

### Files Changed
- `bsv/script/script.py`: OP_RETURN fix with helper methods (adapted for v2.0)
- `tests/bsv/script/test_scripts.py`: New test for OP_RETURN chunk parsing

### Code Metrics
- Cognitive complexity reduced in `_build_chunks()` through helper method extraction
- Code follows v2.0 branch conventions and structure

### Branch Information
- **Source Branch**: `Ver.2.xxxbetap` (based on `Ver.2.xxxbate`)
- **Base Branch**: `Ver.2.xxxbate` (v2.0 beta branch)
- **Original Fix**: Ported from `v1.0.11p` branch
