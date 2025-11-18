# Plan: Fix Transaction.verify() for Script Verification

## Executive Summary

The `Transaction.verify()` method already exists but is using an outdated `Spend` class for script validation. The codebase has a newer, more robust `Engine`-based script interpreter that should be used instead. This plan outlines the steps to migrate the verification logic to use the modern interpreter.

## Current State

### What Exists
1. **Transaction.verify()** (line 396 in `transaction.py`):
   - Accepts `chaintracker` and `scripts_only` parameters
   - Currently uses `Spend.validate()` for script verification
   - Has logic for merkle proof validation
   - Recursively verifies source transactions

2. **Spend class** (`bsv/script/spend.py`):
   - Older-style script interpreter
   - Has its own stack management and opcode execution
   - Used by current Transaction.verify()
   - Known issues with certain script types

3. **Engine-based interpreter** (`bsv/script/interpreter/`):
   - Modern, robust script interpreter
   - Successfully used in test_checksig.py tests
   - Matches Go/TS SDK implementations
   - Properly handles all opcodes including OP_CHECKSIG

### The Problem

When `Transaction.verify()` is called with valid scripts, it returns `False` because:
1. The `Spend` class may not correctly handle modern script validation
2. It doesn't properly integrate with the transaction context
3. The newer `Engine` interpreter is more accurate and well-tested

## Implementation Plan

### Phase 1: Understand Current Behavior (Investigation)

**Task 1.1: Debug Spend.validate() failure**
- Create a test script to understand why Spend.validate() returns False
- Compare stack state with expected behavior
- Identify specific failure point in script execution

**Files to investigate:**
- `bsv/script/spend.py` (Spend.validate method)
- Test with simple P2PKH transaction

**Expected outcome:** Clear understanding of why current implementation fails

---

### Phase 2: Update Transaction.verify() Implementation

**Task 2.1: Replace Spend with Engine-based verification**

**Location:** `bsv/transaction.py`, lines 424-440

**Current code:**
```python
spend = Spend({
    'sourceTXID': tx_input.source_transaction.txid(),
    'sourceOutputIndex': tx_input.source_output_index,
    'sourceSatoshis': source_output.satoshis,
    'lockingScript': source_output.locking_script,
    'transactionVersion': self.version,
    'otherInputs': other_inputs,
    'inputIndex': i,
    'unlockingScript': tx_input.unlocking_script,
    'outputs': self.outputs,
    'inputSequence': tx_input.sequence,
    'lockTime': self.locktime,
})
spend_valid = spend.validate()
if not spend_valid:
    return False
```

**New implementation:**
```python
# Use Engine-based script interpreter
from bsv.script.interpreter import Engine, with_tx, with_after_genesis, with_fork_id

engine = Engine()
err = engine.execute(
    with_tx(self, i, source_output),
    with_after_genesis(),
    with_fork_id()
)

if err is not None:
    # Script verification failed
    return False
```

**Rationale:**
- Engine is the modern, well-tested interpreter
- Already used successfully in test_checksig.py
- Properly handles transaction context via with_tx()
- Matches Go/TS SDK behavior

---

**Task 2.2: Add proper error handling**

**Enhancement:** Add optional error reporting

```python
async def verify(
    self, 
    chaintracker: Optional[ChainTracker] = default_chain_tracker(), 
    scripts_only: bool = False,
    return_errors: bool = False  # New parameter
) -> Union[bool, Tuple[bool, Optional[List[str]]]]:
    """
    Verify transaction validity.
    
    Args:
        chaintracker: Chain tracker for merkle proof validation
        scripts_only: If True, skip merkle proof verification
        return_errors: If True, return (result, error_list) tuple
    
    Returns:
        bool if return_errors=False, else (bool, Optional[List[str]])
    """
    errors = [] if return_errors else None
    
    # ... existing code ...
    
    err = engine.execute(...)
    if err is not None:
        if return_errors:
            errors.append(f"Input {i} script verification failed: {err.message}")
        return (False, errors) if return_errors else False
    
    # ... rest of code ...
    
    return (True, None) if return_errors else True
```

---

**Task 2.3: Handle edge cases**

**Cases to handle:**
1. Empty inputs (coinbase transactions)
2. Missing source transactions (should raise ValueError - already done)
3. Missing unlocking scripts (should raise ValueError - already done)
4. Recursive verification depth limit
5. Genesis vs post-genesis transactions

**Implementation:**
```python
# Add depth tracking to prevent infinite recursion
async def verify(
    self, 
    chaintracker: Optional[ChainTracker] = default_chain_tracker(), 
    scripts_only: bool = False,
    _depth: int = 0,  # Internal parameter
    _max_depth: int = 100  # Prevent infinite recursion
) -> bool:
    if _depth > _max_depth:
        raise ValueError(f"Transaction verification depth exceeded {_max_depth}")
    
    # ... existing code ...
    
    # When recursively verifying source transactions:
    input_verified = await tx_input.source_transaction.verify(
        chaintracker, 
        scripts_only=scripts_only,
        _depth=_depth + 1,
        _max_depth=_max_depth
    )
```

---

### Phase 3: Testing

**Task 3.1: Unit tests for Transaction.verify()**

Create/update tests in `tests/bsv/transaction/test_transaction_verify.py`:

```python
import pytest
from bsv.transaction import Transaction, TransactionInput, TransactionOutput
from bsv.keys import PrivateKey
from bsv.script.type import P2PKH
from bsv.spv import GullibleHeadersClient

@pytest.mark.asyncio
async def test_verify_valid_p2pkh():
    """Test verification of valid P2PKH transaction"""
    priv_key = PrivateKey()
    address = priv_key.address()
    
    # Create source transaction
    source_tx = Transaction([], [
        TransactionOutput(P2PKH().lock(address), 1000)
    ])
    
    # Create spending transaction
    tx = Transaction(
        [TransactionInput(
            source_transaction=source_tx,
            source_output_index=0,
            unlocking_script_template=P2PKH().unlock(priv_key)
        )],
        [TransactionOutput(P2PKH().lock(address), 500)]
    )
    
    tx.sign()
    
    # Verify with scripts_only=True
    chaintracker = GullibleHeadersClient()
    result = await tx.verify(chaintracker, scripts_only=True)
    
    assert result is True

@pytest.mark.asyncio
async def test_verify_invalid_signature():
    """Test verification rejects invalid signature"""
    priv_key = PrivateKey()
    wrong_key = PrivateKey()
    address = priv_key.address()
    
    source_tx = Transaction([], [
        TransactionOutput(P2PKH().lock(address), 1000)
    ])
    
    # Sign with wrong key
    tx = Transaction(
        [TransactionInput(
            source_transaction=source_tx,
            source_output_index=0,
            unlocking_script_template=P2PKH().unlock(wrong_key)
        )],
        [TransactionOutput(P2PKH().lock(address), 500)]
    )
    
    tx.sign()
    
    chaintracker = GullibleHeadersClient()
    result = await tx.verify(chaintracker, scripts_only=True)
    
    assert result is False

@pytest.mark.asyncio
async def test_verify_missing_source_transaction():
    """Test verification raises error for missing source"""
    priv_key = PrivateKey()
    address = priv_key.address()
    
    tx = Transaction(
        [TransactionInput(
            source_txid="0" * 64,
            source_output_index=0,
            unlocking_script_template=P2PKH().unlock(priv_key)
        )],
        [TransactionOutput(P2PKH().lock(address), 500)]
    )
    
    chaintracker = GullibleHeadersClient()
    
    with pytest.raises(ValueError, match="missing an associated source transaction"):
        await tx.verify(chaintracker, scripts_only=True)
```

**Task 3.2: Enable skipped tests**

Update `tests/bsv/spv/test_verify_scripts.py`:
- Remove `pytest.skip()` calls from:
  - `test_verify_scripts_skips_merkle_proof`
  - `test_verify_scripts_with_invalid_script`
- Run tests to verify they pass

**Task 3.3: Integration testing**

Run full test suite:
```bash
cd py-sdk
python -m pytest tests/bsv/spv/test_verify_scripts.py -v
python -m pytest tests/bsv/transaction/ -k verify -v
python -m pytest tests/bsv/script/interpreter/test_checksig.py -v
```

All tests should pass.

---

### Phase 4: Documentation and Cleanup

**Task 4.1: Update docstrings**

Ensure `Transaction.verify()` has comprehensive documentation:
- Parameter descriptions
- Return value explanation
- Example usage
- Performance considerations
- Security warnings

**Task 4.2: Consider deprecating Spend class**

The `Spend` class may no longer be needed if verification is fully migrated to Engine:
- Search codebase for other uses of Spend
- If only used in Transaction.verify(), mark as deprecated
- Add deprecation warning
- Plan removal for future version

**Task 4.3: Update CHANGELOG**

Document the change:
```markdown
### Fixed
- Transaction.verify() now uses modern Engine-based script interpreter
- Script verification is now more accurate and matches Go/TS SDK behavior
- Fixed false negatives in script verification for valid transactions

### Changed
- Transaction.verify() implementation migrated from Spend to Engine

### Deprecated
- Spend class is deprecated and will be removed in a future version
```

---

## Success Criteria

1. ✅ `Transaction.verify()` correctly returns `True` for valid transactions
2. ✅ `Transaction.verify()` correctly returns `False` for invalid signatures
3. ✅ `Transaction.verify()` raises ValueError for missing source transactions
4. ✅ All tests in `test_verify_scripts.py` pass (no skips)
5. ✅ All tests in `test_checksig.py` still pass
6. ✅ No regressions in existing test suite

## Risk Assessment

### Low Risk
- Using Engine is already proven in test_checksig.py
- Changes are isolated to Transaction.verify() method
- Existing tests will catch regressions

### Medium Risk
- Performance impact (Engine might be slower/faster than Spend)
  - **Mitigation:** Benchmark before/after
  - **Mitigation:** Optimize if needed

### Potential Issues
1. **Recursive verification of source transactions**
   - Current code recursively calls verify() on source transactions
   - Could hit recursion limits or be slow
   - **Solution:** Add depth tracking (Task 2.3)

2. **Backward compatibility**
   - Some code might depend on Spend class
   - **Solution:** Search codebase first (Task 4.2)

3. **Edge cases not covered by current tests**
   - Complex scripts (multisig, P2SH, etc.)
   - **Solution:** Add comprehensive test suite

## Timeline Estimate

- **Phase 1 (Investigation):** 30 minutes
- **Phase 2 (Implementation):** 2-3 hours
- **Phase 3 (Testing):** 1-2 hours
- **Phase 4 (Documentation):** 30 minutes

**Total:** 4-6 hours

## Dependencies

- ✅ Engine-based interpreter (already implemented)
- ✅ test_checksig.py tests (already passing)
- ✅ GullibleHeadersClient (already implemented)

## Next Steps

1. Mark Task 1.1 as in-progress
2. Create debug script to understand Spend.validate() failure
3. Implement Transaction.verify() changes
4. Run tests
5. Enable skipped tests
6. Update documentation

---

## References

- **Engine implementation:** `bsv/script/interpreter/engine.py`
- **Current Transaction.verify():** `bsv/transaction.py:396-448`
- **Spend class:** `bsv/script/spend.py`
- **Test examples:** `tests/bsv/script/interpreter/test_checksig.py`
- **verify_scripts function:** `bsv/spv/verify.py`

