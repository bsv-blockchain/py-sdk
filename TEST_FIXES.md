# Test Fixes - Corrected Overzealous Replacements

## Issue
During automated unused variable fixing, some method/variable names were incorrectly replaced with `_`.

## Failures Fixed (7 tests)

### 1. WalletWireResolver.query method
**File**: `bsv/registry/resolver.py:49`  
**Error**: `AttributeError: 'WalletWireResolver' object has no attribute 'query'`  
**Problem**: Method name `query` was replaced with `_`  
**Fix**: Restored method name to `query`

```python
# Before (broken)
def _(self, ctx: Any, definition_type: DefinitionType, query: Dict[str, Any] = None) -> List[Dict[str, Any]]:

# After (fixed)
def query(self, ctx: Any, definition_type: DefinitionType, query: Dict[str, Any] = None) -> List[Dict[str, Any]]:
```

### 2. PublicKey.address() method
**File**: `tests/bsv/script/test_p2pkh_template.py:64`  
**Error**: `AttributeError: 'PublicKey' object has no attribute '_'`  
**Problem**: Method call `address()` was replaced with `_()`  
**Fix**: Restored method call to `address()`

```python
# Before (broken)
_ = public_key._()

# After (fixed)
_ = public_key.address()
```

### 3. PrivateKey.address() method
**File**: `tests/bsv/script/test_scripts.py:272`  
**Error**: `AttributeError: 'PrivateKey' object has no attribute '_'`  
**Problem**: Method call `address()` was replaced with `_()`  
**Fix**: Restored method call to `address()`

```python
# Before (broken)
_ = private_key._()

# After (fixed)
_ = private_key.address()
```

### 4. input_total variable
**File**: `bsv/transaction.py:411`  
**Error**: `UnboundLocalError: cannot access local variable 'input_total' where it is not associated with a value`  
**Problem**: Variable name `input_total` was replaced with `_`, but it was still referenced later  
**Fix**: Restored variable name to `input_total`

**Affected tests** (4 tests):
- `tests/bsv/spv/test_verify_scripts.py::TestVerifyScripts::test_verify_scripts_skips_merkle_proof`
- `tests/bsv/spv/test_verify_scripts.py::TestVerifyScripts::test_verify_scripts_with_invalid_script`
- `tests/bsv/transaction/test_transaction_verify.py::TestTransactionVerify::test_verify_simple_p2pkh_transaction`
- `tests/bsv/transaction/test_transaction_verify.py::TestTransactionVerify::test_verify_rejects_invalid_signature`

```python
# Before (broken)
_ = 0
for i, tx_input in enumerate(self.inputs):
    ...
    input_total += source_output.satoshis  # Error: input_total not defined

# After (fixed)
input_total = 0
for i, tx_input in enumerate(self.inputs):
    ...
    input_total += source_output.satoshis  # Works correctly
```

## Root Cause
The automated script that replaced unused variables with `_` was too aggressive and didn't properly detect:
1. Method names that should not be replaced
2. Variables that are assigned to `_` but are still used elsewhere in the code

## Prevention
For future automated fixes:
1. Always check if a variable/method name is referenced elsewhere before replacing
2. Never replace method definitions or method calls
3. Only replace true unused local variables
4. Test after batch replacements

## Verification
All 7 tests now pass:
```
✅ tests/bsv/registry/test_registry_client.py::TestRegistryClient::test_walletwire_resolver_filters
✅ tests/bsv/script/test_p2pkh_template.py::TestP2PKHTemplate::test_should_estimate_unlocking_script_length
✅ tests/bsv/script/test_scripts.py::test_r_puzzle
✅ tests/bsv/spv/test_verify_scripts.py::TestVerifyScripts::test_verify_scripts_skips_merkle_proof
✅ tests/bsv/spv/test_verify_scripts.py::TestVerifyScripts::test_verify_scripts_with_invalid_script
✅ tests/bsv/transaction/test_transaction_verify.py::TestTransactionVerify::test_verify_simple_p2pkh_transaction
✅ tests/bsv/transaction/test_transaction_verify.py::TestTransactionVerify::test_verify_rejects_invalid_signature
```

