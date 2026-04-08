# Cross-Configuration Chronicle Tests

## Context

Current Chronicle tests cover each configuration axis in isolation (sighash matrix, version matrix, malleability, opcodes), but never test **transitions between configurations** — e.g., a v1 output spent by a v2 tx, or a tx with one BIP143 input and one OTDA input. The user wants to verify the SDK safely handles all cross-configuration scenarios, not just "older to new" but also "new to old" and mixed within a single tx.

## Key Insight: What Determines Behavior

- **Preimage algorithm**: determined per-input by the sighash byte (`SIGHASH.use_otda()`)
- **Malleability rules**: determined by the **spending** tx version (`is_relaxed()` = `tx_version > 1`)
- **Chronicle opcodes**: network-wide, not version-gated
- **Source tx version**: does NOT affect spending behavior

This means the source tx version should be irrelevant — but we need tests to prove it.

## Plan

### 1. Modify `conftest.py`

- Add `version` parameter to `build_funding_tx()` (default 1, backwards-compatible)
- Add new helper `build_cross_config_tx()` that accepts per-input `(lock, unlock, sighash)` configs + separate `funding_version` and `spending_version`

### 2. Create `tests/bsv/live/test_live_cross_config.py` (6 test classes)

**Class 1: `TestVersionTransitions`** — P2PKH with funding_version != spending_version
- v1→v2 with BIP143, v1→v2 with OTDA, v2→v1 with BIP143, v2→v1 with OTDA
- Also P2PK and multisig variants

**Class 2: `TestSighashTransitions`** — Setup tx signed with one sighash, spend with another
- BIP143 setup → OTDA spend (v2), OTDA setup → BIP143 spend (v1)
- Proves outputs are sighash-agnostic

**Class 3: `TestMixedInputSighash`** — Single tx with inputs using different sighash flags
- Input 0 = ALL_FORKID (BIP143), Input 1 = ALL_FORKID_CHRONICLE (OTDA), same tx
- Also NONE, SINGLE, ANYONECANPAY mixes
- Three-input variant: ALL_FORKID + ALL_FORKID_CHRONICLE + NONE_FORKID_CHRONICLE

**Class 4: `TestMixedInputSources`** — Single tx spending inputs from different-versioned source txs
- Input from v1 source + input from v2 source, in v1 and v2 spending txs

**Class 5: `TestVersionMalleabilityInteractions`** — Malleability enforcement depends on spending tx version, NOT source version
- v1 source → v2 spend: dirty stack, non-minimal push, NOP in unlock → all PASS (relaxed)
- v2 source → v1 spend: dirty stack, non-minimal push, NOP in unlock → all FAIL (strict)
- This is the most critical class — proves `is_relaxed()` is source-independent

**Class 6: `TestVersionOpcodeInteractions`** — Chronicle opcodes with "unnatural" pairings
- OP_2MUL with BIP143+v2 (not just OTDA+v2)
- OP_VER with OTDA+v1 (not just BIP143+v1)
- OP_SUBSTR with OTDA+v1
- Proves opcodes are truly version-independent

### 3. Add testnet variants in `test_live_testnet.py`

- `TestTestnetCrossConfig` class with representative subset:
  - v1→v2 and v2→v1 P2PKH transitions
  - Mixed BIP143+OTDA input tx
  - v2 spend with non-push unlocking from v1 source (via WoC broadcaster)
- Parameterize `build_two_step_testnet_tx` to accept `setup_version`
- Bump `TOTAL_TEST_UTXOS` by ~20

### Files to Modify
- `tests/bsv/live/conftest.py` — add `version` param to `build_funding_tx`, add `build_cross_config_tx`
- `tests/bsv/live/test_live_cross_config.py` — **new file**, 6 test classes
- `tests/bsv/live/test_live_testnet.py` — add `TestTestnetCrossConfig`, bump UTXO count

### Verification
```bash
# Run mock cross-config tests (fast, no network)
pytest tests/bsv/live/test_live_cross_config.py -v

# Run testnet cross-config tests (requires FUNDED_TESTNET_WIF)
pytest tests/bsv/live/test_live_testnet.py::TestTestnetCrossConfig -v -m testnet
```
