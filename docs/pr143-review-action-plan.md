# PR #143 Code Review Action Plan

> Based on review comment: https://github.com/bsv-blockchain/py-sdk/pull/143#issuecomment-4159659220
> Date: 2026-03-31

## Overview

This plan addresses all issues raised in the PR #143 code review, organized by priority.
All items have been resolved as of 2026-03-31.

---

## 1. [RESOLVED] `is_op_disabled()` unconditionally returns `False` (9.3.1)

**Reviewer concern**: `is_op_disabled()` returns `False` for all opcodes regardless of tx version.

**Resolution**: This is **intentionally correct**. After Chronicle activation, NO opcodes are disabled for ANY tx version. Opcode restoration is network-wide at the activation block height, not gated by tx version. Only malleability restrictions (clean stack, push-only unlocking, etc.) are version-gated via `is_relaxed()` (tx version > 1). Added comprehensive docstring to `is_op_disabled()` clarifying this design.

**Commit**: `ee17084` - docs(spend): clarify is_op_disabled() is intentionally network-wide

---

## 2. [RESOLVED] Add testnet tests for opcode execution in unlocking scripts (9.4.2.1)

**Fix**: Added `TestTestnetUnlockingOpcodes` class with two tests:
- `test_v2_add_in_unlocking`: OP_1 OP_2 OP_ADD in unlocking script
- `test_v2_2mul_in_unlocking`: Chronicle OP_2MUL in unlocking script

**Commit**: `802d795` - test(live): add v2 unlocking script opcode testnet tests

---

## 3. [RESOLVED] Verify `MAX_SCRIPT_NUMBER_LENGTH` version independence (9.3.2)

**Resolution**: The 32MB limit is network-wide at activation height, not per-tx-version. Added clarifying comment to `AfterGenesisConfig.max_script_number_length()`.

**Commit**: `a76eb27` - docs: clarify OP_INVERT fix and MAX_SCRIPT_NUMBER_LENGTH scope

---

## 4. [RESOLVED] Consolidate OTDA routing logic (9.3.4)

**Fix**: Extracted `SIGHASH.use_otda(sighash)` static method in `constants.py`. Both `transaction.py:calc_input_signature_hash()` and `transaction_preimage.py:tx_preimage()` now call this single method.

**Commit**: `406fcff` - refactor: consolidate OTDA routing logic into SIGHASH.use_otda()

---

## 5. [RESOLVED] Verify NOP4-NOP8 Enum alias resolution (9.3.5)

**Resolution**: Already correctly implemented. `OPCODE_VALUE_NAME_DICT` explicitly maps `b"\xb3"` -> `"OP_SUBSTR"` etc. Added explicit test `test_to_asm_outputs_chronicle_names_not_nop` verifying that `from_asm("OP_NOP4").to_asm()` returns `"OP_SUBSTR"`.

**Commit**: `e89a47d` - test: add to_asm() NOP->Chronicle name verification test

---

## 6. [RESOLVED] OP_INVERT bug fix note (9.3.3)

**Fix**: Added code comment noting `~b -> b ^ 0xFF` is an independent Python bug fix unrelated to Chronicle.

**Commit**: `a76eb27` - docs: clarify OP_INVERT fix and MAX_SCRIPT_NUMBER_LENGTH scope

---

## 7. [RESOLVED] Add WhatsonChain clickable links to all broadcast test outputs

**Fix**: `broadcast_test_tx()` and `fan_out()` in conftest.py now print clickable WoC testnet links:
```
  -> https://test.whatsonchain.com/tx/{txid}
```

**Commit**: `1f767dc` - feat(tests): add WhatsonChain clickable links to all broadcast tests

---

## 8. [RESOLVED] Add mixed sighash multi-input test (9.4.2.2)

**Fix**: Added `TestMixedSighash.test_mixed_bip143_and_otda_inputs` — a transaction with one BIP143 input (ALL_FORKID) and one OTDA input (ALL_FORKID_CHRONICLE), both validated via Spend.

**Commit**: `ef2dfb7` - test: add mixed BIP143/OTDA sighash multi-input test

---

## 9. [RESOLVED] Add OP_CODESEPARATOR interaction test (9.4.2.3)

**Fix**: Added `TestCodeSeparatorWithChronicle` with tests for OP_2MUL, OP_SUBSTR, and OP_LSHIFTNUM executing after OP_CODESEPARATOR.

**Commit**: `6aa8229` - test: add OP_CODESEPARATOR + Chronicle opcode interaction tests

---

## 10. [RESOLVED] Add Chronicle opcodes in unlocking script test (9.4.2.4)

**Fix**: Added `TestChronicleOpcodesInUnlocking` with tests for OP_2MUL, OP_2DIV, OP_LSHIFTNUM, OP_RSHIFTNUM, and OP_SUBSTR in unlocking scripts of v2 transactions.

**Commit**: `1714f8e` - test: add Chronicle opcodes in unlocking script mock tests

---

## Items NOT addressed (out of scope for this branch)

- **9.3.6 SonarQube 0% coverage**: CI configuration issue, not a code problem
- **9.3.7 Squash 30 commits**: Will be done at merge time via squash merge
- **9.3.3 OP_INVERT backport**: Separate PR needed for backporting to existing versions
