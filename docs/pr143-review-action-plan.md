# PR #143 Code Review Action Plan

> Based on review comment: https://github.com/bsv-blockchain/py-sdk/pull/143#issuecomment-4159659220
> Date: 2026-03-31

## Overview

This plan addresses all issues raised in the PR #143 code review, organized by priority.

---

## 1. [CRITICAL] `is_op_disabled()` unconditionally returns `False` (9.3.1)

**Problem**: `is_op_disabled()` is a `@classmethod` that returns `False` for all opcodes regardless of tx version. This means v1 transactions can execute opcodes (OP_VER, OP_VERIF, OP_VERNOTIF, OP_2MUL, OP_2DIV) that should be disabled pre-Chronicle.

**Fix**: Convert from `@classmethod` to instance method, gate by `self.is_relaxed()` (tx version > 1). For v1 txs, OP_VER, OP_VERIF, OP_VERNOTIF, OP_2MUL, OP_2DIV remain disabled.

**Files**: `bsv/script/spend.py`
**Tests**: Add v1 rejection tests in `tests/bsv/script/test_chronicle_opcodes.py`

---

## 2. [CRITICAL] Add testnet tests for opcode execution in unlocking scripts (9.4.2.1)

**Problem**: All testnet tests execute opcodes in locking scripts only. No testnet verification that v2 malleability relaxation (opcodes in unlocking scripts) is accepted by nodes.

**Fix**: Add testnet test that broadcasts a v2 tx with non-push opcodes (e.g. `OP_1 OP_2 OP_ADD`) in the unlocking script.

**Files**: `tests/bsv/live/test_live_testnet.py`

---

## 3. [MEDIUM] Verify `MAX_SCRIPT_NUMBER_LENGTH` version independence (9.3.2)

**Problem**: `AfterGenesisConfig.max_script_number_length()` returns 32MB for all tx versions. Need to confirm this is spec-correct.

**Action**: The Chronicle spec increases the limit network-wide at activation height, not per-tx-version. After Chronicle activates, ALL transactions (v1 and v2) benefit from 32MB. The version gating only applies to malleability relaxation and opcode restoration. No code change needed — add a comment clarifying this.

**Files**: `bsv/script/interpreter/config.py`

---

## 4. [MEDIUM] Consolidate OTDA routing logic (9.3.4)

**Problem**: FORKID/CHRONICLE routing logic is duplicated in `transaction.py:calc_input_signature_hash()` and `transaction_preimage.py:tx_preimage()`.

**Fix**: Extract a shared helper `use_otda(sighash) -> bool` and call it from both locations.

**Files**: `bsv/transaction.py`, `bsv/transaction_preimage.py`, `bsv/constants.py` (or new helper)

---

## 5. [MEDIUM] Verify NOP4-NOP8 Enum alias resolution (9.3.5)

**Problem**: Python Enum aliases mean `OP_NOP4` and `OP_SUBSTR` share `b"\xb3"`. Need to verify `OPCODE_VALUE_NAME_DICT` and `to_asm()` output the canonical Chronicle names.

**Action**: Already handled — `OPCODE_VALUE_NAME_DICT` explicitly overrides `b"\xb3"` → `"OP_SUBSTR"` etc. Add explicit tests for `to_asm()` output and `from_asm("OP_NOP4")` backward compat.

**Files**: `tests/bsv/script/test_chronicle_constants.py`

---

## 6. [MEDIUM] OP_INVERT bug fix note (9.3.3)

**Problem**: `bytes([~b for b in x])` → `bytes([b ^ 0xFF for b in x])` is correct but unrelated to Chronicle.

**Action**: Add a code comment noting this is an independent bug fix. Backport to a separate PR is out of scope for this branch but should be tracked.

**Files**: `bsv/script/spend.py`

---

## 7. [LOW] Add WhatsonChain clickable links to all broadcast test outputs

**Problem**: Testnet broadcast tests don't output WhatsonChain links for easy tx inspection.

**Fix**: Modify `broadcast_test_tx()` in conftest.py to print a clickable WoC testnet link on successful broadcasts.

**Files**: `tests/bsv/live/conftest.py`

---

## 8. [RECOMMENDED] Add mixed sighash multi-input test (9.4.2.2)

**Problem**: No test mixes BIP143 and OTDA inputs within a single transaction.

**Fix**: Add a mock test with 2 inputs — one using SIGHASH.ALL_FORKID (BIP143) and one using SIGHASH.ALL_FORKID_CHRONICLE (OTDA).

**Files**: `tests/bsv/script/test_chronicle_comprehensive.py`

---

## 9. [RECOMMENDED] Add OP_CODESEPARATOR interaction test (9.4.2.3)

**Problem**: No tests where Chronicle opcodes appear after OP_CODESEPARATOR.

**Fix**: Add mock test with Chronicle opcode after OP_CODESEPARATOR.

**Files**: `tests/bsv/script/test_chronicle_comprehensive.py`

---

## 10. [RECOMMENDED] Add Chronicle opcodes in unlocking script test (9.4.2.4)

**Problem**: Mock test `test_v2_opcodes_in_unlocking` only uses OP_ADD. No test uses Chronicle-specific opcodes in unlocking scripts.

**Fix**: Add mock tests using OP_2MUL, OP_SUBSTR, OP_LSHIFTNUM in unlocking scripts.

**Files**: `tests/bsv/script/test_chronicle_comprehensive.py`

---

## Execution Order

1. Fix `is_op_disabled()` + add v1 rejection tests (Critical)
2. Add WoC links to broadcast_test_tx (Low effort, high visibility)
3. Consolidate OTDA routing logic (Medium)
4. Verify/test NOP4-NOP8 alias resolution (Medium)
5. Add OP_INVERT comment (Low)
6. Clarify MAX_SCRIPT_NUMBER_LENGTH comment (Low)
7. Add unlocking script opcode testnet test (Critical test gap)
8. Add mixed sighash multi-input test (Recommended)
9. Add OP_CODESEPARATOR interaction test (Recommended)
10. Add Chronicle opcodes in unlocking script mock tests (Recommended)
