# Chronicle Update — TDD Implementation Plan

## Context

The Chronicle Update is a BSV network upgrade (MainNet target: 07-Apr-2026, block 943,816). This plan implements all required py-sdk changes using strict TDD: for each step, write failing tests first, then implement to make them pass, then commit and push.

Full spec: `CHRONICLE_ROADMAP.md` in repo root. Reference impl: TS-SDK v2.0.0+.

---

## Step 1: Script number size limit (750KB → 32MB)

**Tests** — `tests/bsv/script/interpreter/test_chronicle_number_limit.py`:
- `test_max_script_number_length_after_genesis_is_32mb`
- `test_before_genesis_limit_unchanged` (regression)

**Impl** — `bsv/script/interpreter/config.py:93`:
- Change `750 * 1000` → `32 * 1000 * 1000`

**Commit**: `feat(chronicle): increase MAX_SCRIPT_NUMBER_LENGTH from 750KB to 32MB`

---

## Step 2: New opcode constants, ASM names, version constant

**Tests** — `tests/bsv/script/test_chronicle_constants.py`:
- `test_op_substr_constant` — `OpCode.OP_SUBSTR == b"\xb3"` (and LEFT, RIGHT, LSHIFTNUM, RSHIFTNUM)
- `test_nop_aliases_backward_compat` — `OpCode.OP_NOP4 == b"\xb3"` etc.
- `test_asm_round_trip_new_opcodes` — `Script.from_asm("OP_SUBSTR").to_asm() == "OP_SUBSTR"`
- `test_asm_nop_aliases_parse` — `from_asm("OP_NOP4")` parses same as `from_asm("OP_SUBSTR")`
- `test_opcode_value_name_dict` — dict maps bytes to new names
- `test_transaction_version_chronicle_constant` — `TRANSACTION_VERSION_CHRONICLE == 2`

**Impl**:
- `bsv/constants.py`:
  - Add `TRANSACTION_VERSION_CHRONICLE = 2`
  - Insert `OP_SUBSTR=b"\xb3"`, `OP_LEFT=b"\xb4"`, `OP_RIGHT=b"\xb5"`, `OP_LSHIFTNUM=b"\xb6"`, `OP_RSHIFTNUM=b"\xb7"` **before** the OP_NOP4-8 lines (L281-285) so they become canonical enum names and NOPs become aliases
  - Add entries to `OPCODE_VALUE_NAME_DICT` for the 5 new opcodes
- `bsv/script/script.py`: Update `from_asm()` to accept both new names and NOP aliases

**Commit**: `feat(chronicle): add new opcode constants, ASM names, and version constant`

---

## Step 3: OP_VER, OP_VERIF, OP_VERNOTIF

**Tests** — `tests/bsv/script/test_chronicle_opcodes.py`:
- **OP_VER**: pushes tx version as 4-byte LE (test versions 1, 2, 0xFF00); not disabled
- **OP_VERIF**: matching version → TRUE branch; non-matching → FALSE; non-4-byte → always FALSE; empty stack → error; not disabled
- **OP_VERNOTIF**: negated logic of VERIF; not disabled

**Impl**:
- `bsv/script/spend.py`:
  - Remove OP_VER, OP_VERIF, OP_VERNOTIF from `is_op_disabled()` (L810-817)
  - Add OP_VER handler in `step()`: push `self.tx_version.to_bytes(4, 'little')`
  - Add OP_VERIF/OP_VERNOTIF handlers: pop value, compare with 4-byte LE tx version (>= comparison), only if popped value is exactly 4 bytes; push result to if_stack
- `bsv/script/interpreter/operations.py`:
  - Add `op_ver()`, `op_verif()`, `op_vernotif()` functions
  - Update dispatch table (replace `op_reserved`/`op_verconditional` mappings)

**Commit**: `feat(chronicle): implement OP_VER, OP_VERIF, OP_VERNOTIF opcodes`

---

## Step 4: OP_2MUL, OP_2DIV

**Tests** — append to `tests/bsv/script/test_chronicle_opcodes.py`:
- **OP_2MUL**: 3→6, 0→0, -1→-2; not disabled
- **OP_2DIV**: 6→3, 7→3 (truncation), 0→0, -3→-1; not disabled

**Impl**:
- `bsv/script/spend.py`: Remove from `is_op_disabled()`, add handlers in `step()`
- `bsv/script/interpreter/operations.py`: Add `op_2mul()`, `op_2div()`, update dispatch table

**Commit**: `feat(chronicle): implement OP_2MUL and OP_2DIV opcodes`

---

## Step 5: OP_SUBSTR, OP_LEFT, OP_RIGHT

**Tests** — append to `tests/bsv/script/test_chronicle_opcodes.py`:
- **OP_SUBSTR**: basic extraction, full string, empty source error, negative length error, out-of-range error, insufficient stack error
- **OP_LEFT**: basic, zero-length, full-length, overflow error
- **OP_RIGHT**: basic, zero-length, full-length, 1-byte, overflow error
- **Composition**: LEFT + RIGHT + CAT roundtrip

**Impl**:
- `bsv/script/spend.py`:
  - Remove OP_NOP4, OP_NOP5, OP_NOP6 from NOP list (L131-133) — after Step 2 these are aliases for the new opcodes
  - Add OP_SUBSTR, OP_LEFT, OP_RIGHT handlers in `step()`
- `bsv/script/interpreter/operations.py`: Add functions, update dispatch table

**Commit**: `feat(chronicle): implement OP_SUBSTR, OP_LEFT, OP_RIGHT opcodes`

---

## Step 6: OP_LSHIFTNUM, OP_RSHIFTNUM

**Tests** — append to `tests/bsv/script/test_chronicle_opcodes.py`:
- **OP_LSHIFTNUM**: 1<<3=8, zero shift, multi-byte result, negative shift error
- **OP_RSHIFTNUM**: 8>>3=1, zero shift, negative number handling (negate→shift→negate), truncation
- **Undefined opcodes**: 0xba-0xff still return errors

**Impl**:
- `bsv/script/spend.py`: Remove OP_NOP7, OP_NOP8 from NOP list (L134-135), add handlers
- `bsv/script/interpreter/operations.py`: Add `op_lshiftnum()`, `op_rshiftnum()`, update dispatch table

**Commit**: `feat(chronicle): implement OP_LSHIFTNUM and OP_RSHIFTNUM opcodes`

---

## Step 7: SIGHASH_CHRONICLE constant and validation

**Tests** — `tests/bsv/script/test_chronicle_sighash.py`:
- `test_sighash_chronicle_constant` — `SIGHASH.CHRONICLE == 0x20`
- `test_sighash_all_forkid_chronicle` — value is 0x61
- `test_sighash_validate_accepts_chronicle_variants`
- `test_sighash_validate_still_rejects_invalid`

**Impl**:
- `bsv/constants.py`:
  - Add `CHRONICLE = 0x20` and combination variants to SIGHASH enum
  - Update `SIGHASH.validate()` to accept CHRONICLE variants

**Commit**: `feat(chronicle): add SIGHASH_CHRONICLE constant and update validation`

---

## Step 8: Malleability relaxation (is_relaxed + 7 gates)

**Tests** — `tests/bsv/script/test_chronicle_malleability.py`:
- `test_is_relaxed_v1_false` / `test_is_relaxed_v2_true`
- For each of 7 restrictions, paired tests:
  - v2 allows: non-minimal push, high-S sig, non-empty nullfail, non-empty dummy multisig, dirty stack, opcodes in unlocking script, non-minimal if
  - v1 rejects: same scenarios fail

**Impl**:
- `bsv/script/spend.py`:
  - Add `is_relaxed()` method: `return self.tx_version > 1`
  - Gate 7 checks: minimal push (L97), push-only (L763), clean stack (L774), low-S (L873), nullfail, nulldummy, minimalif — all with `not self.is_relaxed()`
- `bsv/script/interpreter/operations.py` + `thread.py`: Propagate relaxation to Engine path

**Commit**: `feat(chronicle): implement malleability relaxation for tx version > 1`

---

## Step 9: SIGHASH_CHRONICLE and OTDA implementation

**Tests** — `tests/bsv/script/test_chronicle_otda.py`:
- `test_bip143_for_forkid_without_chronicle` (regression)
- `test_otda_for_chronicle_sighash`
- `test_otda_preimage_structure`
- `test_tx_preimage_with_chronicle_flag`
- `test_spend_verify_signature_with_chronicle` (end-to-end)
- `test_mixed_sighash_multiple_inputs`

**Impl**:
- `bsv/transaction.py`:
  - Update `calc_input_signature_hash()` routing: FORKID+!CHRONICLE → BIP143; else → OTDA
  - Add `_calc_input_preimage_otda()` (adapt from `_calc_input_preimage_legacy()`)
- `bsv/transaction_preimage.py`: Add OTDA path in `tx_preimage()`
- `bsv/script/spend.py`: `verify_signature()` routes automatically via updated `tx_preimage()`

**Commit**: `feat(chronicle): implement OTDA for SIGHASH_CHRONICLE`

---

## Step 10: Comprehensive test suite + regression tests

**Tests** — `tests/bsv/script/test_chronicle_comprehensive.py`:
- Regression: OP_RIGHT slice correctness, OP_VER 4-byte LE encoding, LEFT+RIGHT+CAT composition
- Valid NOPs still work (NOP1, NOP2/CLTV, NOP3/CSV, NOP9, NOP10)
- Large script numbers near 32MB limit
- Cross-phase integration: v2 tx with Chronicle opcodes + OTDA + relaxed rules
- v1 tx preserves all pre-Chronicle restrictions

**Impl**: Tests only; fix any bugs discovered.

**Commit**: `test(chronicle): add comprehensive Chronicle upgrade test suite`

---

## Key Files Modified

| File | Steps |
|---|---|
| `bsv/script/interpreter/config.py` | 1 |
| `bsv/constants.py` | 2, 7 |
| `bsv/script/script.py` | 2 |
| `bsv/script/spend.py` | 3, 4, 5, 6, 8, 9 |
| `bsv/script/interpreter/operations.py` | 3, 4, 5, 6, 8 |
| `bsv/script/interpreter/thread.py` | 8 |
| `bsv/transaction.py` | 9 |
| `bsv/transaction_preimage.py` | 9 |

## Critical Design Notes

1. **Enum ordering**: New opcode names (OP_SUBSTR etc.) must be declared BEFORE OP_NOP4-8 in the enum so they become canonical; NOPs become aliases.
2. **NOP list in spend.py** (L126-158): After Step 2, OP_NOP4-8 are aliases for new opcodes. Must remove them from the NOP list when implementing each opcode (Steps 5-6).
3. **Dual execution paths**: Both `Spend` class and `Engine/Thread` interpreter need changes for opcodes and malleability.
4. **OTDA reuse**: Existing `_calc_input_preimage_legacy()` is nearly identical to OTDA — adapt rather than rewrite.

## Verification

After each step, run only the new/changed Chronicle tests:
```bash
pytest tests/bsv/script/test_chronicle_*.py -v
```
Full regression suite (`pytest --cov=bsv`) only at the end after Step 10.
