# Chronicle Update Implementation Roadmap — py-sdk

> **Chronicle Activation**
> - TestNet: Block height 1,713,168 (already activated)
> - MainNet: Block height 943,816 (target: 12:00 UTC, 07-Apr-2026)

> **Reference Specification**: https://hub.bsvblockchain.org/bsv-skills-center/network-topology/nodes/sv-node/chronicle-release
> **Reference Implementation (TypeScript SDK)**: https://github.com/bsv-blockchain/ts-sdk (supported since v2.0.0, bug fixes in v2.0.10)

---

## 1. Status Summary

| Requirement | Current Status | Required Work |
|---|---|---|
| SIGHASH_CHRONICLE (0x20) + OTDA | Not implemented | New implementation |
| tx version > 1 malleability relaxation | Not implemented | Add `isRelaxed()` gate |
| OP_VER (0x62) | Constant exists, disabled as `op_reserved` | Change implementation |
| OP_VERIF (0x65) | Constant exists, partially handled | Change implementation |
| OP_VERNOTIF (0x66) | Constant exists, partially handled | Change implementation |
| OP_SUBSTR (0xb3) | No constant, not implemented | New addition |
| OP_LEFT (0xb4) | No constant, not implemented | New addition |
| OP_RIGHT (0xb5) | No constant, not implemented | New addition |
| OP_2MUL (0x8d) | Constant exists, disabled as `op_reserved` | Change implementation |
| OP_2DIV (0x8e) | Constant exists, disabled as `op_reserved` | Change implementation |
| OP_LSHIFTNUM (0xb6) | No constant (OP_LSHIFT 0x98 is different) | New addition |
| OP_RSHIFTNUM (0xb7) | No constant (OP_RSHIFT 0x99 is different) | New addition |
| MAX_SCRIPT_NUM_LENGTH 32MB | 750KB (partial) | Update value |

---

## 2. Phase 1: SIGHASH_CHRONICLE and OTDA

### 2.1 Specification

Chronicle introduces a new sighash bit `CHRONICLE = 0x20`, enabling the **Original Transaction Digest Algorithm (OTDA)**.

| Configuration | CHRONICLE bit | Algorithm Used |
|---|---|---|
| Single input, single sig | 0 | BIP143 |
| Single input, single sig | 1 | OTDA |
| Multiple signatures | All 0 | BIP143 |
| Multiple signatures | All 1 | OTDA |
| Multiple signatures | Mixed | Mixed (per-input) |

OTDA is the pre-ForkID original Bitcoin signature digest algorithm. It directly serializes inputs/outputs (no hash commitments like BIP143).

### 2.2 Current py-sdk State

- **SIGHASH constants**: `bsv/constants.py:24-66` — `CHRONICLE` not defined
- **Signature hash calculation**: `bsv/transaction.py:106-246` — BIP143 and legacy only
  - `calc_input_signature_hash()` (L106-129): branches on ForkID bit
  - `_calc_input_preimage_bip143()` (L131-232): BIP143 implementation
  - `_calc_input_preimage_legacy()` (L234-246): Legacy implementation exists (usable as OTDA base)
- **SIGHASH.validate()** (L58-66): Only ForkID variants considered valid — needs to accept CHRONICLE variants

### 2.3 Implementation Tasks

#### 2.3.1 Add SIGHASH Constants

**Target file**: `bsv/constants.py`

```python
# Constants to add
SIGHASH.CHRONICLE = 0x20
SIGHASH.ALL_FORKID_CHRONICLE = 0x01 | 0x40 | 0x20  # = 0x61
# Add other combinations as needed
```

**TS-SDK Reference**: `src/primitives/TransactionSignature.ts:42`
```typescript
public static readonly SIGHASH_CHRONICLE = 0x00000020
```

#### 2.3.2 Signature Digest Routing Logic

**Target file**: `bsv/transaction.py` — `calc_input_signature_hash()` (L106-129)

Routing logic:
- **FORKID set + CHRONICLE unset** → BIP143 (current behavior)
- **FORKID unset, OR both FORKID + CHRONICLE set** → OTDA

**TS-SDK Reference**: `src/primitives/TransactionSignature.ts:320-333`
```typescript
static formatBytes(params) {
    const hasForkId = (params.scope & SIGHASH_FORKID) !== 0
    const hasChronicle = params.ignoreChronicle !== true &&
        (params.scope & SIGHASH_CHRONICLE) !== 0
    if (hasForkId && !hasChronicle) {
        return TransactionSignature.formatBip143(params)
    }
    if (!hasForkId || (hasForkId && hasChronicle)) {
        return TransactionSignature.formatOTDA(params)
    }
}
```

#### 2.3.3 OTDA (Original Transaction Digest Algorithm) Implementation

**Target file**: `bsv/transaction.py` — Add new method

Implement OTDA based on the existing `_calc_input_preimage_legacy()` (L234-246). OTDA is equivalent to the pre-SegWit/pre-ForkID original digest.

**TS-SDK Reference**: `src/primitives/TransactionSignature.ts:53-135` (`formatOTDA()`)

OTDA procedure:
1. Serialize transaction (include inputs/outputs directly, no hash commitments)
2. Embed scriptCode for the target input
3. Append sighash type at the end
4. Hash with SHA256d

#### 2.3.4 Update SIGHASH Validation

**Target file**: `bsv/constants.py` — `SIGHASH.validate()` (L58-66)

Update to accept combinations that include the CHRONICLE bit as valid.

#### 2.3.5 Update transaction_preimage.py

**Target file**: `bsv/transaction_preimage.py` — `tx_preimage()`, `_preimage()` (L10-54)

Add a path to generate OTDA preimage based on the CHRONICLE flag.

---

## 3. Phase 2: Selective Malleability Relaxation

### 3.1 Specification

For transactions with version > 1 (`0x01000000`), the following restrictions are removed:

| Restriction | Description |
|---|---|
| Minimal Encoding | Numbers no longer required to use minimum byte representation |
| Low-S Signatures | Signature S value no longer required to be ≤ curve order/2 |
| NULLFAIL | Failed `OP_CHECKSIG` no longer requires empty signature |
| NULLDUMMY | `OP_CHECKMULTISIG` dummy stack item need not be empty |
| MINIMALIF | `OP_IF`/`OP_NOTIF` input no longer must be exactly 0 or 1 |
| Clean Stack | Stack no longer must have exactly 1 element after execution |
| Data-Only Unlocking Script | Functional opcodes now permitted in unlocking scripts |

**Version 1 transactions retain all existing restrictions.**

### 3.2 Current py-sdk State

**Spend class** (`bsv/script/spend.py`):
- L15-18: Restriction flags are **hardcoded** as class variables
  ```python
  REQUIRE_MINIMAL_PUSH = True        # L15
  REQUIRE_PUSH_ONLY_UNLOCKING_SCRIPTS = True  # L16
  REQUIRE_LOW_S_SIGNATURES = True     # L17
  REQUIRE_CLEAN_STACK = True          # L18
  ```
- L97: Minimal push check in `step()`
- L763: Push-only validation
- L774: Clean stack validation
- L873: Low-S check (`s > curve.n // 2`)
- `is_op_disabled()` (L810-817): Disables OP_VER, OP_VERIF, OP_VERNOTIF, OP_2MUL, OP_2DIV

**Script Interpreter** (`bsv/script/interpreter/`):
- `scriptflag.py:1-76`: Script flag definitions
- `thread.py:124`: P2SH unlocking script push-only validation

**Problem**: All restrictions are applied uniformly regardless of version.

### 3.3 Implementation Tasks

#### 3.3.1 Add `is_relaxed()` Method

**Target file**: `bsv/script/spend.py`

```python
def is_relaxed(self) -> bool:
    return self._is_relaxed_override or self.transaction_version > 1
```

Add `is_relaxed` parameter to the constructor for manual override in tests.

**TS-SDK Reference**: `src/script/Spend.ts:219-222`

#### 3.3.2 Relax Minimal Encoding Restriction

**Target file**: `bsv/script/spend.py` — `step()` (L97), `bsv/script/interpreter/operations.py`

Skip minimal encoding check when `is_relaxed()` returns `True`.

**TS-SDK Reference**: `src/script/Spend.ts` — All locations gated by `!this.isRelaxed()`:
- L416 (minimal push check)
- L438, 452, 465, 478, 489, 493, 658, 731, 771, 793, 840-842, 905, 919, 1019, 1032
  (`BigNumber.fromScriptNum(..., !this.isRelaxed())` pattern)

#### 3.3.3 Relax Low-S Signature Restriction

**Target file**: `bsv/script/spend.py` — `check_signature_encoding()` (L873)

```python
# Before
if REQUIRE_LOW_S_SIGNATURES and s > curve.n // 2:
    ...
# After
if not self.is_relaxed() and s > curve.n // 2:
    ...
```

**TS-SDK Reference**: `src/script/Spend.ts:315`

#### 3.3.4 Relax NULLFAIL / NULLDUMMY Checks

**Target file**: `bsv/script/spend.py` and `bsv/script/interpreter/operations.py`

Gate the empty-signature check when `OP_CHECKSIG` returns FALSE, and the dummy element check for `OP_CHECKMULTISIG`, with `is_relaxed()`.

**TS-SDK Reference**: `src/script/Spend.ts:993` (NULLDUMMY)

**Specification details** — Scripts that now return TRUE after Chronicle:
```
# High-S signatures become valid
S1H P1 CHECKSIG  → TRUE
# Non-empty dummy allowed in CHECKMULTISIG
F S1H S2H 2 P1 P2 2 CHECKMULTISIG  → TRUE
```

Scripts that return FALSE (instead of immediate error) after Chronicle:
```
F P1 CHECKSIG  → FALSE (previously immediate error)
```

#### 3.3.5 Relax MINIMALIF Restriction

**Target file**: `bsv/script/interpreter/operations.py` — `OP_IF`/`OP_NOTIF` handling

When `is_relaxed()` is `True`, allow input values that are not strictly 0 or 1.

#### 3.3.6 Relax Clean Stack Restriction

**Target file**: `bsv/script/spend.py` — L774

```python
# Before
if REQUIRE_CLEAN_STACK and len(self.stack) != 1:
    ...
# After
if not self.is_relaxed() and len(self.stack) != 1:
    ...
```

**TS-SDK Reference**: `src/script/Spend.ts:1123-1129`

#### 3.3.7 Relax Data-Only Unlocking Script Restriction

**Target file**: `bsv/script/spend.py` — L763

```python
# Before
if REQUIRE_PUSH_ONLY_UNLOCKING_SCRIPTS and not unlocking_script.is_push_only():
    ...
# After
if not self.is_relaxed() and not unlocking_script.is_push_only():
    ...
```

**TS-SDK Reference**: `src/script/Spend.ts:1102`

**Important specification details**:
- After unlocking script execution, the main stack is kept, but the conditional stack and alt stack are cleared.
- `OP_RETURN` in the unlocking script only ends unlocking script execution, it does NOT invalidate the entire transaction.
- The scriptCode verified by `OP_CHECKSIG` in the unlocking script runs from the last seen `OP_CODESEPARATOR` to the end of the locking script.

**Specification example**:
```
# Unlocking script: S0 S1 OP_CODESEPARATOR P1 OP_CHECKSIG
# Locking script: P0 OP_CHECKSIG

# scriptCode when verifying S1: P1 OP_CHECKSIG P0 OP_CHECKSIG
# scriptCode when verifying S0: P0 OP_CHECKSIG
```

---

## 4. Phase 3: Opcode Restoration (10 opcodes)

### 4.1 Common Specification Rules

- If an opcode produces an error, immediately return the result of a call to `set_error` with the appropriate error message.
- Opcodes do not check the type of values on the stack; they interpret whatever they find as the expected data type.
- If required values are not present on the stack, return an error.

### 4.2 OP_VER (`0x62`)

**Spec**: Pushes the executing transaction's version onto the stack. The version is the first 4 bytes of the transaction, treated as a script number.
```
Input: none
Output: tos = transaction version
```

**Current state**: `bsv/constants.py:193` has `OP_VER = b"\x62"` defined. `bsv/script/interpreter/operations.py:2129` mapped to `op_reserved`. `bsv/script/spend.py:810-817` included in `is_op_disabled()` list.

**Implementation**:
- `operations.py`: `op_reserved` → new `op_ver()` function
- `spend.py`: Remove `OP_VER` from `is_op_disabled()` list
- Push tx version as 4-byte little-endian to stack

**TS-SDK Reference**: `src/script/Spend.ts:430-435`
```typescript
case OP.OP_VER: {
    const ver = this.transactionVersion
    this.pushStack([ver & 0xff, (ver >>> 8) & 0xff,
                    (ver >>> 16) & 0xff, (ver >>> 24) & 0xff])
    break
}
```

> **Note**: Fixed in TS-SDK v2.0.10 — originally used script number encoding, corrected to fixed 4-byte LE. py-sdk should also use 4-byte LE.

---

### 4.3 OP_VERIF (`0x65`)

**Spec**: Compares tos (top of stack) with the transaction version as a **greater-than-or-equal** comparison for conditional branching.
```
OP_VERIF [statements] [OP_ELSE [statements]] OP_ENDIF
```
Logically equivalent to `OP_VER OP_GREATERTHANOREQUAL OP_IF`.
```
Input: comparison value → tos
```

**Current state**: `bsv/constants.py:196` defined. `operations.py` mapped to `op_verconditional` (skips in non-executing context after genesis). `spend.py` included in disabled list.

**Implementation**:
- Pop value from stack
- Encode tx version as 4-byte LE
- Compare only when popped value is **exactly 4 bytes**
- Non-4-byte values always evaluate as FALSE (non-matching)
- Push comparison result onto if stack

**TS-SDK Reference**: `src/script/Spend.ts:529-543`
```typescript
case OP.OP_VERIF:
case OP.OP_VERNOTIF:
    // Pop stack, compare 4-byte LE encoding of tx version
    if (buf1.length === 4) {
        const ver = this.transactionVersion
        buf2 = [ver & 0xff, (ver >>> 8) & 0xff,
                (ver >>> 16) & 0xff, (ver >>> 24) & 0xff]
        fValue = compareNumberArrays(buf1, buf2)
    }
    if (currentOpcode === OP.OP_VERNOTIF) fValue = !fValue
    this.ifStack.push(fValue)
```

> **Note**: Fixed in TS-SDK v2.0.10 — comparison logic updated to match node v1.2.0. Must be **greater-than-or-equal** comparison (per spec).

---

### 4.4 OP_VERNOTIF (`0x66`)

**Spec**: Negated version of OP_VERIF. Logically equivalent to `OP_VER OP_GREATERTHANOREQUAL OP_NOTIF`.
```
OP_VERNOTIF [statements] [OP_ELSE [statements]] OP_ENDIF
```

**Implementation**: Same logic as OP_VERIF, but negate the final boolean value.

**TS-SDK Reference**: `src/script/Spend.ts:529-543` (same case block as OP_VERIF, negated at L541)

---

### 4.5 OP_SUBSTR (`0xb3`)

**Spec**: Returns a substring defined by start index and length.
```
"BSV Blockchain" OP_4 OP_5 OP_SUBSTR → "Block"
```
```
Input:
  tos     → desired substring length
  tos-1   → start index
  tos-2   → source string
Output: tos = string[start, length]
```

Error conditions:
- Source string is empty (zero length)
- Length is negative
- Specified range exceeds source string

**Current state**: No constant, not implemented. Needs to be added to OpCode enum.

**Implementation**:
1. `bsv/constants.py`: Add `OP_SUBSTR = b"\xb3"`
2. `operations.py`: Add `op_substr()` function + register in dispatch table

**TS-SDK Reference**: `src/script/Spend.ts:436-448`

**TS-SDK Constant Reference**: `src/script/OP.ts:131-132`
```typescript
OP_SUBSTR: 0xb3,  // restored in 2026 CHRONICLE upgrade (was OP_NOP4)
OP_NOP4: 0xb3,    // alias for backward compatibility
```

---

### 4.6 OP_LEFT (`0xb4`)

**Spec**: Produces a substring of the specified number of leftmost bytes. Zero-length strings are allowed.
```
"BSV Blockchain" OP_3 OP_LEFT → "BSV"
```
```
Input:
  tos   → desired length
  tos-1 → source string
Output: tos = string[0, length]
```

**Current state**: No constant, not implemented.

**Implementation**: Add `OP_LEFT = b"\xb4"` to `bsv/constants.py` + implement in `operations.py`.

**TS-SDK Reference**: `src/script/Spend.ts:450-461`, `src/script/OP.ts:133-134`

---

### 4.7 OP_RIGHT (`0xb5`)

**Spec**: Produces a substring of the specified number of rightmost bytes. Zero-length strings are allowed.
```
"BSV Blockchain" OP_5 OP_RIGHT → "chain"
```
```
Input:
  tos   → desired length
  tos-1 → source string
Output: start = len(string) - length; tos = string[start:]
```

**Current state**: No constant, not implemented.

**Implementation**: Add `OP_RIGHT = b"\xb5"` to `bsv/constants.py` + implement in `operations.py`.

**TS-SDK Reference**: `src/script/Spend.ts:463-474`, `src/script/OP.ts:135-136`

> **Note**: Bug fix in TS-SDK v2.0.10 for `buf.slice(size - len)` slice logic. When implementing in py-sdk, verify that `data[size - length:]` is the correct slice.

---

### 4.8 OP_2MUL (`0x8d`)

**Spec**: Multiplies the number on top of the stack by 2.
```
Input: tos → number to multiply by 2
Output: tos = input × 2
```

**Current state**: `bsv/constants.py:238` has `OP_2MUL = b"\x8d"` defined. `operations.py:2096` mapped to `op_reserved`.

**Implementation**: Change `op_reserved` → `op_2mul()`. Pop script number from stack, multiply by 2, push result.

**TS-SDK Reference**: `src/script/Spend.ts:767-775`
```typescript
bn = bn.mul(new BigNumber(2))
```

---

### 4.9 OP_2DIV (`0x8e`)

**Spec**: Divides the number on top of the stack by 2 (integer division).
```
Input: tos → number to divide by 2
Output: tos = input / 2
```

**Current state**: `bsv/constants.py:239` has `OP_2DIV = b"\x8e"` defined. `operations.py:2097` mapped to `op_reserved`.

**Implementation**: Change `op_reserved` → `op_2div()`. Use integer division (truncation).

**TS-SDK Reference**: `src/script/Spend.ts:767-776`
```typescript
bn = bn.div(new BigNumber(2))
```

---

### 4.10 OP_LSHIFTNUM (`0xb6`)

**Spec**: Performs a numerical shift to the left, preserving sign. Previously `OP_NOP7`.
```
Input: a, b
Output: a << b bits
```

**Current state**: No constant. Note: Existing `OP_LSHIFT` (`0x98`) is a bitwise shift on byte arrays and is **different**. `OP_LSHIFTNUM` is an arithmetic shift on script numbers (BigInt).

**Implementation**:
1. `bsv/constants.py`: Add `OP_LSHIFTNUM = b"\xb6"`
2. `operations.py`: Add `op_lshiftnum()` — shift bits must be non-negative

**TS-SDK Reference**: `src/script/Spend.ts:476-485`, `src/script/OP.ts:137-138`

---

### 4.11 OP_RSHIFTNUM (`0xb7`)

**Spec**: Performs a numerical shift to the right, preserving sign. Previously `OP_NOP8`.
```
Input: a, b
Output: a >> b bits
```

Negative number handling: Negate → shift → negate again.

**Current state**: No constant. `OP_RSHIFT` (`0x99`) is different.

**Implementation**: Add `OP_RSHIFTNUM = b"\xb7"` to `bsv/constants.py` + implement in `operations.py`.

**TS-SDK Reference**: `src/script/Spend.ts:487-501`, `src/script/OP.ts:139-140`
```typescript
// Negative number handling
if (bn.isNeg()) {
    bn = bn.neg()
    bn = bn.ushrn(shift)
    bn = bn.neg()
} else {
    bn = bn.ushrn(shift)
}
```

---

### 4.12 Opcode Constants & Dispatch Table Update Summary

**`bsv/constants.py` — Add to OpCode enum**:
```python
OP_SUBSTR    = b"\xb3"  # restored in Chronicle (was OP_NOP4)
OP_LEFT      = b"\xb4"  # restored in Chronicle (was OP_NOP5)
OP_RIGHT     = b"\xb5"  # restored in Chronicle (was OP_NOP6)
OP_LSHIFTNUM = b"\xb6"  # restored in Chronicle (was OP_NOP7)
OP_RSHIFTNUM = b"\xb7"  # restored in Chronicle (was OP_NOP8)
```

Backward-compatible aliases:
```python
OP_NOP4 = b"\xb3"
OP_NOP5 = b"\xb4"
OP_NOP6 = b"\xb5"
OP_NOP7 = b"\xb6"
OP_NOP8 = b"\xb7"
```

**`bsv/script/interpreter/operations.py` — OPCODE_DISPATCH table (L1964-2148) update**:
```python
# Change: op_reserved → new implementation
OpCode.OP_VER:    op_ver,
OpCode.OP_2MUL:   op_2mul,
OpCode.OP_2DIV:   op_2div,

# Change: op_verconditional → new implementation
OpCode.OP_VERIF:    op_verif,
OpCode.OP_VERNOTIF: op_vernotif,

# New additions
OpCode.OP_SUBSTR:    op_substr,
OpCode.OP_LEFT:      op_left,
OpCode.OP_RIGHT:     op_right,
OpCode.OP_LSHIFTNUM: op_lshiftnum,
OpCode.OP_RSHIFTNUM: op_rshiftnum,
```

**`bsv/script/spend.py` — `is_op_disabled()` (L810-817) update**:
Remove all Chronicle opcodes from the disabled list.

---

## 5. Phase 4: Script Number Size Limit Increase

### 5.1 Specification

The consensus limit `MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS` is increased from **750KB to 32MB**. Node operators can set their policy limit via `maxscriptnumlengthpolicy`.

### 5.2 Current py-sdk State

**Target file**: `bsv/script/interpreter/config.py:77-99`
```python
MAX_SCRIPT_NUMBER_LENGTH = 750 * 1000  # 750 KB
```

### 5.3 Implementation

```python
# Before
MAX_SCRIPT_NUMBER_LENGTH = 750 * 1000
# After
MAX_SCRIPT_NUMBER_LENGTH = 32 * 1000 * 1000  # 32 MB
```

**TS-SDK Reference**: `src/script/Spend.ts:208`
```typescript
this.memoryLimit = params.memoryLimit ?? 32000000  // 32MB
```

---

## 6. Phase 5: Test Suite

### 6.1 Test Structure

Chronicle tests should be organized into the following categories:

#### 6.1.1 Opcode Tests

For each opcode:
- Happy path (basic behavior, boundary values)
- Error cases (insufficient stack, out of range, type errors)
- Version-dependent behavior verification

**TS-SDK Reference**: `src/script/__tests/ChronicleOpcodes.test.ts` (548 lines)

| Test Group | TS-SDK Lines | Test Content |
|---|---|---|
| OP_VER | L116-135 | 4-byte LE push for versions 1, 2, 0xFF00 |
| OP_VERIF | L140-163 | Match/non-match branching, 3-byte/5-byte rejection, empty stack error |
| OP_VERNOTIF | L166-181 | Negated branch logic, non-4-byte always non-matching |
| OP_SUBSTR | L186-213 | Substring extraction, boundary checks, insufficient stack |
| OP_LEFT | L218-235 | Left N bytes, zero/full length, overflow error |
| OP_RIGHT | L240-261 | Right N bytes, zero/full/1 byte, overflow error |
| OP_2MUL | L266-284 | Multiply by 2 (including 0 and -1) |
| OP_2DIV | L289-306 | Divide by 2 (including truncation) |
| OP_LSHIFTNUM | L311-326 | Left bit shift (including multi-byte result) |
| OP_RSHIFTNUM | L331-346 | Right bit shift |
| Undefined opcodes | L408-429 | 0xba-0xff all return errors |
| Valid NOPs | L434-450 | OP_NOP1, CLTV, CSV, NOP9, NOP10 still work |
| Large number test | L455-467 | Large script numbers and OP_MUL |
| Regression tests | L472-547 | OP_RIGHT slice fix, OP_VER encoding fix, LEFT+RIGHT+CAT composition |

#### 6.1.2 Signature Digest Tests

**TS-SDK Reference**: `src/script/__tests/Chronicle.test.ts` (122 lines)

| Test | TS-SDK Lines | Content |
|---|---|---|
| BIP143 signature verification | L10-21 | v1 transaction P2PKH signing |
| OTDA signature verification | L23-37 | OTDA signing with isRelaxed: true |
| sighash test vectors | L46-50 | External test vectors (Teranode team collaboration) |

#### 6.1.3 Malleability Relaxation Tests

- Version 1: Verify all restrictions are enforced
- Version > 1: Verify each restriction is individually relaxed
- Acceptance tests for high-S signatures, non-empty dummy, non-minimal encoding

---

## 7. Phase 6: Constants, ASM & Documentation Updates

### 7.1 Update ASM Representation

**Target file**: `bsv/constants.py` — `OPCODE_VALUE_NAME_DICT` (L362-366)

Add ASM names for new opcodes:
```python
b"\xb3": "OP_SUBSTR",
b"\xb4": "OP_LEFT",
b"\xb5": "OP_RIGHT",
b"\xb6": "OP_LSHIFTNUM",
b"\xb7": "OP_RSHIFTNUM",
```

**Target file**: `bsv/script/script.py` — `from_asm()` / `to_asm()` methods

Support parsing and output of new opcode names. Also accept `OP_NOP4`–`OP_NOP8` for backward compatibility.

### 7.2 Version Constants

**Target file**: `bsv/constants.py`

```python
TRANSACTION_VERSION_CHRONICLE = 2  # Relaxed malleability rules
```

### 7.3 Update CLAUDE.md

Add a section about Chronicle support.

---

## 8. Recommended Implementation Order

| Order | Phase | Effort | Reason |
|---|---|---|---|
| 1 | Phase 4: Number size limit | Small | 1-line change, done immediately |
| 2 | Phase 6: Constants addition | Small | Prerequisite for opcode impl |
| 3 | Phase 3: Opcode implementation | Medium | 10 opcodes, TS-SDK is good reference |
| 4 | Phase 2: Malleability relaxation | Medium | `is_relaxed()` + 7 conditional changes |
| 5 | Phase 1: SIGHASH/OTDA | Large | Most complex, needs careful testing |
| 6 | Phase 5: Test suite | Large | Tests for all phases |

---

## TS-SDK File Reference Index

| File | Lines | Content |
|---|---|---|
| `src/primitives/TransactionSignature.ts` | 379 | SIGHASH_CHRONICLE definition (L42), routing (L320-333), OTDA (L53-135), BIP143 (L143-309) |
| `src/script/Spend.ts` | 1168 | isRelaxed (L219-222), all opcode implementations, all relaxation checks, memoryLimit (L208) |
| `src/script/OP.ts` | 225 | Opcode constant definitions, NOP aliases (L131-140) |
| `src/script/__tests/ChronicleOpcodes.test.ts` | 548 | Complete opcode tests |
| `src/script/__tests/Chronicle.test.ts` | 122 | Signature digest tests |
