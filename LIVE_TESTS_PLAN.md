# Mocked Live Tests + Testnet Broadcast for Chronicle Network Upgrade

## Context

The Chronicle upgrade implementation (Steps 1-10 in `CHRONICLE_TDD_PLAN.md`) is complete. The existing Chronicle tests in `tests/bsv/script/test_chronicle_*.py` validate opcodes and features in isolation using raw `Spend` objects with fake data. We now need **live-style tests** that build real `Transaction` objects, sign them with real keys, validate each input through `Spend.validate()`, and mock-broadcast — covering every sighash flag combination, both tx versions, and every opcode.

## File Structure

```
tests/bsv/live/
  __init__.py                          (exists, empty)
  conftest.py                          (fixtures, MockBroadcaster, helpers)
  test_live_sighash_matrix.py          (12 sighash flags x 2 tx versions, P2PKH/P2PK/Multisig)
  test_live_chronicle_opcodes.py       (10 restored opcodes in signed txs)
  test_live_standard_opcodes.py        (standard opcodes in signed txs)
  test_live_malleability.py            (v1 vs v2 relaxation in signed txs)
```

## Step 1: conftest.py — Shared Infrastructure [x]

**File:** `tests/bsv/live/conftest.py`

### MockBroadcaster
Implements `Broadcaster` ABC from `bsv/broadcasters/broadcaster.py`. Captures transactions and returns `BroadcastResponse(status="success", txid=tx.txid(), message="mock")`.

### MockChainTracker
Implements `ChainTracker` from `bsv/chaintrackers/chaintrackers.py`. Returns `True` from `is_valid_root_for_height()`.

### Fixtures
- `priv_key` / `priv_key2` / `priv_key3` — Fixed WIF keys for determinism
- `mock_broadcaster` — Fresh `MockBroadcaster` per test

### Helper: `build_funding_tx(locking_script, satoshis=10000) -> Transaction`
Creates a synthetic source tx with one output. Does not need to be valid itself — just provides a UTXO for the spending tx to reference via `source_transaction`.

### Helper: `build_signed_tx(...) -> Transaction`
Core workhorse. Builds a spending tx, signs it, validates every input via `Spend.validate()`, returns the tx.

```python
def build_signed_tx(
    priv_key, locking_script, unlock_template,
    sighash=SIGHASH.ALL_FORKID, tx_version=1,
    num_inputs=1, num_outputs=1, satoshis=10000
) -> Transaction:
```

Flow:
1. Create `num_inputs` funding txs, each with `locking_script` output
2. Build `TransactionInput` for each, setting `source_transaction`, `unlocking_script_template`, and `sighash`
3. Build `num_outputs` outputs (split satoshis minus fee)
4. `Transaction(inputs, outputs, version=tx_version)`
5. `tx.sign(bypass=False)`
6. For each input, construct `Spend({...})` and call `spend.validate()` — assert True
7. Return tx

The `Spend` construction follows the pattern at `bsv/script/spend.py:22-63`: needs `sourceTXID`, `sourceOutputIndex`, `sourceSatoshis`, `lockingScript`, `transactionVersion`, `otherInputs`, `outputs`, `inputIndex`, `unlockingScript`, `inputSequence`, `lockTime`.

Key: `otherInputs` must be a list of `TransactionInput` objects for all inputs except the one being validated. `verify_signature()` at spend.py:960-978 reconstructs the full input list by inserting the current input at `inputIndex`.

### Helper: `custom_unlock(priv_key, data_pushes=b"") -> UnlockingScriptTemplate`
For opcode tests where unlocking scripts need data items before `<sig> <pubkey>`. Uses `to_unlock_script_template()` from `bsv/script/type.py:12-17`.

```python
def custom_unlock(priv_key, data_prefix_script=None):
    def sign(tx, input_index):
        tx_input = tx.inputs[input_index]
        sighash = tx_input.sighash
        signature = priv_key.sign(tx.preimage(input_index))
        public_key = priv_key.public_key().serialize()
        sig_script = Script(
            encode_pushdata(signature + sighash.to_bytes(1, "little"))
            + encode_pushdata(public_key)
        )
        if data_prefix_script:
            return Script(data_prefix_script.serialize() + sig_script.serialize())
        return sig_script
    def estimated_unlocking_byte_length():
        return 200
    return to_unlock_script_template(sign, estimated_unlocking_byte_length)
```

### Helper: `p2pkh_lock_with_prefix(prefix_asm, priv_key) -> Script`
Builds a locking script: `{prefix opcodes} OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG`. The prefix opcodes consume data items from the stack (pushed by unlocking script) before P2PKH validation runs on the remaining `<sig> <pubkey>`.

## Step 2: test_live_sighash_matrix.py — All 12 Sighash Flags x 2 Versions [x]

**File:** `tests/bsv/live/test_live_sighash_matrix.py`

### Parametrization

```python
FORKID_SIGHASHES = [
    SIGHASH.ALL_FORKID, SIGHASH.NONE_FORKID, SIGHASH.SINGLE_FORKID,
    SIGHASH.ALL_ANYONECANPAY_FORKID, SIGHASH.NONE_ANYONECANPAY_FORKID,
    SIGHASH.SINGLE_ANYONECANPAY_FORKID,
]
CHRONICLE_SIGHASHES = [
    SIGHASH.ALL_FORKID_CHRONICLE, SIGHASH.NONE_FORKID_CHRONICLE,
    SIGHASH.SINGLE_FORKID_CHRONICLE, SIGHASH.ALL_ANYONECANPAY_FORKID_CHRONICLE,
    SIGHASH.NONE_ANYONECANPAY_FORKID_CHRONICLE, SIGHASH.SINGLE_ANYONECANPAY_FORKID_CHRONICLE,
]
ALL_SIGHASHES = FORKID_SIGHASHES + CHRONICLE_SIGHASHES
TX_VERSIONS = [1, 2]
```

### Tests (parametrized over `ALL_SIGHASHES x TX_VERSIONS`)

| Test | Description |
|------|-------------|
| `test_p2pkh_single_input` | 1-in, 1-out P2PKH. Build, sign, validate, mock-broadcast |
| `test_p2pkh_multi_input` | 3-in, 2-out P2PKH. Validates each input independently |
| `test_p2pk_single_input` | 1-in, 1-out P2PK using `P2PK` template from `bsv/script/type.py:113` |
| `test_multisig_2of3` | 2-of-3 `BareMultisig` from `bsv/script/type.py:149` |

**SIGHASH_SINGLE handling**: When `sighash & 0x1F == SIGHASH.SINGLE`, ensure `num_outputs >= input_index + 1`. The OTDA code at `transaction_preimage.py:150-160` writes blank outputs for indices below `input_index`.

**SIGHASH_NONE handling**: OTDA writes 0 outputs. BIP143 zeros `hashOutputs`. Both already handled.

**Total**: 12 sighashes x 2 versions x 4 test methods = **96 parametrized tests**

### Preimage routing verification tests (non-parametrized)
- `test_forkid_only_uses_bip143` — Verify preimage format for `ALL_FORKID`
- `test_forkid_chronicle_uses_otda` — Verify preimage format for `ALL_FORKID_CHRONICLE`

## Step 3: test_live_chronicle_opcodes.py — 10 Restored Opcodes [x]

**File:** `tests/bsv/live/test_live_chronicle_opcodes.py`

Each test builds a real signed transaction where the locking script exercises the opcode, validates via `Spend.validate()`, and mock-broadcasts. Pattern:

- **Locking script**: `{opcode logic + verify result} OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG`
- **Unlocking script**: `{data pushes} <sig> <pubkey>` (via `custom_unlock` helper)

Stack order: unlocking pushes `data... sig pubkey`. Locking pops/consumes data from below sig/pubkey first, then P2PKH consumes sig/pubkey.

| Opcode | Locking prefix | Unlocking data | Notes |
|--------|---------------|----------------|-------|
| OP_VER | `OP_VER OP_1 OP_NUMEQUALVERIFY` | (none) | v1 tx pushes 1; also test v2 with `OP_2` |
| OP_VERIF | `OP_VERIF ... OP_ELSE OP_FALSE OP_ENDIF` | `<4-byte-le-version>` | Conditional flow, needs IF/ELSE/ENDIF |
| OP_VERNOTIF | `OP_VERNOTIF ... OP_ELSE ... OP_ENDIF` | `<4-byte-le-version>` | Negated VERIF |
| OP_2MUL | `OP_2MUL OP_4 OP_NUMEQUALVERIFY` | `OP_2` | 2*2=4 |
| OP_2DIV | `OP_2DIV OP_5 OP_NUMEQUALVERIFY` | `0a` (10) | 10/2=5 |
| OP_SUBSTR | `OP_SUBSTR <expected> OP_EQUALVERIFY` | `<data> <offset> <length>` | Substring extraction |
| OP_LEFT | `OP_LEFT <expected> OP_EQUALVERIFY` | `<data> <length>` | Left bytes |
| OP_RIGHT | `OP_RIGHT <expected> OP_EQUALVERIFY` | `<data> <length>` | Right bytes |
| OP_LSHIFTNUM | `OP_LSHIFTNUM OP_8 OP_NUMEQUALVERIFY` | `OP_1 OP_3` | 1<<3=8 |
| OP_RSHIFTNUM | `OP_RSHIFTNUM OP_2 OP_NUMEQUALVERIFY` | `OP_8 OP_2` | 8>>2=2 |

Each opcode gets tested at least twice: once with `SIGHASH.ALL_FORKID` (v1, BIP143) and once with `SIGHASH.ALL_FORKID_CHRONICLE` (v2, OTDA).

## Step 4: test_live_standard_opcodes.py — Standard Opcodes [x]

**File:** `tests/bsv/live/test_live_standard_opcodes.py`

Same pattern as Step 3 but for standard opcodes. Grouped by category, using `pytest.mark.parametrize` where opcodes share test structure.

### Categories

**Constants** (simple validation that push values work in signed txs):
- OP_0/OP_FALSE, OP_1-OP_16, OP_1NEGATE, OP_TRUE

**Stack** (parametrized where possible):
- OP_DUP, OP_DROP, OP_SWAP, OP_OVER, OP_ROT, OP_NIP, OP_TUCK
- OP_PICK, OP_ROLL, OP_DEPTH, OP_IFDUP
- OP_2DUP, OP_3DUP, OP_2OVER, OP_2ROT, OP_2SWAP, OP_2DROP
- OP_TOALTSTACK, OP_FROMALTSTACK
- OP_SIZE

**Arithmetic** (parametrized: `(input_asm, opcode, expected)`):
- Unary: OP_1ADD, OP_1SUB, OP_NEGATE, OP_ABS, OP_NOT, OP_0NOTEQUAL
- Binary: OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD
- Comparison: OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL, OP_LESSTHAN, OP_GREATERTHAN, OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL
- Logic: OP_BOOLAND, OP_BOOLOR
- Range: OP_MIN, OP_MAX, OP_WITHIN

**Bitwise/Splice**:
- OP_AND, OP_OR, OP_XOR, OP_INVERT
- OP_CAT, OP_SPLIT, OP_NUM2BIN, OP_BIN2NUM
- OP_EQUAL, OP_EQUALVERIFY

**Crypto** (each with a real signature):
- OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256
- OP_CHECKSIG (covered by P2PKH/P2PK in sighash matrix)
- OP_CHECKSIGVERIFY
- OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY
- OP_CODESEPARATOR

**Flow control**:
- OP_IF / OP_NOTIF / OP_ELSE / OP_ENDIF
- OP_VERIFY
- OP_NOP (and NOP1, NOP2/CLTV, NOP3/CSV, NOP9, NOP10)
- OP_RETURN (in OP_FALSE OP_RETURN data script — not spendable, test construction only)

## Step 5: test_live_malleability.py — v1 vs v2 Relaxation [x]

**File:** `tests/bsv/live/test_live_malleability.py`

Tests 7 malleability restrictions that are relaxed for `tx_version > 1` (`is_relaxed()` at spend.py:886). Each test has a v2-passes and v1-fails pair.

| Restriction | v2 test (passes) | v1 test (fails) |
|-------------|-------------------|-----------------|
| Non-minimal push | Locking uses non-minimal encoding | Same script, v1 → error |
| Push-only unlocking | Unlocking has OP_NOP | Same, v1 → error |
| Clean stack | Leave 2 items on stack | Same, v1 → error |
| Low-S signature | Sign with high-S sig | Same, v1 → error |
| NULLFAIL | Non-empty sig on failed CHECKSIG | Same, v1 → error |
| NULLDUMMY | Non-zero dummy in CHECKMULTISIG | Same, v1 → error |
| MINIMALIF | Non-minimal boolean in OP_IF | Same, v1 → error |

**Note**: Creating high-S signatures requires post-processing the DER signature (negating S mod curve order). We can do this by manipulating the signature bytes after signing.

## Key Files Referenced

| File | Role |
|------|------|
| `bsv/script/type.py:12-17` | `to_unlock_script_template()` factory |
| `bsv/script/type.py:50-87` | `P2PKH` template — pattern for lock/unlock |
| `bsv/script/type.py:149-188` | `BareMultisig` template |
| `bsv/script/spend.py:22-63` | `Spend.__init__()` params |
| `bsv/script/spend.py:835-860` | `Spend.validate()` |
| `bsv/script/spend.py:960-978` | `Spend.verify_signature()` |
| `bsv/transaction_preimage.py:190-234` | `tx_preimage()` routing |
| `bsv/transaction.py:106-132` | `calc_input_signature_hash()` routing |
| `bsv/constants.py:25-81` | `SIGHASH` enum, all 12 valid combinations |
| `bsv/broadcasters/broadcaster.py` | `Broadcaster` ABC, `BroadcastResponse` |
| `tests/bsv/script/test_chronicle_opcodes.py` | Existing `make_spend()` pattern |

## Verification

```bash
# Run all live tests
pytest tests/bsv/live/ -v

# Run just sighash matrix
pytest tests/bsv/live/test_live_sighash_matrix.py -v

# Run with coverage
pytest tests/bsv/live/ --cov=bsv --cov-report=html -v

# Verify no regressions in existing tests
pytest tests/bsv/script/test_chronicle_*.py -v

# Run testnet broadcast tests (requires FUNDED_TESTNET_WIF)
export FUNDED_TESTNET_WIF=cU7tvH2nfymk5UbhbcVRnSeTC1Yan5B9a6cWVZKyTf1bhctFZF3x
pytest tests/bsv/live/test_live_testnet.py -v
```

## Step 6: Testnet Broadcast Tests [x]

**File:** `tests/bsv/live/test_live_testnet.py`

- UTXOManager with fan-out + JSON persistence (`.utxo_pool.json`)
- 98 testnet tests: P2PKH/P2PK/Multisig x 12 sighash x 2 versions + opcodes
- Gated by `FUNDED_TESTNET_WIF` env var, `@pytest.mark.testnet`

### Testnet Results (2026-03-27)

- **98/98 PASSED** with `X-SkipScriptValidation: true` ARC header
- ARC's script validator doesn't support Chronicle sighash yet, but the underlying node does
- OTDA preimage verified byte-identical to TS-SDK (@bsv/sdk)

## Step 7: Investigate CHRONICLE sighash "malformed" rejection [x]

**Root cause:** ARC's script validator lacks Chronicle support. Fix: `X-SkipScriptValidation: true` header.
OTDA preimage verified byte-identical to TS-SDK.

## Step 8: MINIMALIF malleability gate [x]

Added 7th malleability restriction to `Spend.step()` for OP_IF/OP_NOTIF.
Non-minimal conditionals (e.g. `0x02` instead of `0x01`) rejected in v1, allowed in v2.

## Step 9: Engine/Thread Chronicle parity [ ]

The Engine/Thread interpreter (`bsv/script/interpreter/`) is a Go SDK port from pre-Chronicle.
It needs updates to match the Spend class.

### 9a. Port 10 Chronicle opcodes to Engine

**File:** `bsv/script/interpreter/operations.py`

| Opcode | Current handler | Needed |
|--------|----------------|--------|
| OP_VER | `op_reserved` | Push tx version as 4-byte LE |
| OP_VERIF | `op_verconditional` stub | Version conditional branching |
| OP_VERNOTIF | `op_verconditional` stub | Negated version conditional |
| OP_2MUL | disabled | Multiply by 2 |
| OP_2DIV | disabled | Divide by 2 (truncate toward zero) |
| OP_SUBSTR | `op_nop` (via NOP4 alias) | Substring extraction |
| OP_LEFT | `op_nop` (via NOP5 alias) | Left n bytes |
| OP_RIGHT | `op_nop` (via NOP6 alias) | Right n bytes |
| OP_LSHIFTNUM | `op_nop` (via NOP7 alias) | Left shift numeric |
| OP_RSHIFTNUM | `op_nop` (via NOP8 alias) | Right shift numeric |

### 9b. Add malleability relaxation to Engine

**File:** `bsv/script/interpreter/thread.py`

- Add `is_relaxed()` method: `return self.tx_version > 1`
- Gate 7 malleability checks with `not is_relaxed()`:
  - NULLFAIL, NULLDUMMY, clean stack, MINIMALIF, strict encoding, minimal push, push-only

### 9c. Add checksigData extension for post-Chronicle CHECKSIG

**File:** `bsv/script/interpreter/operations.py`

When CHECKSIG executes in scriptSig (unlocking script) post-Chronicle, the scriptCode
should be extended: `scriptCode += scriptPubKey`. This matches the node's behavior at
`interpreter.cpp:1478-1483`.

### 9d. Remove OP_NOP4-8 aliases from NOP list

The NOP list in `operations.py` still includes OP_NOP4-8 which are now aliases for
OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_LSHIFTNUM, OP_RSHIFTNUM. Remove them so the
actual opcode handlers execute.
