"""
Conformance runner for go-sdk interpreter reference vectors.

Loads the JSON files vendored into this folder:
- data/script_tests.json
- data/tx_valid.json
- data/tx_invalid.json

Goal: match go-sdk behavior as closely as possible.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

import pytest

from bsv.constants import OpCode
from bsv.script.script import Script
from bsv.script.interpreter import Engine, with_tx, with_flags
from bsv.script.interpreter.errs import ErrorCode, is_error_code
from bsv.script.interpreter.scriptflag import Flag
from bsv.transaction import Transaction, TransactionInput, TransactionOutput


VECTORS_DIR = Path(__file__).resolve().parent / "data"


@pytest.fixture(autouse=True)
def patch_signature_validation():
    """
    The interpreter test suite applies an autouse monkeypatch that makes signature verification deterministic.
    For go-sdk conformance vectors we need real interpreter behavior (e.g. invalid encodings must fail),
    so we override that fixture locally by doing nothing.
    """
    yield


def _push_data(data: bytes) -> bytes:
    l = len(data)
    if l == 0:
        return bytes([OpCode.OP_0.value[0]])
    if l <= 75:
        return bytes([l]) + data
    if l <= 0xFF:
        return bytes([OpCode.OP_PUSHDATA1.value[0], l]) + data
    if l <= 0xFFFF:
        return bytes([OpCode.OP_PUSHDATA2.value[0]]) + l.to_bytes(2, "little") + data
    return bytes([OpCode.OP_PUSHDATA4.value[0]]) + l.to_bytes(4, "little") + data


def _minimal_num(n: int) -> bytes:
    # Minimal ScriptNumber encoding (subset sufficient for vectors)
    if n == 0:
        return b""
    neg = n < 0
    v = -n if neg else n
    out = bytearray()
    while v:
        out.append(v & 0xFF)
        v >>= 8
    if out[-1] & 0x80:
        out.append(0x00)
    if neg:
        out[-1] |= 0x80
    return bytes(out)


def _parse_hex_token(tok: str) -> bytes:
    assert tok.startswith("0x")
    return bytes.fromhex(tok[2:])


def _opcode_map() -> dict[str, int]:
    # Build a short-form opcode map similar to go reference_test.go
    m: dict[str, int] = {}
    for op in OpCode:
        name = op.name
        m[name] = op.value[0]

    for op in OpCode:
        name = op.name
        if "OP_UNKNOWN" in name:
            continue

        # Allow OP_FALSE/OP_TRUE aliases without OP_ prefix.
        if name in ("OP_FALSE", "OP_TRUE"):
            m[name.removeprefix("OP_")] = op.value[0]
            continue

        # Exclude OP_0 and OP_1..OP_16 from prefix stripping to avoid collisions with numbers.
        if op.value[0] == OpCode.OP_0.value[0] or (OpCode.OP_1.value[0] <= op.value[0] <= OpCode.OP_16.value[0]):
            continue

        m[name.removeprefix("OP_")] = op.value[0]
    # Aliases used in go reference
    m["OP_0"] = OpCode.OP_0.value[0]
    m["OP_1"] = OpCode.OP_1.value[0]
    # Bitcoin Core aliases (go-sdk includes these). In this SDK they are exposed as NOP2/NOP3.
    m["OP_CHECKLOCKTIMEVERIFY"] = OpCode.OP_NOP2.value[0]
    m["OP_CHECKSEQUENCEVERIFY"] = OpCode.OP_NOP3.value[0]
    m["CHECKLOCKTIMEVERIFY"] = OpCode.OP_NOP2.value[0]
    m["CHECKSEQUENCEVERIFY"] = OpCode.OP_NOP3.value[0]
    m["OP_RESERVED"] = OpCode.OP_RESERVED.value[0]
    return m


_OPS = _opcode_map()


def parse_short_form(script_str: str) -> Script:
    """
    Parse the reference short form used by Bitcoin Core / go-sdk reference tests.
    """
    script_str = script_str.replace("\n", " ").replace("\t", " ")
    tokens = [t for t in script_str.split(" ") if t]
    out = bytearray()
    for tok in tokens:
        # plain number
        try:
            num = int(tok, 10)
            if num == 0:
                out.append(OpCode.OP_0.value[0])
            elif num == -1:
                out.append(OpCode.OP_1NEGATE.value[0])
            elif 1 <= num <= 16:
                out.append((OpCode.OP_1.value[0] - 1) + num)
            else:
                out += _push_data(_minimal_num(num))
            continue
        except ValueError:
            pass

        # raw bytes (0x..)
        if tok.startswith("0x"):
            out += _parse_hex_token(tok)
            continue

        # quoted string
        if len(tok) >= 2 and tok[0] == "'" and tok[-1] == "'":
            out += _push_data(tok[1:-1].encode("utf-8"))
            continue

        # opcode name / alias
        if tok in _OPS:
            out.append(_OPS[tok])
            continue

        raise ValueError(f"bad token {tok!r}")

    return Script(bytes(out))


def parse_script_flags(flag_str: str) -> Flag:  # NOSONAR - Complexity (20), requires refactoring
    flags = Flag(0)
    for f in flag_str.split(","):
        f = f.strip()
        if f in ("", "NONE"):
            continue
        if f == "CHECKLOCKTIMEVERIFY":
            flags = flags.add_flag(Flag.VERIFY_CHECK_LOCK_TIME_VERIFY)
        elif f == "CHECKSEQUENCEVERIFY":
            flags = flags.add_flag(Flag.VERIFY_CHECK_SEQUENCE_VERIFY)
        elif f == "CLEANSTACK":
            flags = flags.add_flag(Flag.VERIFY_CLEAN_STACK)
        elif f == "DERSIG":
            flags = flags.add_flag(Flag.VERIFY_DER_SIGNATURES)
        elif f == "DISCOURAGE_UPGRADABLE_NOPS":
            flags = flags.add_flag(Flag.DISCOURAGE_UPGRADABLE_NOPS)
        elif f == "LOW_S":
            flags = flags.add_flag(Flag.VERIFY_LOW_S)
        elif f == "MINIMALDATA":
            flags = flags.add_flag(Flag.VERIFY_MINIMAL_DATA)
        elif f == "NULLDUMMY":
            flags = flags.add_flag(Flag.STRICT_MULTISIG)
        elif f == "NULLFAIL":
            flags = flags.add_flag(Flag.VERIFY_NULL_FAIL)
        elif f == "P2SH":
            flags = flags.add_flag(Flag.BIP16)
        elif f == "SIGPUSHONLY":
            flags = flags.add_flag(Flag.VERIFY_SIG_PUSH_ONLY)
        elif f == "STRICTENC":
            flags = flags.add_flag(Flag.VERIFY_STRICT_ENCODING)
        elif f == "UTXO_AFTER_GENESIS":
            flags = flags.add_flag(Flag.UTXO_AFTER_GENESIS)
        elif f == "MINIMALIF":
            flags = flags.add_flag(Flag.VERIFY_MINIMAL_IF)
        elif f == "SIGHASH_FORKID":
            flags = flags.add_flag(Flag.ENABLE_SIGHASH_FORK_ID)
        else:
            raise ValueError(f"invalid flag: {f}")
    return flags


def allowed_error_codes(expected: str) -> list[ErrorCode]:
    """
    Mirrors go-sdk reference_test.go parseExpectedResult mapping, but returning Python ErrorCode values.
    This can be expanded as gaps are found.
    """
    if expected == "OK":
        return []

    def _maybe(name: str) -> Optional[ErrorCode]:
        return getattr(ErrorCode, name, None)  # type: ignore[arg-type]

    def _codes(*names: str) -> list[ErrorCode]:
        return [c for c in (_maybe(n) for n in names) if c is not None]

    mapping: dict[str, list[ErrorCode]] = {
        "EVAL_FALSE": _codes("ERR_EVAL_FALSE", "ERR_EMPTY_STACK"),
        "SPLIT_RANGE": _codes("ERR_INVALID_SPLIT_RANGE", "ERR_INVALID_NUMBER_RANGE", "ERR_NUMBER_TOO_BIG", "ERR_NUMBER_TOO_SMALL"),
        "INVALID_NUMBER_RANGE": _codes("ERR_INVALID_NUMBER_RANGE", "ERR_NUMBER_TOO_BIG", "ERR_NUMBER_TOO_SMALL"),
        "OPERAND_SIZE": _codes("ERR_INVALID_INPUT_LENGTH"),
        "EQUALVERIFY": _codes("ERR_EQUAL_VERIFY"),
        "NULLFAIL": _codes("ERR_SIG_NULLFAIL"),
        "NEGATIVE_LOCKTIME": _codes("ERR_NEGATIVE_LOCKTIME", "ERR_NUMBER_TOO_SMALL", "ERR_INVALID_NUMBER_RANGE"),
        "UNSATISFIED_LOCKTIME": _codes("ERR_UNSATISFIED_LOCKTIME", "ERR_UNSATISFIED_LOCKTIME_SEQUENCE"),
        "SIG_HASHTYPE": _codes("ERR_SIG_HASHTYPE"),
        "ILLEGAL_FORKID": _codes("ERR_ILLEGAL_FORKID"),
        "SIG_DER": _codes(
            "ERR_SIG_TOO_SHORT", "ERR_SIG_TOO_LONG", "ERR_SIG_INVALID_SEQ_ID",
            "ERR_SIG_INVALID_DATA_LEN", "ERR_SIG_MISSING_S_TYPE_ID", "ERR_SIG_MISSING_S_LEN",
            "ERR_SIG_INVALID_S_LEN", "ERR_SIG_INVALID_R_INT_ID", "ERR_SIG_ZERO_R_LEN",
            "ERR_SIG_NEGATIVE_R", "ERR_SIG_TOO_MUCH_R_PADDING", "ERR_SIG_INVALID_S_INT_ID",
            "ERR_SIG_ZERO_S_LEN", "ERR_SIG_NEGATIVE_S", "ERR_SIG_TOO_MUCH_S_PADDING",
            "ERR_SIG_HASHTYPE",
        ),
        "SIG_HIGH_S": _codes("ERR_SIG_HIGH_S"),
        "SIG_NULLDUMMY": _codes("ERR_SIG_NULLDUMMY"),
        "SIG_PUSHONLY": _codes("ERR_NOT_PUSH_ONLY", "ERR_SIG_PUSHONLY"),
        "CLEANSTACK": _codes("ERR_CLEAN_STACK"),
        "BAD_OPCODE": _codes("ERR_RESERVED_OPCODE", "ERR_MALFORMED_PUSH"),
        "UNBALANCED_CONDITIONAL": _codes("ERR_UNBALANCED_CONDITIONAL", "ERR_INVALID_STACK_OPERATION"),
        "VERIFY": _codes("ERR_VERIFY"),
        "INVALID_STACK_OPERATION": _codes("ERR_INVALID_STACK_OPERATION"),
        "INVALID_ALTSTACK_OPERATION": _codes("ERR_INVALID_ALTSTACK_OPERATION"),
        "DISABLED_OPCODE": _codes("ERR_DISABLED_OPCODE"),
        "DISCOURAGE_UPGRADABLE_NOPS": _codes("ERR_DISCOURAGE_UPGRADABLE_NOPS"),
        "SCRIPTNUM_OVERFLOW": _codes("ERR_NUMBER_TOO_BIG"),
            "SCRIPTNUM_MINENCODE": _codes("ERR_MINIMAL_DATA"),
            "DIV_BY_ZERO": _codes("ERR_DIVIDE_BY_ZERO"),
            "MOD_BY_ZERO": _codes("ERR_DIVIDE_BY_ZERO"),
        "NUMBER_SIZE": _codes("ERR_NUMBER_TOO_BIG", "ERR_NUMBER_TOO_SMALL"),
        "PUSH_SIZE": _codes("ERR_ELEMENT_TOO_BIG"),
        "OP_COUNT": _codes("ERR_TOO_MANY_OPERATIONS"),
        "STACK_SIZE": _codes("ERR_STACK_OVERFLOW"),
        "SCRIPT_SIZE": _codes("ERR_SCRIPT_TOO_BIG"),
        "ELEMENT_SIZE": _codes("ERR_ELEMENT_TOO_BIG"),
        "PUBKEY_COUNT": _codes("ERR_PUBKEY_COUNT"),
        "SIG_COUNT": _codes("ERR_SIG_COUNT"),
            "PUBKEYTYPE": _codes("ERR_PUBKEY_TYPE"),
            "SIGTYPE": _codes("ERR_SIG_TYPE"),
        "MINIMALDATA": _codes("ERR_MINIMAL_DATA"),
        "MINIMALIF": _codes("ERR_MINIMAL_IF"),
        "CHECKSIGVERIFY": _codes("ERR_CHECK_SIG_VERIFY"),
        "OP_RETURN": _codes("ERR_EARLY_RETURN"),
    }
    if expected not in mapping:
        raise ValueError(f"unrecognized expected result in test data: {expected}")
    return [c for c in mapping[expected] if c is not None]


def _load_json(name: str) -> list[list[Any]]:
    p = VECTORS_DIR / name
    with p.open("rb") as f:
        return json.load(f)


@pytest.mark.parametrize("test_idx,test_vec", [(i, t) for i, t in enumerate(_load_json("script_tests.json")) if len(t) != 1])
def test_go_script_tests_json(test_idx: int, test_vec: list[Any]) -> None:
    # Format: [[wit..., amount]?, scriptSig, scriptPubKey, flags, expected, ...comment]
    vec = list(test_vec)

    input_amt_sats = 0
    if isinstance(vec[0], list):
        # Go scales by 1e8 for this file.
        amt = vec[0][0]
        if isinstance(amt, (int, float)):
            input_amt_sats = int(float(amt) * 100000000)
        vec = vec[1:]

    script_sig = parse_short_form(str(vec[0]))
    script_pubkey = parse_short_form(str(vec[1]))
    flags = parse_script_flags(str(vec[2]))
    expected = str(vec[3])
    allowed = allowed_error_codes(expected)

    # Build the spending tx like go-sdk reference_test.go createSpendingTx:
    # - Create a coinbase tx with one input (outpoint = 0..:0xffffffff, scriptSig = OP_0 OP_0)
    # - Add one output with the test locking script and amount
    # - Create a spending tx that spends that output, with the test unlocking script
    coinbase_tx = Transaction()
    coinbase_tx.add_input(
        TransactionInput(
            source_txid="00" * 32,
            source_output_index=0xFFFFFFFF,
            unlocking_script=Script.from_bytes(b"\x00\x00"),
            sequence=0xFFFFFFFF,
        )
    )
    coinbase_tx.add_output(TransactionOutput(locking_script=script_pubkey, satoshis=input_amt_sats))

    prev_out = coinbase_tx.outputs[0]

    tx = Transaction()
    tx.add_input(
        TransactionInput(
            source_transaction=coinbase_tx,
            source_output_index=0,
            unlocking_script=script_sig,
            sequence=0xFFFFFFFF,
        )
    )
    tx.add_output(TransactionOutput(locking_script=Script.from_bytes(b""), satoshis=input_amt_sats))

    engine = Engine()
    err = engine.execute(with_tx(tx, 0, prev_out), with_flags(flags))

    if expected == "OK":
        assert err is None, f"vector #{test_idx} expected OK, got {err}"
        return

    assert err is not None, f"vector #{test_idx} expected error {expected}, got OK"
    assert any(is_error_code(err, c) for c in allowed), f"vector #{test_idx} expected {expected} (codes={allowed}), got {err}"


def _build_prev_outs_from_inputs(inputs: list[Any]) -> dict[tuple[str, int], TransactionOutput]:
    """Build previous outputs dictionary from test vector inputs."""
    prev_outs: dict[tuple[str, int], TransactionOutput] = {}
    for inp in inputs:
        prev_hash = str(inp[0])
        prev_idx = int(inp[1])
        prev_script = parse_short_form(str(inp[2]))
        prev_value = int(inp[3]) if len(inp) == 4 else 0
        prev_outs[(prev_hash, prev_idx)] = TransactionOutput(locking_script=prev_script, satoshis=prev_value)
    return prev_outs


@pytest.mark.parametrize("test_idx,test_vec", [(i, t) for i, t in enumerate(_load_json("tx_valid.json")) if not (len(t) == 1 and isinstance(t[0], str))])
def test_go_tx_valid_json(test_idx: int, test_vec: list[Any]) -> None:
    # Format: [[[prev_hash, prev_index, prev_script, amount?]...], serializedTxHex, verifyFlags]
    inputs = test_vec[0]
    tx_hex = test_vec[1]
    flags_str = test_vec[2]

    tx = Transaction.from_hex(tx_hex)
    assert tx is not None, f"failed to parse tx hex for vector {test_idx}"

    flags = parse_script_flags(flags_str)
    prev_outs = _build_prev_outs_from_inputs(inputs)

    engine = Engine()
    for k, txin in enumerate(tx.inputs):
        prev = prev_outs.get((txin.source_txid, txin.source_output_index))
        assert prev is not None, f"missing prevout for input {k} in vector {test_idx}"
        err = engine.execute(with_tx(tx, k, prev), with_flags(flags))
        assert err is None, f"tx_valid vector {test_idx} failed at input {k}: {err}"


@pytest.mark.parametrize("test_idx,test_vec", [(i, t) for i, t in enumerate(_load_json("tx_invalid.json")) if not (len(t) == 1 and isinstance(t[0], str))])
def test_go_tx_invalid_json(test_idx: int, test_vec: list[Any]) -> None:
    inputs = test_vec[0]
    tx_hex = test_vec[1]
    flags_str = test_vec[2]

    tx = Transaction.from_hex(tx_hex)
    assert tx is not None, f"failed to parse tx hex for vector {test_idx}"

    flags = parse_script_flags(flags_str)
    prev_outs = _build_prev_outs_from_inputs(inputs)

    engine = Engine()
    # Any failing input is sufficient for the test case to be considered failing (mirrors Go)
    for k, txin in enumerate(tx.inputs):
        prev = prev_outs.get((txin.source_txid, txin.source_output_index))
        if prev is None:
            continue
        err = engine.execute(with_tx(tx, k, prev), with_flags(flags))
        if err is not None:
            return

    pytest.fail(f"tx_invalid vector {test_idx} succeeded when should fail")


