"""Conformance tests for OP_LSHIFT / OP_RSHIFT.

Both opcodes shift by *bits* and preserve the operand's byte width, matching
the TS SDK (`Spend.ts`) and Go SDK (`interpreter/operations.go`).  Expected
values are taken from those reference implementations.
"""

import pytest

from bsv.script.spend import _USE_NATIVE_VM

from .conftest import make_spend

# (operand hex, shift count, is_left_shift, expected hex)
SHIFT_VECTORS = [
    ("ff00", 1, True, "fe00"),
    ("ff00", 4, True, "f000"),
    ("ff00", 8, True, "0000"),
    ("ff00", 1, False, "7f80"),
    ("ff00", 8, False, "00ff"),
    ("80", 1, True, "00"),
    ("80", 1, False, "40"),
    ("01", 1, True, "02"),
    ("123456", 4, True, "234560"),
    ("123456", 4, False, "012345"),
    ("ffffffff", 16, True, "ffff0000"),
    ("ffffffff", 16, False, "0000ffff"),
    ("ff00", 0, True, "ff00"),
    ("ff00", 0, False, "ff00"),
]


def _num_asm(n: int) -> str:
    """Encode a shift count as a script number push (OP_0 for zero)."""
    if n == 0:
        return "OP_0"
    out = bytearray()
    v = n
    while v:
        out.append(v & 0xFF)
        v >>= 8
    if out[-1] & 0x80:
        out.append(0)
    return bytes(out).hex()


def _shift_asm(operand: str, n: int, left: bool, expected: str) -> str:
    op = "OP_LSHIFT" if left else "OP_RSHIFT"
    exp = expected if expected else "OP_0"
    return f"{operand} {_num_asm(n)} {op} {exp} OP_EQUAL"


def _run_both_paths(asm: str, tx_version: int = 2) -> list:
    """Return each VM path's result so native and Python stay in lockstep."""
    spend = make_spend(asm, tx_version=tx_version)
    results = [spend._validate_python()]
    if _USE_NATIVE_VM:
        results.append(make_spend(asm, tx_version=tx_version)._validate_native())
    return results


@pytest.mark.parametrize("operand,n,left,expected", SHIFT_VECTORS)
def test_shift_matches_reference_sdks(operand, n, left, expected):
    asm = _shift_asm(operand, n, left, expected)
    assert all(_run_both_paths(asm))


@pytest.mark.parametrize("left", [True, False])
def test_shift_beyond_operand_width_clears_every_bit(left):
    # 2-byte operand, 16-bit width: shifting by the full width leaves zeros
    # rather than growing the result to the shift count.
    assert all(_run_both_paths(_shift_asm("ff00", 16, left, "0000")))


@pytest.mark.parametrize("left", [True, False])
def test_huge_shift_count_is_bounded(left):
    # Regression: a 5-byte shift count (~21.5e9) once sized the result buffer,
    # so a 6-byte script could request a 21 GB allocation.  The result must
    # stay at the operand's width.
    assert all(_run_both_paths(_shift_asm("ff00", 0x0500000000, left, "0000")))


@pytest.mark.parametrize("left", [True, False])
def test_shift_consumes_both_operands(left):
    # After the shift only its result may remain: drop it and the stack is empty.
    op = "OP_LSHIFT" if left else "OP_RSHIFT"
    asm = f"ff00 01 {op} OP_DROP OP_DEPTH OP_0 OP_NUMEQUAL"
    assert all(_run_both_paths(asm))


@pytest.mark.parametrize("left", [True, False])
def test_empty_operand_stays_empty(left):
    op = "OP_LSHIFT" if left else "OP_RSHIFT"
    asm = f"OP_0 01 {op} OP_SIZE OP_0 OP_NUMEQUAL"
    assert all(_run_both_paths(asm))


@pytest.mark.parametrize("left", [True, False])
def test_negative_shift_count_is_rejected(left):
    op = "OP_LSHIFT" if left else "OP_RSHIFT"
    # 0x81 is script-number -1
    asm = f"ff00 81 {op} OP_TRUE"
    spend = make_spend(asm, tx_version=2)
    with pytest.raises(RuntimeError, match="non-negative"):
        spend._validate_python()
    if _USE_NATIVE_VM:
        with pytest.raises(RuntimeError, match="non-negative"):
            make_spend(asm, tx_version=2)._validate_native()
