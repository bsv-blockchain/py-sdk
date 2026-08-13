"""Range checking for OP_SUBSTR.

The offset and length both come off the stack, so the range check has to hold
for hostile values, not just plausible ones. It mirrors the TS SDK
(`Spend.ts`) and Go SDK (`interpreter/operations.go`): the offset must fall
inside the operand, and the length must fit in what remains.
"""

import pytest

from bsv.script.spend import _USE_NATIVE_VM

from .conftest import make_spend

LLONG_MAX = 0x7FFFFFFFFFFFFFFF


def _num_asm(n: int) -> str:
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


def _run_both_paths(asm: str, tx_version: int = 2) -> list:
    """Return each VM path's result so native and Python stay in lockstep."""
    results = [make_spend(asm, tx_version=tx_version)._validate_python()]
    if _USE_NATIVE_VM:
        results.append(make_spend(asm, tx_version=tx_version)._validate_native())
    return results


def _expect_rejected(asm: str, tx_version: int = 2) -> None:
    with pytest.raises(RuntimeError, match="OP_SUBSTR"):
        make_spend(asm, tx_version=tx_version)._validate_python()
    if _USE_NATIVE_VM:
        native_spend = make_spend(asm, tx_version=tx_version)
        with pytest.raises(RuntimeError, match="OP_SUBSTR"):
            native_spend._validate_native()


@pytest.mark.parametrize(
    "data,start,length,expected",
    [
        ("aabbcc", 0, 3, "aabbcc"),
        ("aabbcc", 1, 2, "bbcc"),
        ("aabbcc", 2, 1, "cc"),
        ("aabbcc", 0, 0, "OP_0"),
        ("aabbcc", 2, 0, "OP_0"),
    ],
)
def test_substr_extracts_expected_range(data, start, length, expected):
    asm = f"{data} {_num_asm(start)} {_num_asm(length)} OP_SUBSTR {expected} OP_EQUAL"
    assert all(_run_both_paths(asm))


@pytest.mark.parametrize("length", [1, 16, 256 * 1024 * 1024])
def test_offset_near_llong_max_is_rejected(length):
    # Regression: `start + length` was compared against the operand size with
    # both values as long long, so an offset near LLONG_MAX overflowed to a
    # negative sum and slipped past the bound. The native VM then read from
    # `data + start` -- an out-of-bounds read that returned live process bytes
    # onto the stack for small lengths and segfaulted for large ones.
    _expect_rejected(f"aa {_num_asm(LLONG_MAX)} {_num_asm(length)} OP_SUBSTR OP_TRUE")


def test_offset_too_wide_for_int64_is_rejected():
    # Wider than long long: the conversion fails rather than overflowing.
    _expect_rejected(f"aa {_num_asm(1 << 100)} OP_1 OP_SUBSTR OP_TRUE")


def test_offset_at_operand_length_is_rejected():
    # TS/Go both require offset < size, even when nothing would be copied.
    _expect_rejected("aa OP_1 OP_0 OP_SUBSTR OP_TRUE")


def test_length_past_end_is_rejected():
    _expect_rejected("aabbcc OP_1 OP_3 OP_SUBSTR OP_TRUE")


def test_negative_offset_is_rejected():
    # 0x81 is script-number -1
    _expect_rejected("aabbcc 81 OP_1 OP_SUBSTR OP_TRUE")


def test_negative_length_is_rejected():
    _expect_rejected("aabbcc OP_1 81 OP_SUBSTR OP_TRUE")


def test_empty_operand_is_rejected():
    _expect_rejected("OP_0 OP_0 OP_0 OP_SUBSTR OP_TRUE")
