"""Conformance tests for OP_DIV, OP_MOD and OP_NUM2BIN.

Division truncates toward zero and the remainder takes the dividend's sign,
matching the TS SDK (BigInt `/` and `%`) and the Go SDK (`big.Int.Quo` and
`big.Int.Rem`). Python's `//` and `%` follow neither for mixed-sign operands.
"""

import pytest

from bsv.script.spend import _USE_NATIVE_VM

from .conftest import make_spend

# script-number encodings used below: 0x81 = -1, 0x82 = -2, 0x87 = -7, 0x88 = -8
DIV_VECTORS = [
    ("07", "02", "03"),  # 7 / 2 = 3
    ("87", "02", "83"),  # -7 / 2 = -3, not -4
    ("07", "82", "83"),  # 7 / -2 = -3, not -4
    ("87", "82", "03"),  # -7 / -2 = 3
    ("81", "02", "OP_0"),  # -1 / 2 = 0, not -1
    ("88", "02", "84"),  # -8 / 2 = -4 (exact, both conventions agree)
]

MOD_VECTORS = [
    ("07", "02", "01"),  # 7 % 2 = 1
    ("87", "02", "81"),  # -7 % 2 = -1, not 1
    ("07", "82", "01"),  # 7 % -2 = 1, not -1
    ("87", "82", "81"),  # -7 % -2 = -1
    ("88", "02", "OP_0"),  # -8 % 2 = 0
]

NUM2BIN_VECTORS = [
    ("OP_0", "OP_0", "OP_0"),  # zero into zero bytes
    ("OP_0", "OP_1", "00"),
    ("OP_0", "OP_4", "00000000"),
    ("OP_1", "OP_4", "01000000"),
    ("81", "OP_1", "81"),  # -1 already fits
    ("81", "OP_4", "01000080"),  # sign bit moves to the new high byte
]


def _run_both_paths(asm: str, tx_version: int = 2) -> list:
    """Return each VM path's result so native and Python stay in lockstep."""
    results = [make_spend(asm, tx_version=tx_version)._validate_python()]
    if _USE_NATIVE_VM:
        results.append(make_spend(asm, tx_version=tx_version)._validate_native())
    return results


@pytest.mark.parametrize("dividend,divisor,expected", DIV_VECTORS)
def test_div_truncates_toward_zero(dividend, divisor, expected):
    assert all(_run_both_paths(f"{dividend} {divisor} OP_DIV {expected} OP_EQUAL"))


@pytest.mark.parametrize("dividend,divisor,expected", MOD_VECTORS)
def test_mod_takes_dividend_sign(dividend, divisor, expected):
    assert all(_run_both_paths(f"{dividend} {divisor} OP_MOD {expected} OP_EQUAL"))


@pytest.mark.parametrize("opcode", ["OP_DIV", "OP_MOD"])
def test_division_by_zero_is_rejected(opcode):
    spend = make_spend(f"07 OP_0 {opcode} OP_TRUE", tx_version=2)
    with pytest.raises(RuntimeError, match="divide by zero"):
        spend._validate_python()
    if _USE_NATIVE_VM:
        native_spend = make_spend(f"07 OP_0 {opcode} OP_TRUE", tx_version=2)
        with pytest.raises(RuntimeError, match="divide by zero"):
            native_spend._validate_native()


@pytest.mark.parametrize("value,size,expected", NUM2BIN_VECTORS)
def test_num2bin_widens_to_requested_size(value, size, expected):
    # Regression: zero encodes to no bytes, and the widening path then mixed an
    # int with a bytes sentinel and indexed an empty buffer -- the pure-Python
    # VM raised TypeError/IndexError out of validate() where the native VM
    # returned a result.
    assert all(_run_both_paths(f"{value} {size} OP_NUM2BIN {expected} OP_EQUAL"))


def test_num2bin_rejects_size_smaller_than_value():
    spend = make_spend("0102 OP_1 OP_NUM2BIN OP_TRUE", tx_version=2)
    with pytest.raises(RuntimeError, match="OP_NUM2BIN"):
        spend._validate_python()
    if _USE_NATIVE_VM:
        native_spend = make_spend("0102 OP_1 OP_NUM2BIN OP_TRUE", tx_version=2)
        with pytest.raises(RuntimeError, match="OP_NUM2BIN"):
            native_spend._validate_native()
