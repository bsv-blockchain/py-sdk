"""Numeric operands must be minimally encoded where minimal pushes are.

The node derives one `requireMinimal` from `VerifyMinimalData(flags) &&
EnforceNonMalleability(flags, version)` and uses it for both `CheckMinimalPush`
and every `CScriptNum` construction. py-sdk applied it to pushes only, so
`0x0100` — a minimal *push* but a non-minimal *number* for 1 — was accepted as
an operand where the node rejects it.
"""

import pytest

from bsv.script.spend import _USE_NATIVE_VM, Spend

from .conftest import make_spend


def _accepted(locking_asm: str, tx_version: int) -> bool:
    """True when both VM paths accept; asserts they agree."""
    results = [make_spend(locking_asm, tx_version=tx_version)._validate_python()]
    if _USE_NATIVE_VM:
        results.append(make_spend(locking_asm, tx_version=tx_version)._validate_native())
    assert len(set(results)) == 1, results
    return results[0]


def _rejected(locking_asm: str, tx_version: int) -> None:
    python_spend = make_spend(locking_asm, tx_version=tx_version)
    with pytest.raises(RuntimeError, match="non-minimally encoded script number"):
        python_spend._validate_python()
    if _USE_NATIVE_VM:
        native_spend = make_spend(locking_asm, tx_version=tx_version)
        with pytest.raises(RuntimeError, match="non-minimally encoded script number"):
            native_spend._validate_native()


@pytest.mark.parametrize(
    "octets,minimal",
    [
        (b"", True),
        (b"\x01", True),
        (b"\x81", True),  # -1
        (b"\x80", False),  # negative zero
        (b"\x00", False),  # padded zero
        (b"\x01\x00", False),  # 1 with a redundant high byte
        (b"\x00\x80", False),
        (b"\x80\x00", True),  # 128 needs the extra byte for its sign bit
        (b"\xff\x00", True),
        (b"\x01\x00\x00", False),
    ],
)
def test_minimality_predicate(octets, minimal):
    assert Spend.is_minimally_encoded_number(octets) is minimal


def test_non_minimal_operand_is_rejected_when_strict():
    # 0x0100 is 1 with a redundant high byte: a minimal push, not a minimal number.
    _rejected("0100 OP_1ADD OP_2 OP_NUMEQUAL", tx_version=1)


def test_negative_zero_operand_is_rejected_when_strict():
    _rejected("80 OP_NOT OP_1 OP_NUMEQUAL", tx_version=1)


def test_non_minimal_operand_is_allowed_when_relaxed():
    # Chronicle relaxes this together with minimal pushes, for version > 1.
    assert _accepted("0100 OP_1ADD OP_2 OP_NUMEQUAL", tx_version=2)


def test_minimal_operand_is_unaffected():
    assert _accepted("OP_1 OP_1ADD OP_2 OP_NUMEQUAL", tx_version=1)


def test_op_bin2num_still_accepts_a_non_minimal_input():
    # Minimising a non-minimal encoding is what the opcode is for, so the node
    # reads the element directly instead of through CScriptNum.
    assert _accepted("0100 OP_BIN2NUM OP_1 OP_NUMEQUAL", tx_version=1)


@pytest.mark.parametrize(
    "locking_asm",
    [
        "OP_1 00 OP_PICK OP_DROP",
        "OP_1 00 OP_ROLL",
        "ff00 00 OP_LSHIFT ff00 OP_EQUAL",
        "ff00 00 OP_RSHIFT ff00 OP_EQUAL",
    ],
)
def test_count_operands_are_numbers_too(locking_asm):
    # `00` is zero pushed as a non-minimal number. The C VM read the count of
    # OP_PICK, OP_ROLL, OP_LSHIFT and OP_RSHIFT unchecked, so it accepted these
    # where the node and the Python VM reject them (found by comparing with GoBDK).
    _rejected(locking_asm, tx_version=1)
    assert _accepted(locking_asm, tx_version=2)


@pytest.mark.parametrize("tx_version", [1, 2])
def test_num2bin_value_need_not_be_minimal(tx_version):
    # Only OP_NUM2BIN's size is a script number. The node normalises the value's
    # bytes (MinimallyEncode) instead, so `0100` (a non-minimal 1) padded to two
    # bytes is `0100` again, also in a version 1 transaction.
    assert _accepted("0100 OP_2 OP_NUM2BIN 0100 OP_EQUAL", tx_version=tx_version)


@pytest.mark.parametrize("op", ["OP_PICK", "OP_ROLL"])
def test_pick_and_roll_check_the_count_before_popping_it(op):
    # The node and the Python VM reject a non-minimal count with the count still
    # on the stack; the C VM popped it first, so the error showed a smaller stack.
    messages = []
    for native in [False, True] if _USE_NATIVE_VM else [False]:
        spend = make_spend(f"OP_1 00 {op}", tx_version=1)
        with pytest.raises(RuntimeError, match="non-minimally encoded script number") as e:
            spend._validate_native() if native else spend._validate_python()
        messages.append(str(e.value))
    assert len(set(messages)) == 1, messages
