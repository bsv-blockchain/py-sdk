"""A stack element wider than the script-number ceiling is not a number.

The node rejects it in `CScriptNum`'s span constructor — `if(span.size() >
max_length) throw scriptnum_overflow_error` — before the bytes reach any
arithmetic, so the operand size is bounded by the rule rather than by whatever
the script managed to build.
"""

import pytest

from bsv.script.script import Script
from bsv.script.spend import _USE_NATIVE_VM, MAX_SCRIPT_NUMBER_LENGTH_AFTER_CHRONICLE, Spend
from bsv.transaction_output import TransactionOutput


def _spend(locking_asm: str, tx_version: int = 2) -> Spend:
    return Spend(
        {
            "sourceTXID": "00" * 32,
            "sourceOutputIndex": 0,
            "sourceSatoshis": 1000,
            "lockingScript": Script.from_asm(locking_asm),
            "transactionVersion": tx_version,
            "otherInputs": [],
            "outputs": [TransactionOutput(locking_script=Script(), satoshis=999)],
            "inputIndex": 0,
            "unlockingScript": Script(),
            "inputSequence": 0xFFFFFFFF,
            "lockTime": 0,
        }
    )


def test_ceiling_matches_the_node():
    # MaxScriptNumLength() for the post-Chronicle era.
    assert MAX_SCRIPT_NUMBER_LENGTH_AFTER_CHRONICLE == 32 * 1024 * 1024


def test_bin2num_rejects_an_oversized_element():
    oversized = b"\x01" * (MAX_SCRIPT_NUMBER_LENGTH_AFTER_CHRONICLE + 1)
    with pytest.raises(ValueError, match="script number overflow"):
        Spend.bin2num(oversized)


def test_bin2num_accepts_an_element_at_the_ceiling():
    at_limit = b"\x01" * MAX_SCRIPT_NUMBER_LENGTH_AFTER_CHRONICLE
    assert Spend.bin2num(at_limit) > 0


@pytest.mark.parametrize("size", [1, 4, 8, 9, 64, 1000])
def test_ordinary_operands_are_unaffected(size):
    value = (1 << (size * 8 - 9)) if size > 1 else 1
    assert Spend.bin2num(Spend.minimally_encode(value)) == value


def test_oversized_operand_fails_the_script_not_the_interpreter():
    # OP_NUM2BIN can build an element past the ceiling; reading it back as a
    # number must be a script error on both paths, not a raw exception.
    over = MAX_SCRIPT_NUMBER_LENGTH_AFTER_CHRONICLE + 1
    asm = f"OP_1 {over.to_bytes(4, 'little').hex()} OP_NUM2BIN OP_1ADD OP_DROP OP_1"
    python_spend = _spend(asm)
    with pytest.raises(RuntimeError, match="script number overflow"):
        python_spend._validate_python()
    if _USE_NATIVE_VM:
        native_spend = _spend(asm)
        with pytest.raises(RuntimeError, match="script number overflow"):
            native_spend._validate_native()
