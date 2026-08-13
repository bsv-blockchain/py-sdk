"""Only the data stack crosses the unlocking→locking script boundary.

The alt stack, the conditional stack and the code-separator position are all
per-script in the TS SDK (`Spend.ts`) and the Go SDK (`interpreter/thread.go`),
which also reject a conditional left open at the end of the unlocking script.
"""

import pytest

from bsv.script.script import Script
from bsv.script.spend import _USE_NATIVE_VM, Spend
from bsv.transaction_output import TransactionOutput


def _spend(locking_asm: str, unlocking_asm: str, tx_version: int = 2) -> Spend:
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
            "unlockingScript": Script.from_asm(unlocking_asm),
            "inputSequence": 0xFFFFFFFF,
            "lockTime": 0,
        }
    )


def _run_both_paths(locking_asm: str, unlocking_asm: str) -> list:
    results = [_spend(locking_asm, unlocking_asm)._validate_python()]
    if _USE_NATIVE_VM:
        results.append(_spend(locking_asm, unlocking_asm)._validate_native())
    return results


def _expect_rejected(locking_asm: str, unlocking_asm: str, match: str) -> None:
    python_spend = _spend(locking_asm, unlocking_asm)
    with pytest.raises(RuntimeError, match=match):
        python_spend._validate_python()
    if _USE_NATIVE_VM:
        native_spend = _spend(locking_asm, unlocking_asm)
        with pytest.raises(RuntimeError, match=match):
            native_spend._validate_native()


def test_alt_stack_does_not_cross_the_boundary():
    # The unlocking script stashes a value; the locking script must not find it.
    _expect_rejected("OP_FROMALTSTACK", "OP_1 OP_TOALTSTACK OP_1", "OP_FROMALTSTACK")


def test_conditional_left_open_in_unlocking_script_is_rejected():
    _expect_rejected("OP_ENDIF OP_1", "OP_1 OP_IF", "prior to the end of the unlocking script")


def test_alt_stack_still_works_within_one_script():
    assert all(_run_both_paths("OP_1 OP_TOALTSTACK OP_FROMALTSTACK", ""))


def test_balanced_conditional_within_one_script_still_works():
    assert all(_run_both_paths("OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF", "OP_1"))


def test_ordinary_unlocking_script_still_hands_over_the_data_stack():
    # The data stack is the one thing that does cross.
    assert all(_run_both_paths("OP_1 OP_EQUAL", "OP_1"))
