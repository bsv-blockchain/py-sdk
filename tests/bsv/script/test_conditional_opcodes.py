"""Conditional-branch behaviour: OP_VERIF and OP_VERNOTIF.

Both sit inside the `OP_IF..OP_ENDIF` opcode range, so they are reached inside
a skipped branch as well. The TS SDK (`Spend.ts`) and the Go SDK
(`interpreter/operations.go`) both leave the data stack alone there and only
push onto the conditional stack.
"""

import pytest

from bsv.script.script import Script
from bsv.script.spend import _USE_NATIVE_VM, Spend
from bsv.transaction_output import TransactionOutput


def _spend(locking_asm: str, unlocking_asm: str = "", tx_version: int = 2) -> Spend:
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
            "unlockingScript": Script.from_asm(unlocking_asm) if unlocking_asm else Script(),
            "inputSequence": 0xFFFFFFFF,
            "lockTime": 0,
        }
    )


def _run_both_paths(locking_asm: str, unlocking_asm: str = "") -> list:
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


@pytest.mark.parametrize("opcode", ["OP_VERIF", "OP_VERNOTIF"])
def test_skipped_branch_does_not_consume_the_operand(opcode):
    # The branch is not taken, so the OP_1 pushed by the unlocking script must
    # still be on the stack when the conditional closes.
    assert all(_run_both_paths(f"OP_0 OP_IF {opcode} OP_ENDIF OP_ENDIF", "OP_1"))


@pytest.mark.parametrize("opcode", ["OP_VERIF", "OP_VERNOTIF"])
def test_taken_branch_still_consumes_the_operand(opcode):
    # 4-byte little-endian tx version 2 matches, so OP_VERIF opens a true branch
    # and OP_VERNOTIF a false one.
    taken = opcode == "OP_VERIF"
    body = "OP_1" if taken else "OP_0"
    assert all(_run_both_paths(f"02000000 {opcode} {body} OP_ELSE {'OP_0' if taken else 'OP_1'} OP_ENDIF"))


def test_one_else_per_if_is_accepted():
    assert all(_run_both_paths("OP_IF OP_0 OP_ELSE OP_1 OP_ENDIF", "OP_0"))


def test_nested_ifs_each_get_their_own_else():
    # Both branches are taken, and each conditional uses its single OP_ELSE, so
    # the inner else must not count against the outer one.
    assert all(_run_both_paths("OP_IF OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF OP_ELSE OP_0 OP_ENDIF", "OP_1 OP_1"))


def test_else_without_if_is_rejected():
    _expect_rejected("OP_ELSE OP_1", "OP_1", "OP_ELSE requires a preceeding OP_IF")


def test_empty_stack_at_the_end_is_a_script_error():
    # Relaxed mode skips the clean-stack rule, so the final truthiness check can
    # be reached with nothing on the stack; that must not escape as IndexError.
    _expect_rejected("OP_1 OP_IF OP_VERIF OP_1 OP_ENDIF OP_ENDIF", "OP_1", "must be truthy")
