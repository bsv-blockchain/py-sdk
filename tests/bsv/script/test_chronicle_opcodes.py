"""Tests for Chronicle opcode implementations."""

import pytest

from bsv.constants import OpCode
from bsv.script.script import Script
from bsv.script.spend import Spend
from bsv.transaction_output import TransactionOutput


def make_spend(locking_asm: str, unlocking_asm: str = "", tx_version: int = 1) -> Spend:
    """Helper to create a Spend for testing script execution."""
    locking = Script.from_asm(locking_asm)
    unlocking = Script.from_asm(unlocking_asm) if unlocking_asm else Script()
    return Spend({
        "sourceTXID": "00" * 32,
        "sourceOutputIndex": 0,
        "sourceSatoshis": 1000,
        "lockingScript": locking,
        "transactionVersion": tx_version,
        "otherInputs": [],
        "outputs": [TransactionOutput(locking_script=Script(), satoshis=999)],
        "inputIndex": 0,
        "unlockingScript": unlocking,
        "inputSequence": 0xFFFFFFFF,
        "lockTime": 0,
    })


# ============================================================
# OP_VER tests
# ============================================================

class TestOpVer:
    def test_not_disabled(self):
        assert not Spend.is_op_disabled(OpCode.OP_VER)

    def test_pushes_version_1(self):
        # OP_VER pushes 4-byte LE tx version; version 1 = [01,00,00,00]
        # Then OP_1 pushes 1, OP_NUMEQUALVERIFY checks equality, OP_TRUE leaves true on stack
        spend = make_spend("OP_VER OP_1 OP_NUMEQUALVERIFY OP_TRUE", tx_version=1)
        assert spend.validate()

    def test_pushes_version_2(self):
        spend = make_spend("OP_VER OP_2 OP_NUMEQUALVERIFY OP_TRUE", tx_version=2)
        assert spend.validate()

    def test_pushes_version_0xff00(self):
        # Version 0xFF00 = 65280 as 4-byte LE: [00, ff, 00, 00]
        # We push the expected value and compare with OP_EQUAL
        spend = make_spend("OP_VER OP_EQUAL", "00ff0000", tx_version=0xFF00)
        assert spend.validate()


# ============================================================
# OP_VERIF tests
# ============================================================

class TestOpVerif:
    def test_not_disabled(self):
        assert not Spend.is_op_disabled(OpCode.OP_VERIF)

    def test_matching_version(self):
        # Push 4-byte LE of version 1 [01,00,00,00], then OP_VERIF
        # tx version >= popped value => TRUE branch executes
        spend = make_spend("OP_VERIF OP_TRUE OP_ELSE OP_FALSE OP_ENDIF", "01000000", tx_version=1)
        assert spend.validate()

    def test_non_matching_version(self):
        # Push 4-byte LE of version 2 [02,00,00,00], tx version is 1
        # 1 >= 2 is FALSE => FALSE branch
        spend = make_spend("OP_VERIF OP_FALSE OP_ELSE OP_TRUE OP_ENDIF", "02000000", tx_version=1)
        assert spend.validate()

    def test_non_4byte_always_false(self):
        # Push 3 bytes — non-4-byte values always evaluate as FALSE
        spend = make_spend("OP_VERIF OP_FALSE OP_ELSE OP_TRUE OP_ENDIF", "010000", tx_version=1)
        assert spend.validate()

    def test_5byte_always_false(self):
        # Push 5 bytes — also non-matching
        spend = make_spend("OP_VERIF OP_FALSE OP_ELSE OP_TRUE OP_ENDIF", "0100000000", tx_version=1)
        assert spend.validate()

    def test_empty_stack_error(self):
        # No value on stack before OP_VERIF
        spend = make_spend("OP_VERIF OP_TRUE OP_ENDIF", tx_version=1)
        with pytest.raises(Exception):
            spend.validate()


# ============================================================
# OP_VERNOTIF tests
# ============================================================

class TestOpVernotif:
    def test_not_disabled(self):
        assert not Spend.is_op_disabled(OpCode.OP_VERNOTIF)

    def test_matching_version_goes_false(self):
        # Matching version => VERNOTIF negates => FALSE branch
        spend = make_spend("OP_VERNOTIF OP_FALSE OP_ELSE OP_TRUE OP_ENDIF", "01000000", tx_version=1)
        assert spend.validate()

    def test_non_matching_version_goes_true(self):
        # Non-matching => VERNOTIF negates => TRUE branch
        spend = make_spend("OP_VERNOTIF OP_TRUE OP_ELSE OP_FALSE OP_ENDIF", "02000000", tx_version=1)
        assert spend.validate()
