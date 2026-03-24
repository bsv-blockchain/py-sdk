"""Comprehensive Chronicle upgrade tests — regression, integration, edge cases."""

import pytest

from bsv.constants import OpCode, SIGHASH
from bsv.script.script import Script
from bsv.script.spend import Spend
from bsv.transaction_output import TransactionOutput


def make_spend(locking_asm: str, unlocking_asm: str = "", tx_version: int = 1) -> Spend:
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
# Regression tests
# ============================================================

class TestOpVerEncoding:
    def test_4byte_le_not_script_number(self):
        """OP_VER must push exactly 4 bytes LE, not script-number encoding."""
        spend = make_spend("OP_VER OP_SIZE OP_4 OP_EQUALVERIFY OP_DROP OP_TRUE", tx_version=1)
        assert spend.validate()

    def test_version_2_is_4_bytes(self):
        spend = make_spend("OP_VER OP_SIZE OP_4 OP_EQUALVERIFY OP_DROP OP_TRUE", tx_version=2)
        assert spend.validate()


class TestOpRightSlice:
    def test_right_slice_correctness(self):
        """OP_RIGHT uses data[size - length:] — verify correctness."""
        # "abcde" = 6162636465, RIGHT 2 => "de" = 6465
        spend = make_spend("OP_2 OP_RIGHT 6465 OP_EQUALVERIFY OP_TRUE", "6162636465")
        assert spend.validate()

    def test_right_1_of_single_byte(self):
        # RIGHT 1 of single byte "a" = 61 => "a"
        spend = make_spend("OP_1 OP_RIGHT 61 OP_EQUALVERIFY OP_TRUE", "61")
        assert spend.validate()


class TestLeftRightCatComposition:
    def test_split_and_rejoin(self):
        """LEFT + RIGHT + CAT reconstructs the original string."""
        # "hello" = 68656c6c6f, split at 2: LEFT(2)="he", RIGHT(3)="llo"
        spend = make_spend(
            "OP_DUP OP_2 OP_LEFT OP_SWAP OP_3 OP_RIGHT OP_CAT 68656c6c6f OP_EQUALVERIFY OP_TRUE",
            "68656c6c6f",
        )
        assert spend.validate()


# ============================================================
# Valid NOPs still work
# ============================================================

class TestValidNopsStillWork:
    def test_nop1(self):
        spend = make_spend("OP_NOP1 OP_TRUE")
        assert spend.validate()

    def test_nop2_cltv(self):
        spend = make_spend("OP_NOP2 OP_TRUE")
        assert spend.validate()

    def test_nop3_csv(self):
        spend = make_spend("OP_NOP3 OP_TRUE")
        assert spend.validate()

    def test_nop9(self):
        spend = make_spend("OP_NOP9 OP_TRUE")
        assert spend.validate()

    def test_nop10(self):
        spend = make_spend("OP_NOP10 OP_TRUE")
        assert spend.validate()


# ============================================================
# Version 1 preserves all pre-Chronicle restrictions
# ============================================================

class TestVersion1PreservesRestrictions:
    def test_v1_rejects_dirty_stack(self):
        spend = make_spend("OP_TRUE", "OP_1 OP_2", tx_version=1)
        with pytest.raises(Exception, match="clean stack"):
            spend.validate()

    def test_v1_rejects_opcodes_in_unlocking(self):
        spend = make_spend("OP_2 OP_EQUALVERIFY OP_TRUE", "OP_1 OP_1 OP_ADD", tx_version=1)
        with pytest.raises(Exception, match="push operations"):
            spend.validate()

    def test_v1_disabled_opcodes_list_empty(self):
        """After Chronicle, no opcodes are disabled."""
        assert not Spend.is_op_disabled(OpCode.OP_VER)
        assert not Spend.is_op_disabled(OpCode.OP_VERIF)
        assert not Spend.is_op_disabled(OpCode.OP_VERNOTIF)
        assert not Spend.is_op_disabled(OpCode.OP_2MUL)
        assert not Spend.is_op_disabled(OpCode.OP_2DIV)


# ============================================================
# Version 2 with Chronicle opcodes + relaxed rules
# ============================================================

class TestVersion2Integration:
    def test_v2_op_ver_with_verif(self):
        """v2 tx using OP_VER and OP_VERIF together."""
        # Push version 2 as 4-byte LE, then VERIF checks >= version 2
        spend = make_spend("OP_VERIF OP_TRUE OP_ELSE OP_FALSE OP_ENDIF", "02000000", tx_version=2)
        assert spend.validate()

    def test_v2_dirty_stack_allowed(self):
        spend = make_spend("OP_TRUE", "OP_1 OP_2 OP_3", tx_version=2)
        assert spend.validate()

    def test_v2_opcodes_in_unlocking(self):
        spend = make_spend("OP_3 OP_EQUALVERIFY OP_TRUE", "OP_1 OP_2 OP_ADD", tx_version=2)
        assert spend.validate()

    def test_v2_new_opcodes_work(self):
        """All new Chronicle opcodes execute in v2 tx."""
        # OP_2MUL: 3 * 2 = 6
        spend = make_spend("OP_2MUL OP_6 OP_EQUALVERIFY OP_TRUE", "OP_3", tx_version=2)
        assert spend.validate()

        # OP_SUBSTR: "abc" start=1 len=1 => "b"
        spend = make_spend("OP_1 OP_1 OP_SUBSTR 62 OP_EQUALVERIFY OP_TRUE", "616263", tx_version=2)
        assert spend.validate()

        # OP_LSHIFTNUM: 1 << 4 = 16
        spend = make_spend("OP_4 OP_LSHIFTNUM OP_16 OP_EQUALVERIFY OP_TRUE", "OP_1", tx_version=2)
        assert spend.validate()


# ============================================================
# Large number tests
# ============================================================

class TestLargeNumbers:
    def test_large_multiply(self):
        """Large script numbers work with OP_MUL."""
        # 1000 * 1000 = 1000000
        # 1000 = e803, 1000000 = 40420f
        spend = make_spend(
            "OP_MUL 40420f OP_EQUALVERIFY OP_TRUE",
            "e803 e803",
        )
        assert spend.validate()

    def test_2mul_large(self):
        """OP_2MUL with larger numbers."""
        # 128 * 2 = 256; 128 = 8000 (sign bit), 256 = 0001
        spend = make_spend("OP_2MUL 0001 OP_EQUALVERIFY OP_TRUE", "8000")
        assert spend.validate()
