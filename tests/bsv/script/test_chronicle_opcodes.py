"""Tests for Chronicle opcode implementations."""

import pytest

from bsv.constants import OpCode
from bsv.script.spend import Spend

from .conftest import make_spend

# ============================================================
# OP_VER tests
# ============================================================


class TestOpVer:
    def test_not_disabled(self):
        assert not Spend.is_op_disabled(OpCode.OP_VER)

    def test_pushes_version_1(self):
        # OP_VER pushes 4-byte LE tx version; version 1 = [01,00,00,00]
        # Then OP_1 pushes 1, OP_NUMEQUALVERIFY checks equality, OP_TRUE leaves true on stack
        spend = make_spend("OP_VER 01000000 OP_EQUALVERIFY OP_TRUE", tx_version=1)
        assert spend.validate()

    def test_pushes_version_2(self):
        spend = make_spend("OP_VER 02000000 OP_EQUALVERIFY OP_TRUE", tx_version=2)
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
        with pytest.raises(RuntimeError):
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


# ============================================================
# OP_2MUL tests
# ============================================================


class TestOp2Mul:
    def test_not_disabled(self):
        assert not Spend.is_op_disabled(OpCode.OP_2MUL)

    def test_basic(self):
        spend = make_spend("OP_2MUL OP_6 OP_EQUALVERIFY OP_TRUE", "OP_3")
        assert spend.validate()

    def test_zero(self):
        spend = make_spend("OP_2MUL OP_0 OP_EQUALVERIFY OP_TRUE", "OP_0")
        assert spend.validate()

    def test_negative(self):
        spend = make_spend("OP_2MUL OP_1ADD OP_1ADD OP_0 OP_EQUALVERIFY OP_TRUE", "OP_1NEGATE")
        assert spend.validate()


# ============================================================
# OP_2DIV tests
# ============================================================


class TestOp2Div:
    def test_not_disabled(self):
        assert not Spend.is_op_disabled(OpCode.OP_2DIV)

    def test_basic(self):
        spend = make_spend("OP_2DIV OP_3 OP_EQUALVERIFY OP_TRUE", "OP_6")
        assert spend.validate()

    def test_truncation(self):
        spend = make_spend("OP_2DIV OP_3 OP_EQUALVERIFY OP_TRUE", "OP_7")
        assert spend.validate()

    def test_zero(self):
        spend = make_spend("OP_2DIV OP_0 OP_EQUALVERIFY OP_TRUE", "OP_0")
        assert spend.validate()

    def test_negative(self):
        spend = make_spend("OP_2DIV OP_1NEGATE OP_EQUALVERIFY OP_TRUE", "82")
        assert spend.validate()


# ============================================================
# OP_SUBSTR tests
# ============================================================


class TestOpSubstr:
    def test_basic(self):
        spend = make_spend(
            "OP_4 OP_5 OP_SUBSTR 426c6f636b OP_EQUALVERIFY OP_TRUE",
            "42535620426c6f636b636861696e",
        )
        assert spend.validate()

    def test_full_string(self):
        spend = make_spend(
            "OP_0 OP_3 OP_SUBSTR 616263 OP_EQUALVERIFY OP_TRUE",
            "616263",
        )
        assert spend.validate()

    def test_empty_source_error(self):
        spend = make_spend("OP_0 OP_0 OP_SUBSTR OP_TRUE", "OP_0")
        with pytest.raises(RuntimeError):
            spend.validate()

    def test_negative_length_error(self):
        spend = make_spend("OP_0 OP_1NEGATE OP_SUBSTR OP_TRUE", "616263")
        with pytest.raises(RuntimeError):
            spend.validate()

    def test_out_of_range_error(self):
        spend = make_spend("OP_1 OP_3 OP_SUBSTR OP_TRUE", "616263")
        with pytest.raises(RuntimeError):
            spend.validate()

    def test_insufficient_stack_error(self):
        spend = make_spend("OP_0 OP_SUBSTR OP_TRUE", "OP_0")
        with pytest.raises(RuntimeError):
            spend.validate()


# ============================================================
# OP_LEFT tests
# ============================================================


class TestOpLeft:
    def test_basic(self):
        spend = make_spend(
            "OP_3 OP_LEFT 425356 OP_EQUALVERIFY OP_TRUE",
            "42535620426c6f636b636861696e",
        )
        assert spend.validate()

    def test_zero_length(self):
        spend = make_spend("OP_0 OP_LEFT OP_0 OP_EQUALVERIFY OP_TRUE", "616263")
        assert spend.validate()

    def test_full_length(self):
        spend = make_spend("OP_3 OP_LEFT 616263 OP_EQUALVERIFY OP_TRUE", "616263")
        assert spend.validate()

    def test_overflow_error(self):
        spend = make_spend("OP_4 OP_LEFT OP_TRUE", "616263")
        with pytest.raises(RuntimeError):
            spend.validate()


# ============================================================
# OP_RIGHT tests
# ============================================================


class TestOpRight:
    def test_basic(self):
        spend = make_spend(
            "OP_5 OP_RIGHT 636861696e OP_EQUALVERIFY OP_TRUE",
            "42535620426c6f636b636861696e",
        )
        assert spend.validate()

    def test_zero_length(self):
        spend = make_spend("OP_0 OP_RIGHT OP_0 OP_EQUALVERIFY OP_TRUE", "616263")
        assert spend.validate()

    def test_full_length(self):
        spend = make_spend("OP_3 OP_RIGHT 616263 OP_EQUALVERIFY OP_TRUE", "616263")
        assert spend.validate()

    def test_one_byte(self):
        spend = make_spend("OP_1 OP_RIGHT 63 OP_EQUALVERIFY OP_TRUE", "616263")
        assert spend.validate()

    def test_overflow_error(self):
        spend = make_spend("OP_4 OP_RIGHT OP_TRUE", "616263")
        with pytest.raises(RuntimeError):
            spend.validate()

    def test_left_right_cat_roundtrip(self):
        spend = make_spend(
            "OP_DUP OP_2 OP_LEFT OP_SWAP OP_1 OP_RIGHT OP_CAT 616263 OP_EQUALVERIFY OP_TRUE",
            "616263",
        )
        assert spend.validate()


# ============================================================
# OP_LSHIFTNUM tests
# ============================================================


class TestOpLshiftnum:
    def test_basic(self):
        spend = make_spend("OP_3 OP_LSHIFTNUM OP_8 OP_EQUALVERIFY OP_TRUE", "OP_1")
        assert spend.validate()

    def test_zero_shift(self):
        spend = make_spend("OP_0 OP_LSHIFTNUM OP_5 OP_EQUALVERIFY OP_TRUE", "OP_5")
        assert spend.validate()

    def test_multi_byte_result(self):
        spend = make_spend("OP_1 OP_LSHIFTNUM fe01 OP_EQUALVERIFY OP_TRUE", "ff00")
        assert spend.validate()

    def test_negative_shift_error(self):
        spend = make_spend("OP_1NEGATE OP_LSHIFTNUM OP_TRUE", "OP_1")
        with pytest.raises(RuntimeError):
            spend.validate()


# ============================================================
# OP_RSHIFTNUM tests
# ============================================================


class TestOpRshiftnum:
    def test_basic(self):
        spend = make_spend("OP_3 OP_RSHIFTNUM OP_1 OP_EQUALVERIFY OP_TRUE", "OP_8")
        assert spend.validate()

    def test_zero_shift(self):
        spend = make_spend("OP_0 OP_RSHIFTNUM OP_5 OP_EQUALVERIFY OP_TRUE", "OP_5")
        assert spend.validate()

    def test_truncation(self):
        spend = make_spend("OP_1 OP_RSHIFTNUM OP_3 OP_EQUALVERIFY OP_TRUE", "OP_7")
        assert spend.validate()

    def test_negative_number(self):
        spend = make_spend("OP_2 OP_RSHIFTNUM 82 OP_EQUALVERIFY OP_TRUE", "88")
        assert spend.validate()
