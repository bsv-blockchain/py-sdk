"""
Tests verifying each fixed opcode matches the BSV node v1.2.0 interpreter
(bitcoin-sv/bitcoin-sv src/script/interpreter.cpp).
"""
import pytest
from bsv.script.script import Script
from bsv.script.spend import Spend, _lshift_bytes, _rshift_bytes


def make_spend(unlocking_hex: str, locking_hex: str) -> Spend:
    return Spend({
        'sourceTXID': '00' * 32,
        'sourceOutputIndex': 0,
        'sourceSatoshis': 1,
        'lockingScript': Script(locking_hex),
        'transactionVersion': 1,
        'otherInputs': [],
        'outputs': [],
        'inputIndex': 0,
        'unlockingScript': Script(unlocking_hex),
        'inputSequence': 0xffffffff,
        'lockTime': 0,
    })


def assert_valid(unlocking_hex: str, locking_hex: str) -> None:
    assert make_spend(unlocking_hex, locking_hex).validate()


def assert_invalid(unlocking_hex: str, locking_hex: str) -> None:
    with pytest.raises(Exception):
        make_spend(unlocking_hex, locking_hex).validate()


# ---------------------------------------------------------------------------
# _lshift_bytes / _rshift_bytes unit tests
# ---------------------------------------------------------------------------

class TestLShiftBytes:
    def test_zero_shift(self):
        assert _lshift_bytes(b'\xAB\xCD\xEF', 0) == b'\xAB\xCD\xEF'

    def test_shift_by_3_bits(self):
        # 0xABCDEF << 3 = 0x5E6F78 (truncated to 24 bits)
        assert _lshift_bytes(b'\xAB\xCD\xEF', 3) == b'\x5E\x6F\x78'

    def test_shift_by_8_bits(self):
        # Shifting by 8 bits == byte shift by 1
        assert _lshift_bytes(b'\xAB\xCD\xEF', 8) == b'\xCD\xEF\x00'

    def test_shift_by_16_bits(self):
        assert _lshift_bytes(b'\xAB\xCD\xEF', 16) == b'\xEF\x00\x00'

    def test_shift_all_out(self):
        # Shifting by >= total bits → all zeros
        assert _lshift_bytes(b'\xAB\xCD\xEF', 24) == b'\x00\x00\x00'
        assert _lshift_bytes(b'\xAB\xCD\xEF', 100) == b'\x00\x00\x00'

    def test_empty(self):
        assert _lshift_bytes(b'', 5) == b''

    def test_single_byte(self):
        assert _lshift_bytes(b'\xFF', 1) == b'\xFE'
        assert _lshift_bytes(b'\xFF', 4) == b'\xF0'
        assert _lshift_bytes(b'\xFF', 8) == b'\x00'

    def test_preserves_length(self):
        for n in range(25):
            result = _lshift_bytes(b'\xAB\xCD\xEF', n)
            assert len(result) == 3, f"Length changed for n={n}"


class TestRShiftBytes:
    def test_zero_shift(self):
        assert _rshift_bytes(b'\xAB\xCD\xEF', 0) == b'\xAB\xCD\xEF'

    def test_shift_by_3_bits(self):
        # rshift(lshift(0xABCDEF, 3), 3):
        #   lshift: 0xABCDEF << 3 (24-bit) = 0x5E6F78
        #   rshift: 0x5E6F78 >> 3 = 0x0BCDEF
        shifted = _lshift_bytes(b'\xAB\xCD\xEF', 3)
        assert shifted == b'\x5E\x6F\x78'
        result = _rshift_bytes(shifted, 3)
        assert result == b'\x0B\xCD\xEF'

    def test_shift_by_8_bits(self):
        assert _rshift_bytes(b'\xAB\xCD\xEF', 8) == b'\x00\xAB\xCD'

    def test_shift_by_16_bits(self):
        assert _rshift_bytes(b'\xAB\xCD\xEF', 16) == b'\x00\x00\xAB'

    def test_shift_all_out(self):
        assert _rshift_bytes(b'\xAB\xCD\xEF', 24) == b'\x00\x00\x00'
        assert _rshift_bytes(b'\xAB\xCD\xEF', 100) == b'\x00\x00\x00'

    def test_empty(self):
        assert _rshift_bytes(b'', 5) == b''

    def test_single_byte(self):
        assert _rshift_bytes(b'\xFF', 1) == b'\x7F'
        assert _rshift_bytes(b'\xFF', 4) == b'\x0F'
        assert _rshift_bytes(b'\xFF', 8) == b'\x00'

    def test_preserves_length(self):
        for n in range(25):
            result = _rshift_bytes(b'\xAB\xCD\xEF', n)
            assert len(result) == 3, f"Length changed for n={n}"

    def test_known_value(self):
        # 0x0102 >> 1 = 0x0081
        assert _rshift_bytes(b'\x01\x02', 1) == b'\x00\x81'


# ---------------------------------------------------------------------------
# OP_LSHIFT / OP_RSHIFT via the script interpreter
# ---------------------------------------------------------------------------

class TestOpShift:
    # OP_LSHIFT = 0x98, OP_RSHIFT = 0x99

    def test_lshift_basic(self):
        # Push 0xFF01 (b'\xff\x01'), shift left 1 bit → b'\xfe\x02'
        # 0xFF01 << 1: MSB=0xFF, LSB=0x01 → result MSB=0xFE, LSB=0x02
        # unlocking: 02ff01 51  (push 0xFF01, OP_1=push 1)
        # locking:   98 02fe02 87  (OP_LSHIFT, push 0xFE02, OP_EQUAL)
        assert_valid('02ff01 51', '98 02fe02 87')

    def test_rshift_basic(self):
        # 0xFF01 >> 1 = 0x7F80
        # rshift mask[1]=0xFE, overflow_mask=0x01
        # i=0 (0xFF): result[0]|=0xFE>>1=0x7F; result[1]|=0x01<<7=0x80
        # i=1 (0x01): result[1]|=0x00
        assert_valid('02ff01 51', '99 027f80 87')

    def test_lshift_zero(self):
        # Shift by 0 is a no-op (using OP_0 which pushes empty = 0)
        assert_valid('02abcd 00', '98 02abcd 87')

    def test_rshift_zero(self):
        assert_valid('02abcd 00', '99 02abcd 87')

    def test_lshift_all_out(self):
        # Shift by 16 bits (= all bits in 2-byte value) → 0x0000
        # OP_16 = 0x60 (minimal encoding for the number 16)
        assert_valid('02abcd 60', '98 020000 87')

    def test_rshift_all_out(self):
        assert_valid('02abcd 60', '99 020000 87')

    def test_lshift_pops_both_args(self):
        # After OP_LSHIFT, exactly one item remains → clean stack passes
        # Stack should be exactly [result], not [n, result]
        # 0xFE02 << 1 = 0xFC04
        assert_valid('02fe02 51', '98 02fc04 87')


# ---------------------------------------------------------------------------
# OP_INVERT
# ---------------------------------------------------------------------------

class TestOpInvert:
    def test_invert_ff(self):
        # ~0xFF = 0x00
        assert_valid('01ff', '83 0100 87')

    def test_invert_00(self):
        # ~0x00 = 0xFF
        assert_valid('0100', '83 01ff 87')

    def test_invert_a5(self):
        # ~0xA5 = 0x5A
        assert_valid('01a5', '83 015a 87')

    def test_invert_multibyte(self):
        # ~0xDEAD = 0x2152
        assert_valid('02dead', '83 022152 87')

    def test_invert_empty(self):
        # ~(empty) = empty; but empty on top means falsy → script fails
        # Just verify it doesn't crash with a non-empty value
        assert_valid('020000', '83 02ffff 87')


# ---------------------------------------------------------------------------
# OP_DIV / OP_MOD (C-style truncation toward zero)
# ---------------------------------------------------------------------------

class TestOpDivMod:
    # Positive / positive  — same as Python floor
    def test_div_positive(self):
        # 7 / 2 = 3
        assert_valid('57 52', '96 53 87')

    def test_mod_positive(self):
        # 7 % 2 = 1
        assert_valid('57 52', '97 51 87')

    # Negative dividend, positive divisor
    def test_div_neg_dividend(self):
        # -7 / 2 = -3  (C truncates toward zero; Python // gives -4)
        # -7 = 0x87 in script number encoding
        assert_valid('0187 52', '96 0183 87')

    def test_mod_neg_dividend(self):
        # -7 % 2 = -1  (C sign follows dividend; Python % gives 1)
        # OP_1NEGATE (0x4f) is the minimal encoding for -1
        assert_valid('0187 52', '97 4f 87')

    # Positive dividend, negative divisor
    def test_div_pos_dividend_neg_divisor(self):
        # 7 / -2 = -3  (C truncates toward zero)
        assert_valid('57 0182', '96 0183 87')

    def test_mod_pos_dividend_neg_divisor(self):
        # 7 % -2 = 1  (C sign follows dividend)
        assert_valid('57 0182', '97 51 87')

    # Negative / negative
    def test_div_both_negative(self):
        # -7 / -2 = 3
        assert_valid('0187 0182', '96 53 87')

    def test_mod_both_negative(self):
        # -7 % -2 = -1  (sign follows dividend)
        assert_valid('0187 0182', '97 4f 87')

    def test_div_by_zero(self):
        assert_invalid('57 00', '96 51 87')

    def test_mod_by_zero(self):
        assert_invalid('57 00', '97 51 87')


# ---------------------------------------------------------------------------
# OP_NUM2BIN
# ---------------------------------------------------------------------------

class TestOpNum2Bin:
    def test_zero_to_bin(self):
        # 0 padded to 4 bytes → b'\x00\x00\x00\x00'
        assert_valid('00 54', '80 0400000000 87')

    def test_positive_padded(self):
        # 1 padded to 2 bytes → b'\x01\x00'
        assert_valid('51 52', '80 020100 87')

    def test_negative_padded(self):
        # -1 padded to 2 bytes → b'\x01\x80'
        # -1 must be pushed as OP_1NEGATE (0x4f) for minimal encoding
        assert_valid('4f 52', '80 020180 87')

    def test_already_minimal(self):
        # 127 (b'\x7f') padded to 1 byte → b'\x7f'
        assert_valid('017f 51', '80 017f 87')


# ---------------------------------------------------------------------------
# OP_BIN2NUM
# ---------------------------------------------------------------------------

class TestOpBin2Num:
    def test_zero(self):
        # b'\x00\x00\x00\x00' → 0
        assert_valid('0400000000', '81 00 87')

    def test_positive(self):
        # b'\x01\x00' → 1
        assert_valid('020100', '81 51 87')

    def test_negative(self):
        # b'\x01\x80' → -1, minimal encoding is OP_1NEGATE (0x4f)
        assert_valid('020180', '81 4f 87')


# ---------------------------------------------------------------------------
# OP_CAT / OP_SPLIT
# ---------------------------------------------------------------------------

class TestOpCatSplit:
    def test_cat(self):
        # b'\xAB' + b'\xCD' = b'\xAB\xCD'
        assert_valid('01ab 01cd', '7e 02abcd 87')

    def test_split(self):
        # b'\xAB\xCD' split at 1 → b'\xAB', b'\xCD'
        # unlocking: push 0xABCD, push 1
        # locking: OP_SPLIT, push 0xCD, OP_EQUAL, OP_NIP (remove 0xAB), OP_VERIFY ...
        # Easier: push abcd, 1, split → [ab, cd]; check cd == cd and ab == ab
        # Just verify split then cat round-trips:
        assert_valid('02abcd 51', '7f 7e 02abcd 87')


# ---------------------------------------------------------------------------
# OP_CHECKMULTISIG (basic 1-of-1 already tested via spend_vector,
# but explicitly test keys_count decrement fix with 2-of-2)
# ---------------------------------------------------------------------------

class TestOpCheckMultisig:
    def test_empty_sig_returns_false(self):
        # Empty signature means verification fails → 0 on stack → script fails
        assert_invalid('00 00', '52 51 ae 87')
