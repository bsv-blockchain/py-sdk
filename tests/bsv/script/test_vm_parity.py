"""VM parity tests: verify py-sdk matches BSV Node C++ behaviour.

Covers the fixes applied on the fix/vm-full-parity branch, each of which
was identified by a 1:1 opcode audit against interpreter.cpp.
"""

import pytest

from bsv.constants import SIGHASH, OpCode
from bsv.hash import hash160
from bsv.keys import PrivateKey
from bsv.script.script import Script
from bsv.script.spend import (
    _USE_NATIVE_VM,
    MAX_SCRIPT_NUMBER_LENGTH_AFTER_CHRONICLE,
    Spend,
)
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput
from bsv.transaction_preimage import tx_preimage
from bsv.utils import encode_pushdata

SOURCE_TXID = "aa" * 32
SOURCE_SATOSHIS = 10_000


def _outputs():
    return [TransactionOutput(locking_script=Script.from_asm("OP_TRUE"), satoshis=9_000)]


def _spend(lock: Script, unlock: Script, tx_version: int = 1) -> Spend:
    return Spend(
        {
            "sourceTXID": SOURCE_TXID,
            "sourceOutputIndex": 0,
            "sourceSatoshis": SOURCE_SATOSHIS,
            "lockingScript": lock,
            "transactionVersion": tx_version,
            "otherInputs": [],
            "outputs": _outputs(),
            "inputIndex": 0,
            "unlockingScript": unlock,
            "inputSequence": 0xFFFFFFFF,
            "lockTime": 0,
        }
    )


# ---------------------------------------------------------------------------
# DER signature encoding (Finding #2)
# ---------------------------------------------------------------------------


class TestDERSignatureEncoding:
    """_is_valid_signature_encoding matches C++ IsValidSignatureEncoding."""

    def test_too_short(self):
        sig = bytes(8)
        assert Spend._is_valid_signature_encoding(sig) is False

    def test_too_long(self):
        sig = bytes(74)
        assert Spend._is_valid_signature_encoding(sig) is False

    def test_not_compound(self):
        sig = bytearray(9)
        sig[0] = 0x31
        assert Spend._is_valid_signature_encoding(bytes(sig)) is False

    def test_length_mismatch(self):
        sig = bytearray(9)
        sig[0] = 0x30
        sig[1] = 99
        assert Spend._is_valid_signature_encoding(bytes(sig)) is False

    def test_zero_length_r(self):
        # 0x30 [6] 0x02 [0] 0x02 [1] [S] [sighash]
        sig = bytes([0x30, 0x06, 0x02, 0x00, 0x02, 0x01, 0x01, 0x00, 0x41])
        assert Spend._is_valid_signature_encoding(sig) is False

    def test_zero_length_s(self):
        # 0x30 [6] 0x02 [1] [R] 0x02 [0] [sighash]
        sig = bytes([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x00, 0x00, 0x41])
        assert Spend._is_valid_signature_encoding(sig) is False

    def test_negative_r(self):
        # R with high bit set
        sig = bytes([0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01, 0x41])
        assert Spend._is_valid_signature_encoding(sig) is False

    def test_negative_s(self):
        # S with high bit set
        sig = bytes([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x80, 0x41])
        assert Spend._is_valid_signature_encoding(sig) is False

    def test_redundant_r_padding(self):
        # R = 0x00 0x01 — the 0x00 is unnecessary since 0x01 has bit 7 clear
        sig = bytes([0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01, 0x41])
        assert Spend._is_valid_signature_encoding(sig) is False

    def test_redundant_s_padding(self):
        # S = 0x00 0x01
        sig = bytes([0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x01, 0x41])
        assert Spend._is_valid_signature_encoding(sig) is False

    def test_valid_minimal(self):
        # Minimal valid: R=1byte, S=1byte
        sig = bytes([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x41])
        assert Spend._is_valid_signature_encoding(sig) is True

    def test_r_needs_padding(self):
        # R = 0x00 0x80 is valid: the 0x00 is needed because 0x80 has bit 7 set
        sig = bytes([0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01, 0x41])
        assert Spend._is_valid_signature_encoding(sig) is True


# ---------------------------------------------------------------------------
# CHECKMULTISIG key/sig count ceiling (Finding #3)
# ---------------------------------------------------------------------------


class TestCheckmultisigCountCeiling:
    """key/sig counts must fit in 4 bytes (CScriptNum::MAXIMUM_ELEMENT_SIZE)."""

    def test_5byte_key_count_rejected(self):
        five_byte_one = b"\x01\x00\x00\x00\x00"
        pub = PrivateKey().public_key().serialize()
        lock = Script(encode_pushdata(five_byte_one) + encode_pushdata(pub) + OpCode.OP_1 + OpCode.OP_CHECKMULTISIG)
        unlock = Script(OpCode.OP_0 + OpCode.OP_0)
        s = _spend(lock, unlock, tx_version=2)
        with pytest.raises((RuntimeError, Exception), match="script number overflow"):
            s._validate_python()


# ---------------------------------------------------------------------------
# OP_BIN2NUM: minimize then check size (Finding #4)
# ---------------------------------------------------------------------------


class TestBin2NumMinimizeFirst:
    """OP_BIN2NUM checks size after minimally encoding, not before."""

    def test_large_trailing_zeros_minimize_to_zero(self):
        from tests.bsv.script.conftest import make_spend

        # A large input of all zeros should minimize to b"" (0), not overflow.
        # We can't push > MAX_SCRIPT_ELEMENT_SIZE, but we can test the
        # bin2num_unchecked + minimize logic directly.
        val = b"\x00" * 100
        result = Spend.bin2num_unchecked(val)
        assert result == 0
        encoded = Spend.minimally_encode(result)
        assert len(encoded) <= MAX_SCRIPT_NUMBER_LENGTH_AFTER_CHRONICLE


# ---------------------------------------------------------------------------
# OP_LSHIFTNUM post-shift size check (Finding #5)
# ---------------------------------------------------------------------------


class TestLshiftnumPostShiftCheck:
    """OP_LSHIFTNUM rejects results that exceed 32MB after shifting."""

    def test_lshiftnum_zero_shift(self):
        from tests.bsv.script.conftest import make_spend

        s = make_spend("OP_LSHIFTNUM OP_1 OP_NUMEQUAL", "OP_1 OP_0", tx_version=2)
        s.validate()

    def test_lshiftnum_basic(self):
        from tests.bsv.script.conftest import make_spend

        # 1 << 1 = 2
        s = make_spend("OP_LSHIFTNUM OP_2 OP_NUMEQUAL", "OP_1 OP_1", tx_version=2)
        s.validate()


# ---------------------------------------------------------------------------
# OP_NUM2BIN size ceiling (Finding #6)
# ---------------------------------------------------------------------------


class TestNum2BinCeiling:
    """OP_NUM2BIN uses INT32_MAX (0x7FFFFFFF) as the size ceiling."""

    def test_negative_size_rejected(self):
        from tests.bsv.script.conftest import make_spend

        s = make_spend("OP_NUM2BIN OP_TRUE", "OP_5 OP_1NEGATE", tx_version=2)
        with pytest.raises(RuntimeError, match="size out of range"):
            s._validate_python()


# ---------------------------------------------------------------------------
# OP_LSHIFT / OP_RSHIFT (existing fix verification)
# ---------------------------------------------------------------------------


class TestBitShifts:
    """OP_LSHIFT/OP_RSHIFT operate at the bit level, preserving byte length."""

    def test_lshift_1_bit(self):
        from tests.bsv.script.conftest import make_spend

        s = make_spend("OP_LSHIFT 04 OP_EQUAL", "02 OP_1", tx_version=2)
        s.validate()

    def test_rshift_1_bit(self):
        from tests.bsv.script.conftest import make_spend

        s = make_spend("OP_RSHIFT 02 OP_EQUAL", "04 OP_1", tx_version=2)
        s.validate()

    def test_lshift_zero(self):
        from tests.bsv.script.conftest import make_spend

        s = make_spend("OP_LSHIFT ff OP_EQUAL", "ff OP_0", tx_version=2)
        s.validate()

    def test_rshift_zero(self):
        from tests.bsv.script.conftest import make_spend

        s = make_spend("OP_RSHIFT ff OP_EQUAL", "ff OP_0", tx_version=2)
        s.validate()

    def test_lshift_at_width(self):
        from tests.bsv.script.conftest import make_spend

        s = make_spend("OP_LSHIFT 00 OP_EQUAL", "ff OP_8", tx_version=2)
        s.validate()

    def test_rshift_at_width(self):
        from tests.bsv.script.conftest import make_spend

        s = make_spend("OP_RSHIFT 00 OP_EQUAL", "ff OP_8", tx_version=2)
        s.validate()

    def test_lshift_empty_input(self):
        from tests.bsv.script.conftest import make_spend

        s = make_spend("OP_LSHIFT OP_0 OP_EQUAL", "OP_0 OP_0", tx_version=2)
        s.validate()


# ---------------------------------------------------------------------------
# OP_2OVER, OP_2ROT, OP_2SWAP, OP_3DUP
# ---------------------------------------------------------------------------


class TestStackOps:
    """Verify less-common stack manipulation opcodes."""

    def test_2over(self):
        from tests.bsv.script.conftest import make_spend

        # [1,2,3,4] -> 2OVER -> [1,2,3,4,1,2] — verify all 6 items
        s = make_spend(
            "OP_2OVER OP_2 OP_EQUALVERIFY OP_1 OP_EQUALVERIFY "
            "OP_4 OP_EQUALVERIFY OP_3 OP_EQUALVERIFY "
            "OP_2 OP_EQUALVERIFY OP_1 OP_EQUAL",
            "OP_1 OP_2 OP_3 OP_4",
            tx_version=2,
        )
        s.validate()

    def test_2swap(self):
        from tests.bsv.script.conftest import make_spend

        # [1,2,3,4] -> 2SWAP -> [3,4,1,2]
        s = make_spend(
            "OP_2SWAP OP_2 OP_EQUALVERIFY OP_1 OP_EQUALVERIFY " "OP_4 OP_EQUALVERIFY OP_3 OP_EQUAL",
            "OP_1 OP_2 OP_3 OP_4",
            tx_version=2,
        )
        s.validate()

    def test_3dup(self):
        from tests.bsv.script.conftest import make_spend

        # [1,2,3] -> 3DUP -> [1,2,3,1,2,3]
        s = make_spend(
            "OP_3DUP OP_3 OP_EQUALVERIFY OP_2 OP_EQUALVERIFY OP_1 OP_EQUALVERIFY "
            "OP_3 OP_EQUALVERIFY OP_2 OP_EQUALVERIFY OP_1 OP_EQUAL",
            "OP_1 OP_2 OP_3",
            tx_version=2,
        )
        s.validate()

    def test_2rot(self):
        from tests.bsv.script.conftest import make_spend

        # [1,2,3,4,5,6] -> 2ROT -> [3,4,5,6,1,2]
        s = make_spend(
            "OP_2ROT OP_2 OP_EQUALVERIFY OP_1 OP_EQUALVERIFY "
            "OP_6 OP_EQUALVERIFY OP_5 OP_EQUALVERIFY "
            "OP_4 OP_EQUALVERIFY OP_3 OP_EQUAL",
            "OP_1 OP_2 OP_3 OP_4 OP_5 OP_6",
            tx_version=2,
        )
        s.validate()


# ---------------------------------------------------------------------------
# Control flow: double OP_ELSE rejection
# ---------------------------------------------------------------------------


class TestDoubleElse:
    """The VM must reject a second OP_ELSE for the same OP_IF level."""

    def test_double_else_rejected(self):
        from tests.bsv.script.conftest import make_spend

        s = make_spend(
            "OP_IF OP_1 OP_ELSE OP_2 OP_ELSE OP_3 OP_ENDIF",
            "OP_TRUE",
        )
        with pytest.raises(RuntimeError, match="OP_ELSE"):
            s.validate()


# ---------------------------------------------------------------------------
# VM boundary reset
# ---------------------------------------------------------------------------


class TestVmBoundaryReset:
    """alt_stack, if_stack, else_stack reset at unlock→lock transition."""

    def test_altstack_not_carried_over(self):
        from tests.bsv.script.conftest import make_spend

        s = make_spend("OP_FROMALTSTACK", "OP_1 OP_TOALTSTACK OP_TRUE")
        with pytest.raises(RuntimeError):
            s.validate()


# ---------------------------------------------------------------------------
# OP_CODESEPARATOR with CHECKSIG (existing fix + native VM fix)
# ---------------------------------------------------------------------------


class TestCodeSeparatorChecksig:
    """OP_CODESEPARATOR changes the subscript for signature verification."""

    def test_codeseparator_excludes_separator(self):
        """Verify the separator itself is excluded from the subscript."""
        priv = PrivateKey()
        pkh = hash160(priv.public_key().serialize())
        subscript = Script(
            OpCode.OP_DUP + OpCode.OP_HASH160 + encode_pushdata(pkh) + OpCode.OP_EQUALVERIFY + OpCode.OP_CHECKSIG
        )
        lock = Script(OpCode.OP_CODESEPARATOR + subscript.serialize())

        inp = TransactionInput(
            source_txid=SOURCE_TXID,
            source_output_index=0,
            unlocking_script=Script(),
            sequence=0xFFFFFFFF,
            sighash=SIGHASH.ALL_FORKID,
        )
        inp.locking_script = subscript
        inp.satoshis = SOURCE_SATOSHIS

        preimage = tx_preimage(0, [inp], _outputs(), 1, 0)
        sig_bytes = priv.sign(preimage)
        sig_with_hashtype = sig_bytes + SIGHASH.ALL_FORKID.to_bytes(1, "little")

        unlock = Script(encode_pushdata(sig_with_hashtype) + encode_pushdata(priv.public_key().serialize()))

        s = _spend(lock, unlock)
        s.validate()


# ---------------------------------------------------------------------------
# OP_DIV / OP_MOD truncation-toward-zero
# ---------------------------------------------------------------------------


class TestDivModTruncation:
    """OP_DIV truncates toward zero, OP_MOD uses dividend's sign."""

    def test_neg_div_pos(self):
        from tests.bsv.script.conftest import make_spend

        # -7 / 2 = -3 (truncate toward zero, not -4)
        s = make_spend("OP_DIV OP_1NEGATE OP_3 OP_MUL OP_NUMEQUAL", "87 OP_2", tx_version=2)
        s.validate()

    def test_neg_mod_pos(self):
        from tests.bsv.script.conftest import make_spend

        # -7 % 2 = -1 (remainder takes dividend's sign)
        s = make_spend("OP_MOD OP_1NEGATE OP_NUMEQUAL", "87 OP_2", tx_version=2)
        s.validate()


# ---------------------------------------------------------------------------
# Native / Python path equivalence
# ---------------------------------------------------------------------------


class TestNativePythonEquivalence:
    """Both VM paths must agree on basic scripts."""

    @pytest.fixture
    def priv_key(self):
        return PrivateKey()

    def test_p2pkh_both_paths(self, priv_key):
        """P2PKH validates identically on native and Python paths."""
        pkh = hash160(priv_key.public_key().serialize())
        lock = Script(
            OpCode.OP_DUP + OpCode.OP_HASH160 + encode_pushdata(pkh) + OpCode.OP_EQUALVERIFY + OpCode.OP_CHECKSIG
        )

        inp = TransactionInput(
            source_txid=SOURCE_TXID,
            source_output_index=0,
            unlocking_script=Script(),
            sequence=0xFFFFFFFF,
            sighash=SIGHASH.ALL_FORKID,
        )
        inp.locking_script = lock
        inp.satoshis = SOURCE_SATOSHIS

        preimage = tx_preimage(0, [inp], _outputs(), 1, 0)
        sig_bytes = priv_key.sign(preimage)
        sig_with_hashtype = sig_bytes + SIGHASH.ALL_FORKID.to_bytes(1, "little")

        unlock = Script(encode_pushdata(sig_with_hashtype) + encode_pushdata(priv_key.public_key().serialize()))

        s = _spend(lock, unlock)

        # Python path
        python_result = s._validate_python()
        assert python_result is True

        # Native path (if available)
        if _USE_NATIVE_VM:
            s2 = _spend(lock, unlock)
            native_result = s2._validate_native()
            assert native_result is True


# ---------------------------------------------------------------------------
# OP_NOP11+ must be invalid opcodes (C++ SCRIPT_ERR_BAD_OPCODE)
# ---------------------------------------------------------------------------


class TestNop11PlusInvalid:
    """OP_NOP11 through OP_NOP73 and OP_NOP77 are invalid opcodes per C++."""

    @pytest.mark.parametrize(
        "nop",
        [
            OpCode.OP_NOP11,
            OpCode.OP_NOP40,
            OpCode.OP_NOP73,
            OpCode.OP_NOP77,
        ],
        ids=["NOP11", "NOP40", "NOP73", "NOP77"],
    )
    def test_nop11_plus_rejected_python(self, nop):
        lock = Script(nop + OpCode.OP_TRUE)
        unlock = Script(OpCode.OP_TRUE)
        s = _spend(lock, unlock, tx_version=2)
        with pytest.raises(RuntimeError, match="Invalid opcode"):
            s._validate_python()

    @pytest.mark.parametrize(
        "nop",
        [
            OpCode.OP_NOP11,
            OpCode.OP_NOP40,
            OpCode.OP_NOP73,
            OpCode.OP_NOP77,
        ],
        ids=["NOP11", "NOP40", "NOP73", "NOP77"],
    )
    def test_nop11_plus_rejected_native(self, nop):
        if not _USE_NATIVE_VM:
            pytest.skip("native VM not available")
        lock = Script(nop + OpCode.OP_TRUE)
        unlock = Script(OpCode.OP_TRUE)
        s = _spend(lock, unlock, tx_version=2)
        with pytest.raises(RuntimeError, match="Invalid opcode"):
            s._validate_native()

    def test_nop1_through_nop10_still_valid(self):
        """OP_NOP, NOP1-3, NOP9-10 remain valid no-ops."""
        for nop in [OpCode.OP_NOP, OpCode.OP_NOP1, OpCode.OP_NOP2, OpCode.OP_NOP3, OpCode.OP_NOP9, OpCode.OP_NOP10]:
            lock = Script(nop + OpCode.OP_TRUE)
            unlock = Script(OpCode.OP_TRUE)
            s = _spend(lock, unlock, tx_version=2)
            assert s._validate_python() is True
            if _USE_NATIVE_VM:
                s2 = _spend(lock, unlock, tx_version=2)
                assert s2._validate_native() is True


# ---------------------------------------------------------------------------
# SIGHASH_SINGLE bug (OTDA path): input_index >= len(outputs)
# ---------------------------------------------------------------------------


class TestSighashSingleBug:
    """OTDA SIGHASH_SINGLE with input_index >= len(outputs) must use uint256(1).

    C++ returns uint256(1) as the sighash when SIGHASH_SINGLE and
    input_index >= len(outputs). The VM must not crash in this case.
    """

    def _make_spend_no_outputs(self):
        """Spend with CHECKSIG, 0 outputs, OTDA sighash (SINGLE|FORKID|CHRONICLE)."""
        priv = PrivateKey()
        pub = priv.public_key().serialize()
        lock = Script(encode_pushdata(pub) + OpCode.OP_CHECKSIG)
        sighash_flag = SIGHASH.SINGLE_FORKID_CHRONICLE
        single_bug_hash = b"\x01" + b"\x00" * 31
        sig_der = priv.sign(single_bug_hash, hasher=None)
        sig_with_hashtype = sig_der + sighash_flag.to_bytes(1, "little")
        unlock = Script(encode_pushdata(sig_with_hashtype))
        return Spend(
            {
                "sourceTXID": SOURCE_TXID,
                "sourceOutputIndex": 0,
                "sourceSatoshis": SOURCE_SATOSHIS,
                "lockingScript": lock,
                "transactionVersion": 2,
                "otherInputs": [],
                "outputs": [],
                "inputIndex": 0,
                "unlockingScript": unlock,
                "inputSequence": 0xFFFFFFFF,
                "lockTime": 0,
            }
        )

    def test_single_bug_python(self):
        s = self._make_spend_no_outputs()
        assert s._validate_python() is True

    def test_single_bug_native(self):
        if not _USE_NATIVE_VM:
            pytest.skip("native VM not available")
        s = self._make_spend_no_outputs()
        assert s._validate_native() is True


# ---------------------------------------------------------------------------
# OP_RESERVED, OP_RESERVED1, OP_RESERVED2
# ---------------------------------------------------------------------------


class TestReservedOpcodes:
    """OP_RESERVED/RESERVED1/RESERVED2 must error when executed, pass when skipped."""

    @pytest.mark.parametrize(
        "op",
        [OpCode.OP_RESERVED, OpCode.OP_RESERVED1, OpCode.OP_RESERVED2],
        ids=["RESERVED", "RESERVED1", "RESERVED2"],
    )
    def test_reserved_rejected_when_executed_python(self, op):
        lock = Script(op + OpCode.OP_TRUE)
        unlock = Script(OpCode.OP_TRUE)
        s = _spend(lock, unlock, tx_version=2)
        with pytest.raises(RuntimeError, match="Invalid opcode"):
            s._validate_python()

    @pytest.mark.parametrize(
        "op",
        [OpCode.OP_RESERVED, OpCode.OP_RESERVED1, OpCode.OP_RESERVED2],
        ids=["RESERVED", "RESERVED1", "RESERVED2"],
    )
    def test_reserved_rejected_when_executed_native(self, op):
        if not _USE_NATIVE_VM:
            pytest.skip("native VM not available")
        lock = Script(op + OpCode.OP_TRUE)
        unlock = Script(OpCode.OP_TRUE)
        s = _spend(lock, unlock, tx_version=2)
        with pytest.raises(RuntimeError, match="Invalid opcode"):
            s._validate_native()

    @pytest.mark.parametrize(
        "op",
        [OpCode.OP_RESERVED, OpCode.OP_RESERVED1, OpCode.OP_RESERVED2],
        ids=["RESERVED", "RESERVED1", "RESERVED2"],
    )
    def test_reserved_skipped_in_false_branch(self, op):
        lock = Script(OpCode.OP_IF + op + OpCode.OP_ENDIF + OpCode.OP_TRUE)
        unlock = Script(OpCode.OP_FALSE)
        s = _spend(lock, unlock, tx_version=2)
        assert s._validate_python() is True
        if _USE_NATIVE_VM:
            s2 = _spend(lock, unlock, tx_version=2)
            assert s2._validate_native() is True


# ---------------------------------------------------------------------------
# Comprehensive dual-path opcode coverage: Python == Native for every opcode
# ---------------------------------------------------------------------------

_DUAL_PATH_CASES = [
    # --- Constants ---
    pytest.param("OP_0 OP_NOT", "", 2, id="OP_0"),
    pytest.param("OP_1NEGATE OP_1 OP_ADD OP_NOT", "", 2, id="OP_1NEGATE"),
    pytest.param("OP_1 OP_1 OP_NUMEQUAL", "", 2, id="OP_1"),
    pytest.param("OP_2 OP_2 OP_NUMEQUAL", "", 2, id="OP_2"),
    pytest.param("OP_3 OP_3 OP_NUMEQUAL", "", 2, id="OP_3"),
    pytest.param("OP_4 OP_4 OP_NUMEQUAL", "", 2, id="OP_4"),
    pytest.param("OP_5 OP_5 OP_NUMEQUAL", "", 2, id="OP_5"),
    pytest.param("OP_6 OP_6 OP_NUMEQUAL", "", 2, id="OP_6"),
    pytest.param("OP_7 OP_7 OP_NUMEQUAL", "", 2, id="OP_7"),
    pytest.param("OP_8 OP_8 OP_NUMEQUAL", "", 2, id="OP_8"),
    pytest.param("OP_9 OP_9 OP_NUMEQUAL", "", 2, id="OP_9"),
    pytest.param("OP_10 OP_10 OP_NUMEQUAL", "", 2, id="OP_10"),
    pytest.param("OP_11 OP_11 OP_NUMEQUAL", "", 2, id="OP_11"),
    pytest.param("OP_12 OP_12 OP_NUMEQUAL", "", 2, id="OP_12"),
    pytest.param("OP_13 OP_13 OP_NUMEQUAL", "", 2, id="OP_13"),
    pytest.param("OP_14 OP_14 OP_NUMEQUAL", "", 2, id="OP_14"),
    pytest.param("OP_15 OP_15 OP_NUMEQUAL", "", 2, id="OP_15"),
    pytest.param("OP_16 OP_16 OP_NUMEQUAL", "", 2, id="OP_16"),
    # --- Stack manipulation ---
    pytest.param("OP_DUP OP_NUMEQUAL", "OP_5", 2, id="OP_DUP"),
    pytest.param("OP_DROP OP_TRUE", "OP_1 OP_2", 2, id="OP_DROP"),
    pytest.param("OP_2DROP OP_TRUE", "OP_1 OP_2 OP_3", 2, id="OP_2DROP"),
    pytest.param("OP_2DUP OP_EQUALVERIFY OP_NUMEQUAL", "OP_5 OP_5", 2, id="OP_2DUP"),
    pytest.param(
        "OP_3DUP OP_DROP OP_DROP OP_DROP OP_DROP OP_DROP OP_TRUE",
        "OP_1 OP_2 OP_3",
        2,
        id="OP_3DUP",
    ),
    pytest.param("OP_NIP OP_2 OP_NUMEQUAL", "OP_1 OP_2", 2, id="OP_NIP"),
    pytest.param("OP_OVER OP_1 OP_NUMEQUAL", "OP_1 OP_2", 2, id="OP_OVER"),
    pytest.param("OP_PICK OP_1 OP_NUMEQUAL", "OP_1 OP_2 OP_3 OP_2", 2, id="OP_PICK"),
    pytest.param("OP_ROLL OP_1 OP_NUMEQUAL", "OP_1 OP_2 OP_3 OP_2", 2, id="OP_ROLL"),
    pytest.param("OP_ROT OP_1 OP_NUMEQUAL", "OP_1 OP_2 OP_3", 2, id="OP_ROT"),
    pytest.param("OP_SWAP OP_1 OP_NUMEQUAL", "OP_1 OP_2", 2, id="OP_SWAP"),
    pytest.param("OP_TUCK OP_DROP OP_DROP OP_TRUE", "OP_1 OP_2", 2, id="OP_TUCK"),
    pytest.param("OP_IFDUP OP_NUMEQUAL", "OP_5", 2, id="OP_IFDUP"),
    pytest.param("OP_DEPTH OP_2 OP_NUMEQUAL", "OP_1 OP_2", 2, id="OP_DEPTH"),
    pytest.param("OP_SIZE OP_1 OP_NUMEQUAL", "OP_5", 2, id="OP_SIZE"),
    pytest.param(
        "OP_TOALTSTACK OP_FROMALTSTACK OP_5 OP_NUMEQUAL",
        "OP_5",
        2,
        id="OP_TOALTSTACK_FROMALTSTACK",
    ),
    pytest.param(
        "OP_2OVER OP_DROP OP_DROP OP_DROP OP_DROP OP_TRUE",
        "OP_1 OP_2 OP_3 OP_4",
        2,
        id="OP_2OVER",
    ),
    pytest.param(
        "OP_2SWAP OP_DROP OP_DROP OP_DROP OP_TRUE",
        "OP_1 OP_2 OP_3 OP_4",
        2,
        id="OP_2SWAP",
    ),
    pytest.param(
        "OP_2ROT OP_DROP OP_DROP OP_DROP OP_DROP OP_DROP OP_TRUE",
        "OP_1 OP_2 OP_3 OP_4 OP_5 OP_6",
        2,
        id="OP_2ROT",
    ),
    # --- Splice ---
    pytest.param("OP_CAT 0102 OP_EQUAL", "01 02", 2, id="OP_CAT"),
    pytest.param(
        "OP_SPLIT 02 OP_EQUALVERIFY 01 OP_EQUAL",
        "0102 OP_1",
        2,
        id="OP_SPLIT",
    ),
    pytest.param("OP_NUM2BIN 05000000 OP_EQUAL", "OP_5 OP_4", 2, id="OP_NUM2BIN"),
    pytest.param("OP_BIN2NUM OP_5 OP_NUMEQUAL", "05000000", 2, id="OP_BIN2NUM"),
    # --- Bitwise ---
    pytest.param("OP_INVERT 00 OP_EQUAL", "ff", 2, id="OP_INVERT"),
    pytest.param("OP_AND 0f OP_EQUAL", "ff 0f", 2, id="OP_AND"),
    pytest.param("OP_OR ff OP_EQUAL", "f0 0f", 2, id="OP_OR"),
    pytest.param("OP_XOR 00 OP_EQUAL", "ff ff", 2, id="OP_XOR"),
    pytest.param("OP_EQUAL", "OP_5 OP_5", 2, id="OP_EQUAL"),
    pytest.param("OP_EQUALVERIFY OP_TRUE", "OP_5 OP_5", 2, id="OP_EQUALVERIFY"),
    # --- Unary arithmetic ---
    pytest.param("OP_1ADD OP_5 OP_NUMEQUAL", "OP_4", 2, id="OP_1ADD"),
    pytest.param("OP_1SUB OP_5 OP_NUMEQUAL", "OP_6", 2, id="OP_1SUB"),
    pytest.param("OP_NEGATE OP_5 OP_ADD OP_NOT", "OP_5", 2, id="OP_NEGATE"),
    pytest.param("OP_ABS OP_5 OP_NUMEQUAL", "85", 2, id="OP_ABS"),
    pytest.param("OP_NOT", "OP_0", 2, id="OP_NOT"),
    pytest.param("OP_0NOTEQUAL", "OP_5", 2, id="OP_0NOTEQUAL"),
    # --- Binary arithmetic ---
    pytest.param("OP_ADD OP_5 OP_NUMEQUAL", "OP_2 OP_3", 2, id="OP_ADD"),
    pytest.param("OP_SUB OP_2 OP_NUMEQUAL", "OP_5 OP_3", 2, id="OP_SUB"),
    pytest.param("OP_MUL OP_6 OP_NUMEQUAL", "OP_2 OP_3", 2, id="OP_MUL"),
    pytest.param("OP_DIV OP_3 OP_NUMEQUAL", "OP_6 OP_2", 2, id="OP_DIV"),
    pytest.param("OP_MOD OP_1 OP_NUMEQUAL", "07 OP_3", 2, id="OP_MOD"),
    # --- Boolean ---
    pytest.param("OP_BOOLAND", "OP_1 OP_1", 2, id="OP_BOOLAND"),
    pytest.param("OP_BOOLOR", "OP_0 OP_1", 2, id="OP_BOOLOR"),
    # --- Numeric comparison ---
    pytest.param("OP_NUMEQUAL", "OP_5 OP_5", 2, id="OP_NUMEQUAL"),
    pytest.param("OP_NUMEQUALVERIFY OP_TRUE", "OP_5 OP_5", 2, id="OP_NUMEQUALVERIFY"),
    pytest.param("OP_NUMNOTEQUAL", "OP_3 OP_5", 2, id="OP_NUMNOTEQUAL"),
    pytest.param("OP_LESSTHAN", "OP_2 OP_5", 2, id="OP_LESSTHAN"),
    pytest.param("OP_GREATERTHAN", "OP_5 OP_2", 2, id="OP_GREATERTHAN"),
    pytest.param("OP_LESSTHANOREQUAL", "OP_5 OP_5", 2, id="OP_LESSTHANOREQUAL"),
    pytest.param("OP_GREATERTHANOREQUAL", "OP_5 OP_5", 2, id="OP_GREATERTHANOREQUAL"),
    pytest.param("OP_MIN OP_3 OP_NUMEQUAL", "OP_3 OP_5", 2, id="OP_MIN"),
    pytest.param("OP_MAX OP_5 OP_NUMEQUAL", "OP_3 OP_5", 2, id="OP_MAX"),
    pytest.param("OP_WITHIN", "OP_3 OP_1 OP_5", 2, id="OP_WITHIN"),
    # --- Crypto (hash) ---
    pytest.param(
        "OP_0 OP_RIPEMD160 9c1185a5c5e9fc54612808977ee8f548b2258d31 OP_EQUAL",
        "",
        2,
        id="OP_RIPEMD160",
    ),
    pytest.param(
        "OP_0 OP_SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709 OP_EQUAL",
        "",
        2,
        id="OP_SHA1",
    ),
    pytest.param(
        "OP_0 OP_SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 OP_EQUAL",
        "",
        2,
        id="OP_SHA256",
    ),
    pytest.param(
        "OP_0 OP_HASH160 b472a266d0bd89c13706a4132ccfb16f7c3b9fcb OP_EQUAL",
        "",
        2,
        id="OP_HASH160",
    ),
    pytest.param(
        "OP_0 OP_HASH256 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456 OP_EQUAL",
        "",
        2,
        id="OP_HASH256",
    ),
    # --- Control flow ---
    pytest.param(
        "OP_IF OP_TRUE OP_ELSE OP_FALSE OP_ENDIF",
        "OP_TRUE",
        2,
        id="OP_IF_true",
    ),
    pytest.param(
        "OP_IF OP_FALSE OP_ELSE OP_TRUE OP_ENDIF",
        "OP_FALSE",
        2,
        id="OP_IF_false",
    ),
    pytest.param(
        "OP_NOTIF OP_TRUE OP_ELSE OP_FALSE OP_ENDIF",
        "OP_FALSE",
        2,
        id="OP_NOTIF",
    ),
    pytest.param("OP_VERIFY OP_TRUE", "OP_TRUE", 2, id="OP_VERIFY"),
    pytest.param(
        "OP_IF OP_RETURN OP_ENDIF OP_TRUE",
        "OP_FALSE",
        2,
        id="OP_RETURN_skipped",
    ),
    # --- NOP ---
    pytest.param("OP_NOP OP_TRUE", "", 2, id="OP_NOP"),
    pytest.param("OP_CODESEPARATOR OP_TRUE", "", 2, id="OP_CODESEPARATOR"),
    # --- Chronicle opcodes ---
    pytest.param("OP_VER OP_2 OP_NUMEQUAL", "", 2, id="OP_VER"),
    pytest.param("OP_2MUL OP_6 OP_NUMEQUAL", "OP_3", 2, id="OP_2MUL"),
    pytest.param("OP_2DIV OP_3 OP_NUMEQUAL", "OP_6", 2, id="OP_2DIV"),
    pytest.param("OP_SUBSTR 2345 OP_EQUAL", "012345 OP_1 OP_2", 2, id="OP_SUBSTR"),
    pytest.param("OP_LEFT 01 OP_EQUAL", "0102 OP_1", 2, id="OP_LEFT"),
    pytest.param("OP_RIGHT 02 OP_EQUAL", "0102 OP_1", 2, id="OP_RIGHT"),
    pytest.param("OP_LSHIFTNUM OP_4 OP_NUMEQUAL", "OP_2 OP_1", 2, id="OP_LSHIFTNUM"),
    pytest.param("OP_RSHIFTNUM OP_2 OP_NUMEQUAL", "OP_4 OP_1", 2, id="OP_RSHIFTNUM"),
    # --- Bit shifts ---
    pytest.param("OP_LSHIFT 04 OP_EQUAL", "02 OP_1", 2, id="OP_LSHIFT"),
    pytest.param("OP_RSHIFT 02 OP_EQUAL", "04 OP_1", 2, id="OP_RSHIFT"),
]


class TestDualPathOpcodes:
    """Every opcode must produce identical results on Python and native VM paths."""

    @pytest.mark.parametrize("lock_asm,unlock_asm,tx_version", _DUAL_PATH_CASES)
    def test_opcode(self, lock_asm, unlock_asm, tx_version):
        from tests.bsv.script.conftest import make_spend

        s = make_spend(lock_asm, unlock_asm, tx_version)
        assert s._validate_python() is True

        if _USE_NATIVE_VM:
            s2 = make_spend(lock_asm, unlock_asm, tx_version)
            assert s2._validate_native() is True

    def test_checksigverify_both_paths(self):
        """OP_CHECKSIGVERIFY validates identically on both paths."""
        priv = PrivateKey()
        pub = priv.public_key().serialize()
        lock = Script(encode_pushdata(pub) + OpCode.OP_CHECKSIGVERIFY + OpCode.OP_TRUE)

        inp = TransactionInput(
            source_txid=SOURCE_TXID,
            source_output_index=0,
            unlocking_script=Script(),
            sequence=0xFFFFFFFF,
            sighash=SIGHASH.ALL_FORKID,
        )
        inp.locking_script = lock
        inp.satoshis = SOURCE_SATOSHIS

        preimage = tx_preimage(0, [inp], _outputs(), 1, 0)
        sig_bytes = priv.sign(preimage)
        sig_with_hashtype = sig_bytes + SIGHASH.ALL_FORKID.to_bytes(1, "little")
        unlock = Script(encode_pushdata(sig_with_hashtype))

        s = _spend(lock, unlock)
        assert s._validate_python() is True
        if _USE_NATIVE_VM:
            s2 = _spend(lock, unlock)
            assert s2._validate_native() is True

    def test_checkmultisig_both_paths(self):
        """OP_CHECKMULTISIG validates identically on both paths."""
        priv = PrivateKey()
        pub = priv.public_key().serialize()
        lock = Script(OpCode.OP_1 + encode_pushdata(pub) + OpCode.OP_1 + OpCode.OP_CHECKMULTISIG)

        inp = TransactionInput(
            source_txid=SOURCE_TXID,
            source_output_index=0,
            unlocking_script=Script(),
            sequence=0xFFFFFFFF,
            sighash=SIGHASH.ALL_FORKID,
        )
        inp.locking_script = lock
        inp.satoshis = SOURCE_SATOSHIS

        preimage = tx_preimage(0, [inp], _outputs(), 1, 0)
        sig_bytes = priv.sign(preimage)
        sig_with_hashtype = sig_bytes + SIGHASH.ALL_FORKID.to_bytes(1, "little")
        unlock = Script(OpCode.OP_0 + encode_pushdata(sig_with_hashtype))

        s = _spend(lock, unlock)
        assert s._validate_python() is True
        if _USE_NATIVE_VM:
            s2 = _spend(lock, unlock)
            assert s2._validate_native() is True

    def test_checkmultisigverify_both_paths(self):
        """OP_CHECKMULTISIGVERIFY validates identically on both paths."""
        priv = PrivateKey()
        pub = priv.public_key().serialize()
        lock = Script(OpCode.OP_1 + encode_pushdata(pub) + OpCode.OP_1 + OpCode.OP_CHECKMULTISIGVERIFY + OpCode.OP_TRUE)

        inp = TransactionInput(
            source_txid=SOURCE_TXID,
            source_output_index=0,
            unlocking_script=Script(),
            sequence=0xFFFFFFFF,
            sighash=SIGHASH.ALL_FORKID,
        )
        inp.locking_script = lock
        inp.satoshis = SOURCE_SATOSHIS

        preimage = tx_preimage(0, [inp], _outputs(), 1, 0)
        sig_bytes = priv.sign(preimage)
        sig_with_hashtype = sig_bytes + SIGHASH.ALL_FORKID.to_bytes(1, "little")
        unlock = Script(OpCode.OP_0 + encode_pushdata(sig_with_hashtype))

        s = _spend(lock, unlock)
        assert s._validate_python() is True
        if _USE_NATIVE_VM:
            s2 = _spend(lock, unlock)
            assert s2._validate_native() is True
