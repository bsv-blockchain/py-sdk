"""Chronicle opcodes in real signed transactions.

Each test builds a Transaction with a custom locking script exercising
a restored opcode, signs it with real keys, validates via Spend.validate(),
and mock-broadcasts.
"""

import pytest

from bsv.constants import SIGHASH
from bsv.script.script import Script
from bsv.utils import encode_pushdata

from .conftest import (
    MockBroadcaster,
    build_signed_tx,
    custom_unlock,
    p2pkh_lock_with_prefix,
)

# Test each opcode with both BIP143 (FORKID v1) and OTDA (FORKID+CHRONICLE v2)
SIGHASH_VERSIONS = [
    pytest.param(SIGHASH.ALL_FORKID, 1, id="BIP143_v1"),
    pytest.param(SIGHASH.ALL_FORKID_CHRONICLE, 2, id="OTDA_v2"),
]


# ---------------------------------------------------------------------------
# OP_VER
# ---------------------------------------------------------------------------


class TestOpVer:
    """OP_VER pushes the tx version as 4-byte LE onto the stack."""

    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSIONS)
    def test_op_ver_v1(self, priv_key, sighash, tx_version):
        """OP_VER pushes 4-byte LE nVersion; compare with OP_EQUALVERIFY (not NUMEQUAL on-node)."""
        ver_le_hex = tx_version.to_bytes(4, "little").hex()
        lock = p2pkh_lock_with_prefix(f"OP_VER {ver_le_hex} OP_EQUALVERIFY", priv_key)
        unlock = custom_unlock(priv_key)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert tx.txid()

    def test_op_ver_version_2_explicit(self, priv_key):
        """OP_VER on a v2 tx pushes 02000000 LE."""
        lock = p2pkh_lock_with_prefix("OP_VER 02000000 OP_EQUALVERIFY", priv_key)
        unlock = custom_unlock(priv_key)
        tx = build_signed_tx(
            lock,
            unlock,
            sighash=SIGHASH.ALL_FORKID_CHRONICLE,
            tx_version=2,
        )
        assert tx.txid()


# ---------------------------------------------------------------------------
# OP_VERIF
# ---------------------------------------------------------------------------


class TestOpVerif:
    """OP_VERIF pops a value, compares tx_version >= value, pushes to if_stack."""

    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSIONS)
    def test_op_verif_true_branch(self, priv_key, sighash, tx_version):
        """Push 4-byte LE version onto stack, OP_VERIF enters TRUE branch."""
        # Locking: OP_VERIF <true_branch: P2PKH> OP_ELSE OP_FALSE OP_ENDIF
        lock = p2pkh_lock_with_prefix(
            "OP_VERIF",
            priv_key,
        )
        # Append OP_ELSE OP_FALSE OP_ENDIF
        lock = Script(lock.serialize() + Script.from_asm("OP_ELSE OP_FALSE OP_ENDIF").serialize())
        # Unlocking pushes 4-byte LE version (matching tx_version) then sig+pubkey
        ver_bytes = tx_version.to_bytes(4, "little")
        data = Script(encode_pushdata(ver_bytes))
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert tx.txid()

    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSIONS)
    def test_op_verif_false_branch(self, priv_key, sighash, tx_version):
        """Push version higher than tx_version, OP_VERIF enters FALSE branch."""
        # Locking: OP_VERIF OP_FALSE OP_ELSE <P2PKH> OP_ENDIF
        from bsv.constants import OpCode
        from bsv.hash import hash160

        pkh = hash160(priv_key.public_key().serialize())
        p2pkh_script = Script(
            OpCode.OP_DUP + OpCode.OP_HASH160 + encode_pushdata(pkh) + OpCode.OP_EQUALVERIFY + OpCode.OP_CHECKSIG
        )
        lock = Script(
            Script.from_asm("OP_VERIF OP_FALSE OP_ELSE").serialize()
            + p2pkh_script.serialize()
            + Script.from_asm("OP_ENDIF").serialize()
        )
        # Push version higher than tx_version so condition is false
        high_ver = (tx_version + 1).to_bytes(4, "little")
        data = Script(encode_pushdata(high_ver))
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert tx.txid()


# ---------------------------------------------------------------------------
# OP_VERNOTIF
# ---------------------------------------------------------------------------


class TestOpVernotif:
    """OP_VERNOTIF is negated OP_VERIF."""

    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSIONS)
    def test_op_vernotif_true_when_not_matching(self, priv_key, sighash, tx_version):
        """OP_VERNOTIF enters TRUE branch when version comparison fails."""
        # Push higher version so VERIF would be FALSE, VERNOTIF makes it TRUE
        lock = p2pkh_lock_with_prefix("OP_VERNOTIF", priv_key)
        lock = Script(lock.serialize() + Script.from_asm("OP_ELSE OP_FALSE OP_ENDIF").serialize())
        high_ver = (tx_version + 1).to_bytes(4, "little")
        data = Script(encode_pushdata(high_ver))
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert tx.txid()


# ---------------------------------------------------------------------------
# OP_2MUL
# ---------------------------------------------------------------------------


class TestOp2Mul:
    """OP_2MUL multiplies top stack item by 2."""

    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSIONS)
    def test_2mul_basic(self, priv_key, sighash, tx_version):
        """Doubling 2 yields 4."""
        lock = p2pkh_lock_with_prefix("OP_2MUL OP_4 OP_NUMEQUALVERIFY", priv_key)
        data = Script.from_asm("OP_2")
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert tx.txid()

    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSIONS)
    def test_2mul_zero(self, priv_key, sighash, tx_version):
        """Doubling 0 yields 0."""
        lock = p2pkh_lock_with_prefix("OP_2MUL OP_0 OP_NUMEQUALVERIFY", priv_key)
        data = Script.from_asm("OP_0")
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert tx.txid()

    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSIONS)
    def test_2mul_negative(self, priv_key, sighash, tx_version):
        """Doubling minus one yields minus two."""
        lock = p2pkh_lock_with_prefix("OP_2MUL OP_1NEGATE OP_1SUB OP_NUMEQUALVERIFY", priv_key)
        data = Script.from_asm("OP_1NEGATE")
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert tx.txid()


# ---------------------------------------------------------------------------
# OP_2DIV
# ---------------------------------------------------------------------------


class TestOp2Div:
    """OP_2DIV divides top stack item by 2 (truncates toward zero)."""

    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSIONS)
    def test_2div_basic(self, priv_key, sighash, tx_version):
        """Halving 10 yields 5."""
        lock = p2pkh_lock_with_prefix("OP_2DIV OP_5 OP_NUMEQUALVERIFY", priv_key)
        data = Script.from_asm("OP_10")
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert tx.txid()

    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSIONS)
    def test_2div_truncation(self, priv_key, sighash, tx_version):
        """Halving 7 yields 3 (truncated)."""
        lock = p2pkh_lock_with_prefix("OP_2DIV OP_3 OP_NUMEQUALVERIFY", priv_key)
        data = Script.from_asm("OP_7")
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert tx.txid()

    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSIONS)
    def test_2div_zero(self, priv_key, sighash, tx_version):
        """Halving 0 yields 0."""
        lock = p2pkh_lock_with_prefix("OP_2DIV OP_0 OP_NUMEQUALVERIFY", priv_key)
        data = Script.from_asm("OP_0")
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert tx.txid()


# ---------------------------------------------------------------------------
# OP_SUBSTR
# ---------------------------------------------------------------------------


class TestOpSubstr:
    """OP_SUBSTR extracts a substring. Stack: data, start, length -> substr."""

    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSIONS)
    def test_substr_basic(self, priv_key, sighash, tx_version):
        """Extract 'bc' from 'abcde' (start=1, length=2)."""
        lock = p2pkh_lock_with_prefix("OP_SUBSTR 6263 OP_EQUALVERIFY", priv_key)
        # Stack top to bottom after unlock: length(2), start(1), data("abcde")
        # Push order in unlock (bottom to top): data, start, length
        data = Script(
            encode_pushdata(bytes.fromhex("6162636465"))  # "abcde"
            + Script.from_asm("OP_1 OP_2").serialize()  # pushes start (1) then length (2)
        )
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert tx.txid()


# ---------------------------------------------------------------------------
# OP_LEFT
# ---------------------------------------------------------------------------


class TestOpLeft:
    """OP_LEFT returns leftmost n bytes. Stack: data, length -> left."""

    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSIONS)
    def test_left_basic(self, priv_key, sighash, tx_version):
        """Left 2 bytes of 'abcde' = 'ab'."""
        lock = p2pkh_lock_with_prefix("OP_LEFT 6162 OP_EQUALVERIFY", priv_key)
        data = Script(encode_pushdata(bytes.fromhex("6162636465")) + Script.from_asm("OP_2").serialize())
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert tx.txid()

    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSIONS)
    def test_left_full_length(self, priv_key, sighash, tx_version):
        """Left 5 bytes of 'abcde' = 'abcde'."""
        lock = p2pkh_lock_with_prefix("OP_LEFT 6162636465 OP_EQUALVERIFY", priv_key)
        data = Script(encode_pushdata(bytes.fromhex("6162636465")) + Script.from_asm("OP_5").serialize())
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert tx.txid()


# ---------------------------------------------------------------------------
# OP_RIGHT
# ---------------------------------------------------------------------------


class TestOpRight:
    """OP_RIGHT returns rightmost n bytes. Stack: data, length -> right."""

    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSIONS)
    def test_right_basic(self, priv_key, sighash, tx_version):
        """Right 2 bytes of 'abcde' = 'de'."""
        lock = p2pkh_lock_with_prefix("OP_RIGHT 6465 OP_EQUALVERIFY", priv_key)
        data = Script(encode_pushdata(bytes.fromhex("6162636465")) + Script.from_asm("OP_2").serialize())
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert tx.txid()

    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSIONS)
    def test_right_full_length(self, priv_key, sighash, tx_version):
        """Right 5 bytes of 'abcde' = 'abcde'."""
        lock = p2pkh_lock_with_prefix("OP_RIGHT 6162636465 OP_EQUALVERIFY", priv_key)
        data = Script(encode_pushdata(bytes.fromhex("6162636465")) + Script.from_asm("OP_5").serialize())
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert tx.txid()


# ---------------------------------------------------------------------------
# OP_LSHIFTNUM
# ---------------------------------------------------------------------------


class TestOpLshiftnum:
    """OP_LSHIFTNUM left-shifts a number. Stack: value, shift_amount -> result."""

    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSIONS)
    def test_lshiftnum_basic(self, priv_key, sighash, tx_version):
        """Shifting 1 left by 3 yields 8."""
        lock = p2pkh_lock_with_prefix("OP_LSHIFTNUM OP_8 OP_NUMEQUALVERIFY", priv_key)
        data = Script.from_asm("OP_1 OP_3")
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert tx.txid()

    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSIONS)
    def test_lshiftnum_zero_shift(self, priv_key, sighash, tx_version):
        """Shifting 5 left by 0 yields 5."""
        lock = p2pkh_lock_with_prefix("OP_LSHIFTNUM OP_5 OP_NUMEQUALVERIFY", priv_key)
        data = Script.from_asm("OP_5 OP_0")
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert tx.txid()


# ---------------------------------------------------------------------------
# OP_RSHIFTNUM
# ---------------------------------------------------------------------------


class TestOpRshiftnum:
    """OP_RSHIFTNUM right-shifts a number. Stack: value, shift_amount -> result."""

    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSIONS)
    def test_rshiftnum_basic(self, priv_key, sighash, tx_version):
        """Shifting 8 right by 2 yields 2."""
        lock = p2pkh_lock_with_prefix("OP_RSHIFTNUM OP_2 OP_NUMEQUALVERIFY", priv_key)
        data = Script.from_asm("OP_8 OP_2")
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert tx.txid()

    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSIONS)
    def test_rshiftnum_truncation(self, priv_key, sighash, tx_version):
        """Shifting 7 right by 1 yields 3 (truncated)."""
        lock = p2pkh_lock_with_prefix("OP_RSHIFTNUM OP_3 OP_NUMEQUALVERIFY", priv_key)
        data = Script.from_asm("OP_7 OP_1")
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert tx.txid()

    @pytest.mark.parametrize("sighash,tx_version", SIGHASH_VERSIONS)
    def test_rshiftnum_zero_shift(self, priv_key, sighash, tx_version):
        """Shifting 5 right by 0 yields 5."""
        lock = p2pkh_lock_with_prefix("OP_RSHIFTNUM OP_5 OP_NUMEQUALVERIFY", priv_key)
        data = Script.from_asm("OP_5 OP_0")
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        tx = build_signed_tx(lock, unlock, sighash=sighash, tx_version=tx_version)
        assert tx.txid()


# ---------------------------------------------------------------------------
# Mock broadcast integration for chronicle opcodes
# ---------------------------------------------------------------------------


class TestChronicleOpcodeBroadcast:
    """Verify chronicle opcode txs can be mock-broadcast after validation."""

    @pytest.mark.asyncio
    async def test_broadcast_op_ver_tx(self, priv_key, mock_broadcaster):
        lock = p2pkh_lock_with_prefix("OP_VER 02000000 OP_EQUALVERIFY", priv_key)
        unlock = custom_unlock(priv_key)
        tx = build_signed_tx(
            lock,
            unlock,
            sighash=SIGHASH.ALL_FORKID_CHRONICLE,
            tx_version=2,
        )
        result = await tx.broadcast(broadcaster=mock_broadcaster)
        assert result.status == "success"
        assert result.txid == tx.txid()

    @pytest.mark.asyncio
    async def test_broadcast_op_2mul_tx(self, priv_key, mock_broadcaster):
        lock = p2pkh_lock_with_prefix("OP_2MUL OP_6 OP_NUMEQUALVERIFY", priv_key)
        data = Script.from_asm("OP_3")
        unlock = custom_unlock(priv_key, data_prefix_script=data)
        tx = build_signed_tx(
            lock,
            unlock,
            sighash=SIGHASH.ALL_FORKID_CHRONICLE,
            tx_version=2,
        )
        result = await tx.broadcast(broadcaster=mock_broadcaster)
        assert result.status == "success"
