"""Comprehensive Chronicle upgrade tests — regression, integration, edge cases."""

import pytest

from bsv.constants import OpCode, SIGHASH
from bsv.keys import PrivateKey
from bsv.script.script import Script
from bsv.script.spend import Spend
from bsv.script.type import P2PKH
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
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


# ============================================================
# Mixed sighash tests (review 9.4.2.2)
# ============================================================

class TestMixedSighash:
    """Mix BIP143 and OTDA inputs within a single transaction."""

    def _build_funding_tx(self, locking_script, satoshis=10_000):
        return Transaction(
            tx_inputs=[TransactionInput(
                source_txid="00" * 32,
                source_output_index=0,
                unlocking_script=Script(),
                sequence=0xFFFFFFFF,
            )],
            tx_outputs=[TransactionOutput(locking_script=locking_script, satoshis=satoshis)],
            version=1,
        )

    def test_mixed_bip143_and_otda_inputs(self):
        """One input using BIP143 (FORKID) and another using OTDA (FORKID+CHRONICLE)."""
        priv = PrivateKey("L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi")
        p2pkh = P2PKH()
        lock = p2pkh.lock(priv.address())

        funding1 = self._build_funding_tx(lock)
        funding2 = self._build_funding_tx(lock)

        inp1 = TransactionInput(
            source_transaction=funding1,
            source_output_index=0,
            unlocking_script_template=p2pkh.unlock(priv),
            sequence=0xFFFFFFFF,
            sighash=SIGHASH.ALL_FORKID,  # BIP143
        )
        inp2 = TransactionInput(
            source_transaction=funding2,
            source_output_index=0,
            unlocking_script_template=p2pkh.unlock(priv),
            sequence=0xFFFFFFFF,
            sighash=SIGHASH.ALL_FORKID_CHRONICLE,  # OTDA
        )

        tx = Transaction(
            [inp1, inp2],
            [TransactionOutput(locking_script=lock, satoshis=19_000)],
            version=2,
        )
        tx.sign(bypass=False)

        # Validate both inputs via Spend
        from tests.bsv.live.conftest import validate_all_inputs
        validate_all_inputs(tx)


# ============================================================
# OP_CODESEPARATOR interaction tests (review 9.4.2.3)
# ============================================================

class TestCodeSeparatorWithChronicle:
    """Chronicle opcodes after OP_CODESEPARATOR."""

    def test_2mul_after_codeseparator(self):
        """OP_2MUL executes correctly after OP_CODESEPARATOR."""
        spend = make_spend(
            "OP_CODESEPARATOR OP_2MUL OP_6 OP_EQUALVERIFY OP_TRUE",
            "OP_3",
            tx_version=2,
        )
        assert spend.validate()

    def test_substr_after_codeseparator(self):
        """OP_SUBSTR executes correctly after OP_CODESEPARATOR."""
        spend = make_spend(
            "OP_CODESEPARATOR OP_1 OP_1 OP_SUBSTR 62 OP_EQUALVERIFY OP_TRUE",
            "616263",
            tx_version=2,
        )
        assert spend.validate()

    def test_lshiftnum_after_codeseparator(self):
        """OP_LSHIFTNUM executes correctly after OP_CODESEPARATOR."""
        spend = make_spend(
            "OP_CODESEPARATOR OP_2 OP_LSHIFTNUM OP_8 OP_EQUALVERIFY OP_TRUE",
            "OP_2",
            tx_version=2,
        )
        assert spend.validate()
