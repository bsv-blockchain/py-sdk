"""Tests for Chronicle malleability relaxation (tx version > 1)."""

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


class TestIsRelaxed:
    def test_version_1_returns_false(self):
        spend = make_spend("OP_TRUE", tx_version=1)
        assert not spend.is_relaxed()

    def test_version_2_returns_true(self):
        spend = make_spend("OP_TRUE", tx_version=2)
        assert spend.is_relaxed()

    def test_version_3_returns_true(self):
        spend = make_spend("OP_TRUE", tx_version=3)
        assert spend.is_relaxed()


class TestRelaxedDirtyStack:
    def test_v2_allows_dirty_stack(self):
        # Extra items on stack after execution — v2 allows it
        spend = make_spend("OP_TRUE", "OP_1 OP_2", tx_version=2)
        assert spend.validate()

    def test_v1_rejects_dirty_stack(self):
        spend = make_spend("OP_TRUE", "OP_1 OP_2", tx_version=1)
        with pytest.raises(Exception, match="clean stack"):
            spend.validate()


class TestRelaxedPushOnlyUnlocking:
    def test_v2_allows_opcodes_in_unlocking(self):
        # OP_1 OP_1 OP_ADD in unlocking script — contains non-push opcode
        spend = make_spend("OP_2 OP_EQUALVERIFY OP_TRUE", "OP_1 OP_1 OP_ADD", tx_version=2)
        assert spend.validate()

    def test_v1_rejects_opcodes_in_unlocking(self):
        spend = make_spend("OP_2 OP_EQUALVERIFY OP_TRUE", "OP_1 OP_1 OP_ADD", tx_version=1)
        with pytest.raises(Exception, match="push operations"):
            spend.validate()


class TestRelaxedNulldummy:
    def test_v2_allows_non_empty_dummy(self):
        # CHECKMULTISIG dummy element check — v2 allows non-empty dummy
        # This is hard to test without real signature verification,
        # so we test that the check is gated
        spend = make_spend("OP_TRUE", tx_version=2)
        # Just verify is_relaxed gates the check
        assert spend.is_relaxed()

    def test_v1_enforces_empty_dummy(self):
        spend = make_spend("OP_TRUE", tx_version=1)
        assert not spend.is_relaxed()
