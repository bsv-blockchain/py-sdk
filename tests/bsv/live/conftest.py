"""Shared fixtures and helpers for mocked live tests."""

import pytest

from bsv.broadcasters.broadcaster import BroadcastResponse, Broadcaster
from bsv.chaintracker import ChainTracker
from bsv.constants import SIGHASH, OpCode
from bsv.hash import hash160
from bsv.keys import PrivateKey
from bsv.script.script import Script
from bsv.script.spend import Spend
from bsv.script.type import P2PKH, to_unlock_script_template
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput
from bsv.utils import encode_pushdata


# ---------------------------------------------------------------------------
# Mock implementations
# ---------------------------------------------------------------------------


class MockBroadcaster(Broadcaster):
    """Captures transactions instead of broadcasting to the network."""

    def __init__(self):
        super().__init__()
        self.transactions: list[Transaction] = []

    async def broadcast(self, transaction):
        self.transactions.append(transaction)
        return BroadcastResponse(
            status="success",
            txid=transaction.txid(),
            message="mock broadcast",
        )


class MockChainTracker(ChainTracker):
    """Always-valid chain tracker for testing."""

    async def is_valid_root_for_height(self, root: str, height: int) -> bool:
        return True

    async def current_height(self) -> int:
        return 943_816


# ---------------------------------------------------------------------------
# Deterministic key fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def priv_key():
    return PrivateKey("L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi")


@pytest.fixture
def priv_key2():
    return PrivateKey("L32Mf2qU7BLmPmnbs943EYWRv4EUpqnFxkViinPMYesxWLnL6DTA")


@pytest.fixture
def priv_key3():
    return PrivateKey("L1DkuXRTu3cGZAmJCDw2TWAoEaRKesq2sZUGzUmbYExgDwhQWe5T")


@pytest.fixture
def mock_broadcaster():
    return MockBroadcaster()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def build_funding_tx(locking_script: Script, satoshis: int = 10_000) -> Transaction:
    """Create a synthetic funding transaction with one output.

    The funding tx itself does not need to be valid — it just provides
    a UTXO for a spending transaction to reference via source_transaction.
    """
    return Transaction(
        tx_inputs=[
            TransactionInput(
                source_txid="00" * 32,
                source_output_index=0,
                unlocking_script=Script(),
                sequence=0xFFFFFFFF,
            )
        ],
        tx_outputs=[
            TransactionOutput(locking_script=locking_script, satoshis=satoshis),
        ],
        version=1,
    )


def validate_spend(tx: Transaction, input_index: int) -> bool:
    """Validate a single input of a signed transaction via Spend.validate()."""
    inp = tx.inputs[input_index]

    other_inputs = []
    for j, other in enumerate(tx.inputs):
        if j != input_index:
            other_inputs.append(
                TransactionInput(
                    source_txid=other.source_txid,
                    source_output_index=other.source_output_index,
                    unlocking_script=other.unlocking_script,
                    sequence=other.sequence,
                    sighash=other.sighash,
                )
            )
            # Carry over satoshis and locking_script for preimage computation
            other_inputs[-1].satoshis = other.satoshis
            other_inputs[-1].locking_script = other.locking_script

    spend = Spend(
        {
            "sourceTXID": inp.source_txid,
            "sourceOutputIndex": inp.source_output_index,
            "sourceSatoshis": inp.satoshis,
            "lockingScript": inp.locking_script,
            "transactionVersion": tx.version,
            "otherInputs": other_inputs,
            "outputs": tx.outputs,
            "inputIndex": input_index,
            "unlockingScript": inp.unlocking_script,
            "inputSequence": inp.sequence,
            "lockTime": tx.locktime,
        }
    )
    return spend.validate()


def validate_all_inputs(tx: Transaction) -> None:
    """Validate every input in a signed transaction via Spend."""
    for i in range(len(tx.inputs)):
        assert validate_spend(tx, i), f"Spend validation failed for input {i}"


def build_signed_tx(
    locking_script: Script,
    unlock_template,
    sighash: int = SIGHASH.ALL_FORKID,
    tx_version: int = 1,
    num_inputs: int = 1,
    num_outputs: int = 1,
    satoshis: int = 10_000,
) -> Transaction:
    """Build a transaction, sign it, validate every input, and return it.

    Args:
        locking_script: The locking script for each funding output.
        unlock_template: An UnlockingScriptTemplate class (not instance).
        sighash: Sighash flag for all inputs.
        tx_version: Transaction version (1 = legacy, 2 = Chronicle).
        num_inputs: Number of inputs to create.
        num_outputs: Number of outputs to create.
        satoshis: Satoshis per funding UTXO.
    """
    inputs = []
    for _ in range(num_inputs):
        funding_tx = build_funding_tx(locking_script, satoshis=satoshis)
        inputs.append(
            TransactionInput(
                source_transaction=funding_tx,
                source_output_index=0,
                unlocking_script_template=unlock_template,
                sequence=0xFFFFFFFF,
                sighash=SIGHASH(sighash),
            )
        )

    # Distribute satoshis across outputs (leave room for fee)
    total = satoshis * num_inputs
    per_output = (total - 500) // num_outputs  # 500 sat fee buffer
    outputs = [
        TransactionOutput(locking_script=locking_script, satoshis=per_output)
        for _ in range(num_outputs)
    ]

    tx = Transaction(inputs, outputs, version=tx_version)
    tx.sign(bypass=False)
    validate_all_inputs(tx)
    return tx


def custom_unlock(priv_key: PrivateKey, data_prefix_script: Script = None):
    """Create an UnlockingScriptTemplate that pushes optional data then <sig> <pubkey>.

    Use this for opcode tests where the unlocking script needs to push
    data items before the standard P2PKH signature + public key.
    """

    def sign(tx, input_index) -> Script:
        tx_input = tx.inputs[input_index]
        sighash = tx_input.sighash
        signature = priv_key.sign(tx.preimage(input_index))
        public_key = priv_key.public_key().serialize()
        sig_script = Script(
            encode_pushdata(signature + sighash.to_bytes(1, "little"))
            + encode_pushdata(public_key)
        )
        if data_prefix_script:
            # Data goes AFTER sig+pubkey so it's on TOP of the stack
            # when the locking script starts executing
            return Script(sig_script.serialize() + data_prefix_script.serialize())
        return sig_script

    def estimated_unlocking_byte_length() -> int:
        return 200

    return to_unlock_script_template(sign, estimated_unlocking_byte_length)


def p2pkh_lock_with_prefix(prefix_asm: str, priv_key: PrivateKey) -> Script:
    """Build a locking script: {prefix opcodes} OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG.

    The prefix opcodes consume data items from the stack before P2PKH
    validation runs on the remaining <sig> <pubkey>.
    """
    pkh = hash160(priv_key.public_key().serialize())
    prefix = Script.from_asm(prefix_asm) if prefix_asm else Script()
    p2pkh_suffix = Script(
        OpCode.OP_DUP
        + OpCode.OP_HASH160
        + encode_pushdata(pkh)
        + OpCode.OP_EQUALVERIFY
        + OpCode.OP_CHECKSIG
    )
    return Script(prefix.serialize() + p2pkh_suffix.serialize())
