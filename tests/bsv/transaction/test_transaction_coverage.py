"""
Coverage tests for transaction.py focusing on untested branches.
Targeting error paths, edge cases, and branch coverage.
"""
import pytest
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput
from bsv.script.script import Script
from bsv.keys import PrivateKey


@pytest.fixture
def simple_tx():
    """Create a simple transaction."""
    return Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=0)


# ========================================================================
# Initialization Edge Cases
# ========================================================================

def test_transaction_init_with_none_inputs():
    """Test Transaction handles None inputs list."""
    tx = Transaction(version=1, tx_inputs=None, tx_outputs=[], locktime=0)
    assert tx.inputs == []


def test_transaction_init_with_none_outputs():
    """Test Transaction handles None outputs list."""
    tx = Transaction(version=1, tx_inputs=[], tx_outputs=None, locktime=0)
    assert tx.outputs == []


def test_transaction_init_with_zero_version():
    """Test Transaction with version 0."""
    tx = Transaction(version=0, tx_inputs=[], tx_outputs=[], locktime=0)
    assert tx.version == 0


def test_transaction_init_with_max_locktime():
    """Test Transaction with maximum locktime."""
    max_locktime = 0xFFFFFFFF
    tx = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=max_locktime)
    assert tx.locktime == max_locktime


def test_transaction_init_empty():
    """Test Transaction with all empty/default values."""
    tx = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=0)
    assert len(tx.inputs) == 0
    assert len(tx.outputs) == 0
    assert tx.version == 1
    assert tx.locktime == 0


# ========================================================================
# Serialization Edge Cases
# ========================================================================

def test_transaction_serialize_empty(simple_tx):
    """Test serializing empty transaction."""
    serialized = simple_tx.serialize()
    assert isinstance(serialized, bytes)
    assert len(serialized) > 0


def test_transaction_serialize_with_single_input():
    """Test serialization with one input."""
    # Create a simple mock transaction for input
    mock_prev_tx = Transaction(version=1, tx_inputs=[], tx_outputs=[
        TransactionOutput(satoshis=1000, locking_script=Script.from_asm(""))
    ], locktime=0)
    
    inp = TransactionInput(
        source_transaction=mock_prev_tx,
        source_output_index=0,
        unlocking_script=Script.from_asm(""),
        sequence=0xFFFFFFFF
    )
    tx = Transaction(version=1, tx_inputs=[inp], tx_outputs=[], locktime=0)
    serialized = tx.serialize()
    assert isinstance(serialized, bytes)


def test_transaction_serialize_with_single_output():
    """Test serialization with one output."""
    out = TransactionOutput(
        satoshis=1000,
        locking_script=Script.from_asm("OP_DUP OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG")
    )
    tx = Transaction(version=1, tx_inputs=[], tx_outputs=[out], locktime=0)
    serialized = tx.serialize()
    assert isinstance(serialized, bytes)


# ========================================================================
# Hash Edge Cases
# ========================================================================

def test_transaction_hash_empty(simple_tx):
    """Test hash of empty transaction."""
    tx_hash = simple_tx.hash()
    assert isinstance(tx_hash, bytes)
    assert len(tx_hash) == 32


def test_transaction_hash_deterministic(simple_tx):
    """Test that hash is deterministic."""
    hash1 = simple_tx.hash()
    hash2 = simple_tx.hash()
    assert hash1 == hash2


def test_transaction_hex_method(simple_tx):
    """Test hex() method returns hex string."""
    hex_str = simple_tx.hex()
    assert isinstance(hex_str, str)
    # Should be valid hex
    assert all(c in '0123456789abcdef' for c in hex_str.lower())


# ========================================================================
# Input/Output Mutation
# ========================================================================

def test_transaction_add_input_after_creation(simple_tx):
    """Test adding input after creation."""
    # Create a simple mock transaction for input
    mock_prev_tx = Transaction(version=1, tx_inputs=[], tx_outputs=[
        TransactionOutput(satoshis=1000, locking_script=Script.from_asm(""))
    ], locktime=0)
    
    inp = TransactionInput(
        source_transaction=mock_prev_tx,
        source_output_index=0,
        unlocking_script=Script.from_asm(""),
        sequence=0xFFFFFFFF
    )
    simple_tx.inputs.append(inp)
    assert len(simple_tx.inputs) == 1


def test_transaction_add_output_after_creation(simple_tx):
    """Test adding output after creation."""
    out = TransactionOutput(
        satoshis=1000,
        locking_script=Script.from_asm("")
    )
    simple_tx.outputs.append(out)
    assert len(simple_tx.outputs) == 1


def test_transaction_multiple_inputs():
    """Test transaction with multiple inputs."""
    # Create a simple mock transaction for inputs
    mock_prev_tx = Transaction(version=1, tx_inputs=[], tx_outputs=[
        TransactionOutput(satoshis=1000, locking_script=Script.from_asm(""))
    ], locktime=0)
    
    inputs = [
        TransactionInput(
            source_transaction=mock_prev_tx,
            source_output_index=0,
            unlocking_script=Script.from_asm(""),
            sequence=0xFFFFFFFF
        )
        for i in range(3)
    ]
    tx = Transaction(version=1, tx_inputs=inputs, tx_outputs=[], locktime=0)
    assert len(tx.inputs) == 3


def test_transaction_multiple_outputs():
    """Test transaction with multiple outputs."""
    outputs = [
        TransactionOutput(
            satoshis=1000 * (i + 1),
            locking_script=Script.from_asm("")
        )
        for i in range(3)
    ]
    tx = Transaction(version=1, tx_inputs=[], tx_outputs=outputs, locktime=0)
    assert len(tx.outputs) == 3


# ========================================================================
# Boundary Conditions
# ========================================================================

def test_transaction_zero_satoshi_output():
    """Test output with zero satoshis."""
    out = TransactionOutput(satoshis=0, locking_script=Script.from_asm(""))
    tx = Transaction(version=1, tx_inputs=[], tx_outputs=[out], locktime=0)
    assert tx.outputs[0].satoshis == 0


def test_transaction_large_satoshi_output():
    """Test output with large satoshi amount."""
    large_amount = 21_000_000 * 100_000_000  # Max BTC supply in satoshis
    out = TransactionOutput(satoshis=large_amount, locking_script=Script.from_asm(""))
    tx = Transaction(version=1, tx_inputs=[], tx_outputs=[out], locktime=0)
    assert tx.outputs[0].satoshis == large_amount


def test_transaction_with_locktime_zero(simple_tx):
    """Test transaction with locktime 0 (unlocked)."""
    assert simple_tx.locktime == 0
    serialized = simple_tx.serialize()
    assert isinstance(serialized, bytes)


def test_transaction_with_locktime_block_height():
    """Test transaction with locktime as block height."""
    block_height = 500000  # Less than 500000000
    tx = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=block_height)
    assert tx.locktime == block_height


def test_transaction_with_locktime_timestamp():
    """Test transaction with locktime as timestamp."""
    timestamp = 1500000000  # Greater than 500000000
    tx = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=timestamp)
    assert tx.locktime == timestamp


# ========================================================================
# Version Variations
# ========================================================================

def test_transaction_version_1():
    """Test transaction with version 1 (standard)."""
    tx = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=0)
    assert tx.version == 1


def test_transaction_version_2():
    """Test transaction with version 2 (BIP 68)."""
    tx = Transaction(version=2, tx_inputs=[], tx_outputs=[], locktime=0)
    assert tx.version == 2


def test_transaction_negative_version():
    """Test transaction with negative version."""
    tx = Transaction(version=-1, tx_inputs=[], tx_outputs=[], locktime=0)
    assert tx.version == -1

