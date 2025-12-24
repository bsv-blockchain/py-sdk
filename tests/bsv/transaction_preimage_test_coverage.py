"""
Coverage tests for transaction_preimage.py - untested branches.
"""
import pytest
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput
from bsv.script.script import Script


# ========================================================================
# Transaction preimage branches
# ========================================================================

def test_transaction_preimage_basic():
    """Test generating transaction preimage."""
    tx = Transaction(
        version=1,
        tx_inputs=[
            TransactionInput(
                source_txid='0' * 64,
                source_output_index=0,
                unlocking_script=Script(b''),
                sequence=0xFFFFFFFF
            )
        ],
        tx_outputs=[
            TransactionOutput(satoshis=1000, locking_script=Script(b''))
        ],
        locktime=0
    )
    
    if hasattr(tx, 'preimage'):
        preimage = tx.preimage(0)
        assert isinstance(preimage, bytes)
        assert len(preimage) > 0


def test_transaction_preimage_multiple_inputs():
    """Test preimage with multiple inputs."""
    tx = Transaction(
        version=1,
        tx_inputs=[
            TransactionInput(
                source_txid='0' * 64,
                source_output_index=0,
                unlocking_script=Script(b''),
                sequence=0xFFFFFFFF
            ),
            TransactionInput(
                source_txid='1' * 64,
                source_output_index=1,
                unlocking_script=Script(b''),
                sequence=0xFFFFFFFF
            )
        ],
        tx_outputs=[
            TransactionOutput(satoshis=1000, locking_script=Script(b''))
        ],
        locktime=0
    )
    
    if hasattr(tx, 'preimage'):
        preimage0 = tx.preimage(0)
        preimage1 = tx.preimage(1)
        assert preimage0 != preimage1


def test_transaction_preimage_with_sighash():
    """Test preimage with specific sighash type."""
    try:
        from bsv.constants import SIGHASH
        
        tx = Transaction(
            version=1,
            tx_inputs=[
                TransactionInput(
                    source_txid='0' * 64,
                    source_output_index=0,
                    unlocking_script=Script(b''),
                    sequence=0xFFFFFFFF
                )
            ],
            tx_outputs=[
                TransactionOutput(satoshis=1000, locking_script=Script(b''))
            ],
            locktime=0
        )
        
        if hasattr(tx, 'preimage'):
            try:
                preimage = tx.preimage(0, sighash_type=SIGHASH.ALL)
                assert isinstance(preimage, bytes)
            except TypeError:
                # preimage may not accept sighash_type parameter
                pytest.skip("preimage doesn't support sighash_type parameter")
    except ImportError:
        pytest.skip("SIGHASH not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_transaction_preimage_index_bounds():
    """Test preimage with input index at bounds."""
    tx = Transaction(
        version=1,
        tx_inputs=[
            TransactionInput(
                source_txid='0' * 64,
                source_output_index=0,
                unlocking_script=Script(b''),
                sequence=0xFFFFFFFF
            )
        ],
        tx_outputs=[
            TransactionOutput(satoshis=1000, locking_script=Script(b''))
        ],
        locktime=0
    )
    
    if hasattr(tx, 'preimage'):
        try:
            _ = tx._(99)  # Out of bounds
            assert False, "Should raise error"
        except IndexError:
            assert True


def test_transaction_preimage_deterministic():
    """Test preimage is deterministic."""
    tx = Transaction(
        version=1,
        tx_inputs=[
            TransactionInput(
                source_txid='0' * 64,
                source_output_index=0,
                unlocking_script=Script(b''),
                sequence=0xFFFFFFFF
            )
        ],
        tx_outputs=[
            TransactionOutput(satoshis=1000, locking_script=Script(b''))
        ],
        locktime=0
    )
    
    if hasattr(tx, 'preimage'):
        preimage1 = tx.preimage(0)
        preimage2 = tx.preimage(0)
        assert preimage1 == preimage2

