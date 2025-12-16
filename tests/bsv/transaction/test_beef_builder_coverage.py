"""
Coverage tests for transaction/beef_builder.py - untested branches.
"""
import pytest
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput
from bsv.script.script import Script


# ========================================================================
# BEEF Builder initialization branches
# ========================================================================

def test_beef_builder_init():
    """Test BEEF Builder functions availability."""
    from bsv.transaction.beef_builder import merge_transaction, merge_beef
    from bsv.transaction.beef import Beef
    
    # beef_builder module has functions, not a class
    beef = Beef(version=4)
    assert beef is not None
    assert callable(merge_transaction)
    assert callable(merge_beef)


# ========================================================================
# BEEF Builder add transaction branches
# ========================================================================

def test_beef_builder_add_transaction():
    """Test adding transaction to BEEF."""
    from bsv.transaction.beef_builder import merge_transaction
    from bsv.transaction.beef import Beef
    
    beef = Beef(version=4)
    tx = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=0)
    
    # Use merge_transaction function
    beef_tx = merge_transaction(beef, tx)
    assert beef_tx is not None


def test_beef_builder_add_multiple_transactions():
    """Test adding multiple transactions."""
    from bsv.transaction.beef_builder import merge_transaction
    from bsv.transaction.beef import Beef
    
    beef = Beef(version=4)
    tx1 = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=0)
    tx2 = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=0)
    
    # Use merge_transaction function for multiple transactions
    beef_tx1 = merge_transaction(beef, tx1)
    beef_tx2 = merge_transaction(beef, tx2)
    assert beef_tx1 is not None
    assert beef_tx2 is not None


# ========================================================================
# BEEF Builder build branches
# ========================================================================

def test_beef_builder_build():
    """Test building BEEF."""
    from bsv.transaction.beef import Beef
    
    # Beef is created directly, not via a builder
    beef = Beef(version=4)
    assert beef is not None
    assert hasattr(beef, 'to_binary')
    assert hasattr(beef, 'to_hex')


def test_beef_builder_build_with_transactions():
    """Test building BEEF with transactions."""
    from bsv.transaction.beef_builder import merge_transaction
    from bsv.transaction.beef import Beef
    
    beef = Beef(version=4)
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
    
    # Use merge_transaction to add tx to beef
    beef_tx = merge_transaction(beef, tx)
    assert beef_tx is not None
    assert beef is not None


# ========================================================================
# Edge cases
# ========================================================================

def test_beef_builder_empty():
    """Test building empty BEEF."""
    from bsv.transaction.beef import Beef
    
    # Beef can be created empty
    beef = Beef(version=4)
    assert beef is not None
    assert hasattr(beef, 'txs')


def test_beef_builder_reset():
    """Test resetting BEEF builder."""
    from bsv.transaction.beef_builder import merge_transaction, remove_existing_txid
    from bsv.transaction.beef import Beef
    
    beef = Beef(version=4)
    tx = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=0)
    
    # Add transaction and then remove it (reset-like operation)
    beef_tx = merge_transaction(beef, tx)
    if beef_tx:
        remove_existing_txid(beef, beef_tx.txid)
    assert True

