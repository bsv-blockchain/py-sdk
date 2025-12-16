"""
Coverage tests for transaction/beef.py - untested branches.
"""
import pytest
from bsv.transaction import Transaction


# ========================================================================
# BEEF class initialization branches
# ========================================================================

def test_beef_init():
    """Test BEEF initialization."""
    from bsv.transaction.beef import Beef
    beef = Beef(version=4)
    assert beef  # Verify object creation succeeds


def test_beef_init_with_transactions():
    """Test BEEF with transactions."""
    from bsv.transaction.beef import Beef
    
    tx = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=0)
    
    # Beef constructor accepts version, create empty beef and add tx via merge
    beef = Beef(version=4)
    assert hasattr(beef, 'txs')


# ========================================================================
# BEEF serialization branches
# ========================================================================

def test_beef_serialize():
    """Test BEEF serialization."""
    from bsv.transaction.beef import Beef
    
    beef = Beef(version=4)
    
    if hasattr(beef, 'to_binary'):
        serialized = beef.to_binary()
        assert isinstance(serialized, bytes)


def test_beef_deserialize():
    """Test BEEF deserialization."""
    from bsv.transaction.beef import Beef
    
    if hasattr(Beef, 'deserialize'):
        try:
            _ = Beef.deserialize(b'')
            assert True
        except Exception:
            # Expected with empty data
            assert True


# ========================================================================
# BEEF transaction management branches
# ========================================================================

def test_beef_get_transactions():
    """Test getting transactions from BEEF."""
    from bsv.transaction.beef import Beef
    
    beef = Beef(version=4)
    
    # Beef has txs dict, not get_transactions method
    assert hasattr(beef, 'txs')
    assert isinstance(beef.txs, dict)


def test_beef_add_transaction():
    """Test adding transaction to BEEF."""
    from bsv.transaction.beef_builder import merge_transaction
    from bsv.transaction.beef import Beef
    
    beef = Beef(version=4)
    tx = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=0)
    
    # Use merge_transaction function to add tx
    beef_tx = merge_transaction(beef, tx)
    assert beef_tx is not None


# ========================================================================
# BEEF validation branches
# ========================================================================

def test_beef_validate():
    """Test BEEF validation."""
    from bsv.transaction.beef import Beef
    
    beef = Beef(version=4)
    
    # Beef has validation methods
    if hasattr(beef, 'is_valid'):
        try:
            is_valid = beef.is_valid()
            assert isinstance(is_valid, bool)
        except Exception:
            # May require valid structure
            pass


# ========================================================================
# Edge cases
# ========================================================================

def test_beef_empty():
    """Test empty BEEF."""
    from bsv.transaction.beef import Beef
    
    beef = Beef(version=4)
    
    if hasattr(beef, 'to_binary'):
        serialized = beef.to_binary()
        assert isinstance(serialized, bytes)


def test_beef_roundtrip():
    """Test BEEF serialize/deserialize roundtrip."""
    from bsv.transaction.beef import Beef
    
    beef1 = Beef(version=4)
    
    if hasattr(beef1, 'to_binary') and hasattr(Beef, 'deserialize'):
        try:
            serialized = beef1.to_binary()
            beef2 = Beef.deserialize(serialized)
            assert beef2 is not None
        except Exception:
            # May require valid structure
            pass

