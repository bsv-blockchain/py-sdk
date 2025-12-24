"""
Coverage tests for transaction/beef_party.py - untested branches.
"""
import pytest


# ========================================================================
# BEEF party branches
# ========================================================================

def test_beef_party_init():
    """Test BEEF party initialization."""
    from bsv.transaction.beef_party import BeefParty
    party = BeefParty()
    assert party  # Verify object creation succeeds


def test_beef_party_add_transaction():
    """Test adding transaction to party."""
    from bsv.transaction.beef_party import BeefParty
    from bsv.transaction import Transaction
    
    party = BeefParty()
    tx = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=0)
    
    # BeefParty inherits from Beef, check available methods
    assert hasattr(party, 'txs')
    assert hasattr(party, 'to_binary')
    assert hasattr(party, 'merge_transaction')
    
    # Test actually adding a transaction
    beef_tx = party.merge_transaction(tx)
    assert beef_tx is not None


def test_beef_party_serialize():
    """Test BEEF party serialization."""
    from bsv.transaction.beef_party import BeefParty
    
    party = BeefParty()
    
    if hasattr(party, 'to_binary'):
        serialized = party.to_binary()
        assert isinstance(serialized, bytes)


# ========================================================================
# Edge cases
# ========================================================================

def test_beef_party_empty():
    """Test empty BEEF party."""
    from bsv.transaction.beef_party import BeefParty
    
    party = BeefParty()
    
    if hasattr(party, 'to_binary'):
        serialized = party.to_binary()
        assert isinstance(serialized, bytes)

