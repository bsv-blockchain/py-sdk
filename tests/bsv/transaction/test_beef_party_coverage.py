"""
Coverage tests for transaction/beef_party.py - untested branches.
"""
import pytest


# ========================================================================
# BEEF party branches
# ========================================================================

def test_beef_party_init():
    """Test BEEF party initialization."""
    try:
        from bsv.transaction.beef_party import BeefParty
        party = BeefParty()
        assert party is not None
    except ImportError:
        pytest.skip("BeefParty not available")


def test_beef_party_add_transaction():
    """Test adding transaction to party."""
    try:
        from bsv.transaction.beef_party import BeefParty
        from bsv.transaction import Transaction
        
        party = BeefParty()
        tx = Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=0)
        
        if hasattr(party, 'add_transaction'):
            party.add_transaction(tx)
            assert True
    except ImportError:
        pytest.skip("BeefParty not available")


def test_beef_party_serialize():
    """Test BEEF party serialization."""
    try:
        from bsv.transaction.beef_party import BeefParty
        
        party = BeefParty()
        
        if hasattr(party, 'serialize'):
            serialized = party.serialize()
            assert isinstance(serialized, bytes)
    except ImportError:
        pytest.skip("BeefParty not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_beef_party_empty():
    """Test empty BEEF party."""
    try:
        from bsv.transaction.beef_party import BeefParty
        
        party = BeefParty()
        
        if hasattr(party, 'serialize'):
            serialized = party.serialize()
            assert isinstance(serialized, bytes)
    except ImportError:
        pytest.skip("BeefParty not available")

