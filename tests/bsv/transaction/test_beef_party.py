"""
Tests for BeefParty implementation.

Translated from TS SDK BeefParty tests.
"""
import pytest
from bsv.transaction.beef_party import BeefParty
from bsv.transaction.beef import Beef, BEEF_V2


class TestBeefParty:
    """Test BeefParty matching TS SDK tests."""

    def test_should_create_with_parties(self):
        """Test creating BeefParty with initial parties."""
        parties = ['party1', 'party2', 'party3']
        beef_party = BeefParty(parties)
        
        assert beef_party.is_party('party1')
        assert beef_party.is_party('party2')
        assert beef_party.is_party('party3')

    def test_should_add_party(self):
        """Test adding a new party."""
        beef_party = BeefParty()
        beef_party.add_party('new_party')
        
        assert beef_party.is_party('new_party')

    def test_should_throw_error_if_party_already_exists(self):
        """Test that adding duplicate party raises error."""
        beef_party = BeefParty(['party1'])
        
        with pytest.raises(ValueError, match='already exists'):
            beef_party.add_party('party1')

    def test_should_get_known_txids_for_party(self):
        """Test getting known txids for a party."""
        beef_party = BeefParty(['party1'])
        txids = ['txid1', 'txid2', 'txid3']
        
        beef_party.add_known_txids_for_party('party1', txids)
        known = beef_party.get_known_txids_for_party('party1')
        
        assert len(known) == 3
        assert 'txid1' in known
        assert 'txid2' in known
        assert 'txid3' in known

    def test_should_throw_error_for_unknown_party(self):
        """Test that getting txids for unknown party raises error."""
        beef_party = BeefParty()
        
        with pytest.raises(ValueError, match='is unknown'):
            beef_party.get_known_txids_for_party('unknown_party')

    def test_should_get_trimmed_beef_for_party(self):
        """Test getting trimmed beef for a party."""
        beef_party = BeefParty(['party1'])
        txids = ['txid1', 'txid2']
        beef_party.add_known_txids_for_party('party1', txids)
        
        trimmed = beef_party.get_trimmed_beef_for_party('party1')
        assert isinstance(trimmed, Beef)

    def test_should_merge_beef_from_party(self):
        """Test merging beef from a party."""
        beef_party = BeefParty(['party1'])
        other_beef = Beef(BEEF_V2)
        
        # Merge should not raise error
        beef_party.merge_beef_from_party('party1', other_beef)
        
        # Party should be added if it doesn't exist
        beef_party2 = BeefParty()
        beef_party2.merge_beef_from_party('new_party', other_beef)
        assert beef_party2.is_party('new_party')

