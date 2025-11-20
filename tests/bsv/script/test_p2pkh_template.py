"""
Tests for P2PKH script template implementation.

Translated from TS SDK P2PKH template tests.
"""
import pytest
from bsv.script.type import P2PKH
from bsv.keys import PrivateKey, PublicKey
from bsv.utils import address_to_public_key_hash


class TestP2PKHTemplate:
    """Test P2PKH script template matching TS SDK tests."""

    def test_should_create_locking_script_from_address(self):
        """Test that lock creates P2PKH locking script from address."""
        private_key = PrivateKey()
        public_key = private_key.public_key()
        address = public_key.address()
        
        p2pkh = P2PKH()
        locking_script = p2pkh.lock(address)
        
        assert locking_script is not None
        assert len(locking_script.to_bytes()) > 0

    def test_should_create_locking_script_from_pubkey_hash(self):
        """Test that lock creates P2PKH locking script from pubkey hash."""
        private_key = PrivateKey()
        public_key = private_key.public_key()
        pubkey_hash = public_key.hash160()
        
        p2pkh = P2PKH()
        locking_script = p2pkh.lock(pubkey_hash)
        
        assert locking_script is not None
        assert len(locking_script.to_bytes()) > 0

    def test_should_throw_error_for_invalid_address(self):
        """Test that lock throws error for invalid address."""
        p2pkh = P2PKH()
        
        with pytest.raises((ValueError, TypeError)):
            p2pkh.lock("invalid_address")

    def test_should_create_unlocking_script_template(self):
        """Test that unlock creates unlocking script template."""
        private_key = PrivateKey()
        public_key = private_key.public_key()
        address = public_key.address()
        
        p2pkh = P2PKH()
        _ = p2pkh.lock(address)
        unlocker = p2pkh.unlock(private_key)
        
        assert unlocker is not None
        assert hasattr(unlocker, 'sign')
        assert hasattr(unlocker, 'estimated_unlocking_byte_length')

    def test_should_estimate_unlocking_script_length(self):
        """Test that unlocker estimates unlocking script length."""
        private_key = PrivateKey()
        public_key = private_key.public_key()
        _ = public_key.address()
        
        p2pkh = P2PKH()
        unlocker = p2pkh.unlock(private_key)
        
        length = unlocker.estimated_unlocking_byte_length()
        assert length > 0
        # Compressed keys: ~107 bytes, uncompressed: ~139 bytes
        assert length in (107, 139)

