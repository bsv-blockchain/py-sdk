"""
Tests for RPuzzle script template implementation.

Translated from TS SDK RPuzzle template tests.
"""
import pytest
from bsv.script.type import RPuzzle
from bsv.keys import PrivateKey
from bsv.hash import sha256, sha1, hash160, hash256


class TestRPuzzleTemplate:
    """Test RPuzzle script template matching TS SDK tests."""

    def test_should_create_raw_rpuzzle_locking_script(self):
        """Test that lock creates raw RPuzzle locking script."""
        r_value = b'\x01' * 32  # 32-byte R value
        
        rpuzzle = RPuzzle('raw')
        locking_script = rpuzzle.lock(r_value)
        
        assert locking_script is not None
        assert len(locking_script.to_bytes()) > 0

    def test_should_create_sha256_rpuzzle_locking_script(self):
        """Test that lock creates SHA256 RPuzzle locking script."""
        r_value = b'\x01' * 32
        r_hash = sha256(r_value)
        
        rpuzzle = RPuzzle('SHA256')
        locking_script = rpuzzle.lock(r_hash)
        
        assert locking_script is not None
        assert len(locking_script.to_bytes()) > 0

    def test_should_create_sha1_rpuzzle_locking_script(self):
        """Test that lock creates SHA1 RPuzzle locking script."""
        r_value = b'\x01' * 32
        r_hash = sha1(r_value)
        
        rpuzzle = RPuzzle('SHA1')
        locking_script = rpuzzle.lock(r_hash)
        
        assert locking_script is not None
        assert len(locking_script.to_bytes()) > 0

    def test_should_create_hash160_rpuzzle_locking_script(self):
        """Test that lock creates HASH160 RPuzzle locking script."""
        r_value = b'\x01' * 32
        r_hash = hash160(r_value)
        
        rpuzzle = RPuzzle('HASH160')
        locking_script = rpuzzle.lock(r_hash)
        
        assert locking_script is not None
        assert len(locking_script.to_bytes()) > 0

    def test_should_create_unlocking_script_template(self):
        """Test that unlock creates unlocking script template."""
        from bsv.curve import curve
        k_value = 12345  # K value for R-puzzle
        private_key = PrivateKey()
        r_value = b'\x01' * 32
        
        rpuzzle = RPuzzle('raw')
        _ = rpuzzle.lock(r_value)
        unlocker = rpuzzle.unlock(k_value, private_key)
        
        assert unlocker is not None
        assert hasattr(unlocker, 'sign')
        assert hasattr(unlocker, 'estimated_unlocking_byte_length')

    def test_should_estimate_unlocking_script_length(self):
        """Test that unlocker estimates unlocking script length."""
        from bsv.curve import curve
        k_value = 12345
        private_key = PrivateKey()
        
        rpuzzle = RPuzzle('raw')
        unlocker = rpuzzle.unlock(k_value, private_key)
        
        length = unlocker.estimated_unlocking_byte_length()
        assert length > 0
        # RPuzzle unlocking script should be ~108 bytes
        assert length >= 100

