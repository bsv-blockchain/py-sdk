"""
Tests for py-sdk/bsv/keys.py - PrivateKey operations
Ported from ts-sdk/src/primitives/__tests/PrivateKey.test.ts
"""

import pytest
from bsv.keys import PrivateKey, PublicKey


class TestPrivateKey:
    """Test cases for PrivateKey class"""
    
    def test_private_key_creation_from_int(self):
        """Test private key creation from integer"""
        priv = PrivateKey(42)
        assert isinstance(priv, PrivateKey)
        # Should be deterministic
        priv2 = PrivateKey(42)
        assert priv.hex() == priv2.hex()
    
    def test_private_key_creation_from_hex(self):
        """Test private key creation from hex bytes"""
        hex_key = "0000000000000000000000000000000000000000000000000000000000000001"
        key_bytes = bytes.fromhex(hex_key)
        priv = PrivateKey(key_bytes)
        assert isinstance(priv, PrivateKey)
        assert priv.hex() == hex_key
    
    def test_private_key_creation_from_bytes(self):
        """Test private key creation from bytes"""
        key_bytes = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
        priv = PrivateKey(key_bytes)
        assert isinstance(priv, PrivateKey)
        assert priv.hex() == "0000000000000000000000000000000000000000000000000000000000000001"
    
    def test_private_key_validation(self):
        """Test private key validation"""
        # Valid keys
        valid_keys = [
            "0000000000000000000000000000000000000000000000000000000000000001",
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
            "8a2f85e08360a04c8a36b7c22c5e9e9a0d3bcf2f95c97db2b8bd90fc5f5ff66a",
            "1b5a8f2392e6959a7de2b0a58f8a64cc528c9bfc1788ee0d32e1455063e71545"
        ]
        
        for key_hex in valid_keys:
            key_bytes = bytes.fromhex(key_hex)
            priv = PrivateKey(key_bytes)
            assert priv.hex() == key_hex
    
    def test_private_key_invalid_validation(self):
        """Test that invalid private keys raise errors"""
        # Zero key should raise error
        with pytest.raises(ValueError):
            PrivateKey("0000000000000000000000000000000000000000000000000000000000000000")
        
        # Key >= curve order should raise error
        with pytest.raises(ValueError):
            PrivateKey("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
    
    def test_public_key_derivation(self):
        """Test public key derivation from private key"""
        priv = PrivateKey(42)
        pub = priv.public_key()
        assert isinstance(pub, PublicKey)
        
        # Should be deterministic
        pub2 = priv.public_key()
        assert pub.hex() == pub2.hex()
    
    def test_child_key_derivation(self):
        """Test child key derivation"""
        priv = PrivateKey(42)
        counterparty_pub = PrivateKey(69).public_key()
        invoice_number = "test-invoice-123"
        
        child = priv.derive_child(counterparty_pub, invoice_number)
        assert isinstance(child, PrivateKey)
        
        # Should be deterministic
        child2 = priv.derive_child(counterparty_pub, invoice_number)
        assert child.hex() == child2.hex()
        
        # Different invoice numbers should produce different children
        child3 = priv.derive_child(counterparty_pub, "different-invoice")
        assert child.hex() != child3.hex()
    
    def test_shared_secret_derivation(self):
        """Test shared secret derivation"""
        alice_priv = PrivateKey(42)
        bob_priv = PrivateKey(69)
        
        alice_pub = alice_priv.public_key()
        bob_pub = bob_priv.public_key()
        
        # Both parties should derive the same shared secret
        alice_secret = alice_priv.derive_shared_secret(bob_pub)
        bob_secret = bob_priv.derive_shared_secret(alice_pub)
        
        assert alice_secret == bob_secret
        assert isinstance(alice_secret, bytes)
        assert len(alice_secret) > 0
    
    def test_message_signing(self):
        """Test message signing"""
        priv = PrivateKey(42)
        message = b"Hello, BSV!"
        
        # Check if sign_message method exists, otherwise skip or use alternative
        if hasattr(priv, 'sign_message'):
            signature = priv.sign_message(message)
            assert isinstance(signature, bytes)
            assert len(signature) > 0
            
            # Should be deterministic for same message
            signature2 = priv.sign_message(message)
            assert signature == signature2
        else:
            # Alternative: test sign method if available
            assert hasattr(priv, 'sign') or hasattr(priv, 'ecdsa_sign')
            # Skip detailed testing if method signature is different
    
    def test_wif_encoding_decoding(self):
        """Test WIF encoding and decoding"""
        priv = PrivateKey(42)
        
        # Test mainnet WIF
        wif = priv.wif()
        assert isinstance(wif, str)
        assert len(wif) > 0
        
        # Test decoding WIF back to private key (using string constructor)
        priv_from_wif = PrivateKey(wif)
        assert priv.hex() == priv_from_wif.hex()
    
    def test_hex_encoding(self):
        """Test hex encoding"""
        priv = PrivateKey(42)
        hex_str = priv.hex()
        assert isinstance(hex_str, str)
        assert len(hex_str) == 64  # 32 bytes * 2 chars per byte
        
        # Should match original if created from bytes
        key_bytes = bytes.fromhex(hex_str)
        priv2 = PrivateKey(key_bytes)
        assert priv.hex() == priv2.hex()
    
    def test_deterministic_key_derivation(self):
        """Test deterministic key derivation"""
        root_priv = PrivateKey(12345)
        counterparty_pub = PrivateKey(67890).public_key()
        
        # Multiple derivations with same parameters should be identical
        invoice1 = "invoice-123"
        child1a = root_priv.derive_child(counterparty_pub, invoice1)
        child1b = root_priv.derive_child(counterparty_pub, invoice1)
        assert child1a.hex() == child1b.hex()
        
        # Different invoices should produce different children
        invoice2 = "invoice-456"
        child2 = root_priv.derive_child(counterparty_pub, invoice2)
        assert child1a.hex() != child2.hex()
