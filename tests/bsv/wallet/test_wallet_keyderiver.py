"""
Tests for py-sdk/bsv/wallet/key_deriver.py
Ported from ts-sdk/src/wallet/__tests/KeyDeriver.test.ts
"""

import pytest
from bsv.keys import PrivateKey, PublicKey
from bsv.wallet.key_deriver import KeyDeriver, Protocol, Counterparty, CounterpartyType


class TestKeyDeriver:
    """Test cases for KeyDeriver class"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.root_private_key = PrivateKey(42)
        self.root_public_key = self.root_private_key.public_key()
        self.counterparty_private_key = PrivateKey(69)
        self.counterparty_public_key = self.counterparty_private_key.public_key()
        self.anyone_public_key = PrivateKey(1).public_key()
        
        self.protocol = Protocol(0, 'testprotocol')
        self.key_id = '12345'
        
        self.key_deriver = KeyDeriver(self.root_private_key)
    
    def test_compute_invoice_number(self):
        """Test invoice number computation"""
        invoice_number = self.key_deriver.compute_invoice_number(self.protocol, self.key_id)
        assert invoice_number == '0-testprotocol-12345'
    
    def test_normalize_counterparty_throws_for_invalid(self):
        """Test that normalize_counterparty throws for invalid input"""
        # Test with invalid string
        with pytest.raises(ValueError, match=r"non-hexadecimal number found in fromhex\(\) arg at position 0"):
            self.key_deriver.normalize_counterparty('invalid_type')
        
        # Test with Counterparty with invalid type
        with pytest.raises(ValueError):
            invalid_counterparty = Counterparty('invalid', None)
            self.key_deriver.normalize_counterparty(invalid_counterparty)
    
    def test_normalize_counterparty_self(self):
        """Test normalize_counterparty for self"""
        # Test with Counterparty object
        counterparty = Counterparty(CounterpartyType.SELF)
        normalized = self.key_deriver.normalize_counterparty(counterparty)
        assert normalized.hex() == self.root_public_key.hex()
        
        # Test with string 'self' - this should be handled by string parsing
        # normalized_str = self.key_deriver.normalize_counterparty('self')
        # assert normalized_str.hex() == self.root_public_key.hex()
    
    def test_normalize_counterparty_anyone(self):
        """Test normalize_counterparty for anyone"""
        counterparty = Counterparty(CounterpartyType.ANYONE)
        normalized = self.key_deriver.normalize_counterparty(counterparty)
        # Should return fixed public key matching TypeScript's PrivateKey(1).toPublicKey()
        anyone_private = PrivateKey(1)
        expected = anyone_private.public_key()
        assert normalized.hex() == expected.hex()
    
    def test_normalize_counterparty_other(self):
        """Test normalize_counterparty for other party"""
        counterparty = Counterparty(CounterpartyType.OTHER, self.counterparty_public_key)
        normalized = self.key_deriver.normalize_counterparty(counterparty)
        assert normalized.hex() == self.counterparty_public_key.hex()
    
    def test_normalize_counterparty_public_key(self):
        """Test normalize_counterparty with PublicKey object"""
        normalized = self.key_deriver.normalize_counterparty(self.counterparty_public_key)
        assert normalized.hex() == self.counterparty_public_key.hex()
    
    def test_normalize_counterparty_hex_string(self):
        """Test normalize_counterparty with hex string"""
        hex_string = self.counterparty_public_key.hex()
        normalized = self.key_deriver.normalize_counterparty(hex_string)
        assert normalized.hex() == self.counterparty_public_key.hex()
    
    def test_derive_private_key_for_self(self):
        """Test private key derivation for self"""
        counterparty = Counterparty(CounterpartyType.SELF)
        derived = self.key_deriver.derive_private_key(self.protocol, self.key_id, counterparty)
        assert isinstance(derived, PrivateKey)
        # Should be deterministic
        derived2 = self.key_deriver.derive_private_key(self.protocol, self.key_id, counterparty)
        assert derived.hex() == derived2.hex()
    
    def test_derive_private_key_for_other(self):
        """Test private key derivation for other party"""
        counterparty = Counterparty(CounterpartyType.OTHER, self.counterparty_public_key)
        derived = self.key_deriver.derive_private_key(self.protocol, self.key_id, counterparty)
        assert isinstance(derived, PrivateKey)
        
        # Should be different from self derivation
        self_counterparty = Counterparty(CounterpartyType.SELF)
        self_derived = self.key_deriver.derive_private_key(self.protocol, self.key_id, self_counterparty)
        assert derived.hex() != self_derived.hex()
    
    def test_derive_public_key_for_self(self):
        """Test public key derivation for self"""
        counterparty = Counterparty(CounterpartyType.SELF)
        derived = self.key_deriver.derive_public_key(self.protocol, self.key_id, counterparty, for_self=True)
        assert isinstance(derived, PublicKey)
        
        # Should match the public key of the derived private key
        derived_private = self.key_deriver.derive_private_key(self.protocol, self.key_id, counterparty)
        assert derived.hex() == derived_private.public_key().hex()
    
    def test_derive_public_key_for_other(self):
        """Test public key derivation for other party"""
        counterparty = Counterparty(CounterpartyType.OTHER, self.counterparty_public_key)
        derived = self.key_deriver.derive_public_key(self.protocol, self.key_id, counterparty, for_self=False)
        assert isinstance(derived, PublicKey)
    
    def test_derive_symmetric_key(self):
        """Test symmetric key derivation"""
        counterparty = Counterparty(CounterpartyType.OTHER, self.counterparty_public_key)
        symmetric_key = self.key_deriver.derive_symmetric_key(self.protocol, self.key_id, counterparty)
        assert isinstance(symmetric_key, bytes)
        assert len(symmetric_key) > 0
        
        # Should be deterministic
        symmetric_key2 = self.key_deriver.derive_symmetric_key(self.protocol, self.key_id, counterparty)
        assert symmetric_key == symmetric_key2
    
    def test_identity_key(self):
        """Test identity key retrieval"""
        identity = self.key_deriver.identity_key()
        assert identity.hex() == self.root_public_key.hex()
    
    def test_protocol_validation(self):
        """Test protocol validation"""
        # Valid protocols (avoid ending with " protocol")
        valid_protocols = [
            Protocol(0, 'valid test'),
            Protocol(1, 'another valid test'),
            Protocol(2, 'yet another valid test'),
            Protocol(1, 'a' * 400),  # Max length protocol name
        ]
        
        for protocol in valid_protocols:
            # Should not raise
            self.key_deriver.compute_invoice_number(protocol, self.key_id)
        
        # Invalid security levels
        with pytest.raises(ValueError, match='protocol security level must be 0, 1, or 2'):
            invalid_protocol = Protocol(-1, 'valid protocol')
            self.key_deriver.compute_invoice_number(invalid_protocol, self.key_id)
        
        with pytest.raises(ValueError, match='protocol security level must be 0, 1, or 2'):
            invalid_protocol = Protocol(3, 'valid test')
            self.key_deriver.compute_invoice_number(invalid_protocol, self.key_id)
    
    def test_key_id_validation(self):
        """Test key ID validation"""
        # Valid key IDs
        valid_key_ids = ['1', 'a' * 800]  # Min and max length
        
        for key_id in valid_key_ids:
            # Should not raise
            self.key_deriver.compute_invoice_number(self.protocol, key_id)
        
        # Invalid key IDs
        with pytest.raises(ValueError, match='key IDs must be 1-800 characters'):
            self.key_deriver.compute_invoice_number(self.protocol, '')  # Too short
        
        with pytest.raises(ValueError, match='key IDs must be 1-800 characters'):
            self.key_deriver.compute_invoice_number(self.protocol, 'a' * 801)  # Too long
    
    def test_protocol_name_validation(self):
        """Test protocol name validation"""
        # Should not error
        valid_protocol = Protocol(0, 'abc')  # 3 chars
        self.key_deriver.compute_invoice_number(valid_protocol, self.key_id)
        # Too short
        with pytest.raises(ValueError, match='protocol names must be 3-400 characters'):
            invalid_protocol = Protocol(0, 'ab')  # 2 chars
            self.key_deriver.compute_invoice_number(invalid_protocol, self.key_id)
        
        # Too long
        with pytest.raises(ValueError, match='protocol names must be 3-400 characters'):
            invalid_protocol = Protocol(0, 'a' * 401)
            self.key_deriver.compute_invoice_number(invalid_protocol, self.key_id)
        
        # Multiple consecutive spaces
        with pytest.raises(ValueError, match='protocol names cannot contain multiple consecutive spaces'):
            invalid_protocol = Protocol(0, 'test  protocol')
            self.key_deriver.compute_invoice_number(invalid_protocol, self.key_id)
        
        # Invalid characters
        with pytest.raises(ValueError, match='protocol names can only contain letters, numbers and spaces'):
            invalid_protocol = Protocol(0, 'test-protocol')
            self.key_deriver.compute_invoice_number(invalid_protocol, self.key_id)
        
        # Ending with " protocol"
        with pytest.raises(ValueError, match='no need to end your protocol name with " protocol"'):
            invalid_protocol = Protocol(0, 'test protocol')
            self.key_deriver.compute_invoice_number(invalid_protocol, self.key_id)
    
    def test_deterministic_derivation(self):
        """Test that key derivation is deterministic"""
        counterparty = Counterparty(CounterpartyType.OTHER, self.counterparty_public_key)
        
        # Multiple derivations should produce the same result
        private1 = self.key_deriver.derive_private_key(self.protocol, self.key_id, counterparty)
        private2 = self.key_deriver.derive_private_key(self.protocol, self.key_id, counterparty)
        assert private1.hex() == private2.hex()
        
        public1 = self.key_deriver.derive_public_key(self.protocol, self.key_id, counterparty, for_self=True)
        public2 = self.key_deriver.derive_public_key(self.protocol, self.key_id, counterparty, for_self=True)
        assert public1.hex() == public2.hex()
        
        symmetric1 = self.key_deriver.derive_symmetric_key(self.protocol, self.key_id, counterparty)
        symmetric2 = self.key_deriver.derive_symmetric_key(self.protocol, self.key_id, counterparty)
        assert symmetric1 == symmetric2
    
    def test_different_parameters_produce_different_keys(self):
        """Test that different parameters produce different keys"""
        counterparty = Counterparty(CounterpartyType.OTHER, self.counterparty_public_key)
        
        # Different protocols
        protocol1 = Protocol(0, 'protocol one')
        protocol2 = Protocol(0, 'protocol two')
        
        key1 = self.key_deriver.derive_private_key(protocol1, self.key_id, counterparty)
        key2 = self.key_deriver.derive_private_key(protocol2, self.key_id, counterparty)
        assert key1.hex() != key2.hex()
        
        # Different key IDs
        key3 = self.key_deriver.derive_private_key(self.protocol, 'keyid1', counterparty)
        key4 = self.key_deriver.derive_private_key(self.protocol, 'keyid2', counterparty)
        assert key3.hex() != key4.hex()
        
        # Different counterparties
        counterparty2 = Counterparty(CounterpartyType.OTHER, PrivateKey(100).public_key())
        key5 = self.key_deriver.derive_private_key(self.protocol, self.key_id, counterparty)
        key6 = self.key_deriver.derive_private_key(self.protocol, self.key_id, counterparty2)
        assert key5.hex() != key6.hex()
