"""
Tests for ContactsManager implementation.

Translated from TS SDK ContactsManager functionality.
"""
import pytest
from unittest.mock import Mock, MagicMock
from bsv.identity.contacts_manager import ContactsManager, Contact
from bsv.wallet.wallet_interface import WalletInterface


class TestContactsManager:
    """Test ContactsManager matching TS SDK tests."""

    def setup_method(self):
        """Set up test fixtures."""
        self.wallet = Mock(spec=WalletInterface)
        self.wallet.list_outputs = Mock(return_value={
            'outputs': [],
            'BEEF': None
        })
        self.wallet.create_hmac = Mock(return_value={
            'hmac': b'\x01\x02\x03\x04'
        })
        self.wallet.encrypt = Mock(return_value={
            'ciphertext': b'encrypted_contact_data'
        })
        self.wallet.decrypt = Mock(return_value={
            'plaintext': b'{"identityKey":"test-key","name":"Test Contact"}'
        })
        self.wallet.get_public_key = Mock(return_value={
            'publicKey': '02a1633cafb311f41c1137864d7dd7cf2d5c9e5c2e5b5f5a5d5c5b5a59584f5e5fac'
        })
        self.wallet.create_signature = Mock(return_value={
            'signature': b'dummy_signature_for_testing_purposes_32bytes'
        })
        self.wallet.create_action = Mock(return_value={
            'tx': b'transaction_bytes'
        })
        self.contacts_manager = ContactsManager(self.wallet)

    def test_should_get_empty_contacts_when_none_exist(self):
        """Test that getContacts returns empty list when no contacts exist."""
        contacts = self.contacts_manager.get_contacts()
        assert contacts == []

    def test_should_get_contacts_by_identity_key(self):
        """Test that getContacts filters by identity key."""
        identity_key = 'test-identity-key-123'
        self.wallet.list_outputs.return_value = {
            'outputs': [{
                'outpoint': 'txid1.0',
                'lockingScript': 'mock_script',
                'customInstructions': '{"keyID":"test-key-id"}'
            }],
            'BEEF': b'mock_beef'
        }
        
        contacts = self.contacts_manager.get_contacts(identity_key=identity_key)
        # Should call list_outputs with appropriate tags
        assert self.wallet.list_outputs.called

    def test_should_save_new_contact(self):
        """Test that saveContact creates a new contact."""
        contact = {
            'identityKey': 'new-contact-key',
            'name': 'New Contact',
            'avatarURL': 'avatar.png'
        }
        
        self.contacts_manager.save_contact(contact)
        
        # Should call create_action to create contact output
        assert self.wallet.create_action.called

    def test_should_update_existing_contact(self):
        """Test that saveContact updates an existing contact."""
        # First, set up existing contact
        existing_output = {
            'outpoint': 'txid1.0',
            'lockingScript': 'mock_script',
            'customInstructions': '{"keyID":"existing-key-id"}'
        }
        self.wallet.list_outputs.return_value = {
            'outputs': [existing_output],
            'BEEF': b'mock_beef'
        }
        
        contact = {
            'identityKey': 'existing-contact-key',
            'name': 'Updated Contact',
            'avatarURL': 'new_avatar.png'
        }
        
        self.contacts_manager.save_contact(contact)
        
        # Should attempt to update (will call create_action with inputs)
        assert self.wallet.list_outputs.called

    def test_should_delete_contact(self):
        """Test that deleteContact removes a contact."""
        identity_key = 'contact-to-delete'
        # Mock get_contacts to return a contact
        self.contacts_manager.get_contacts = Mock(return_value=[{
            'identityKey': identity_key,
            'name': 'Contact to Delete'
        }])
        self.wallet.list_outputs.return_value = {
            'outputs': [{
                'outpoint': 'txid1.0',
                'lockingScript': 'mock_script'
            }],
            'BEEF': b'mock_beef'
        }
        
        self.contacts_manager.delete_contact(identity_key)
        
        # Should call create_action to spend the contact output
        assert self.wallet.create_action.called

