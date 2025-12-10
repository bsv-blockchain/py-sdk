"""
Comprehensive tests for bsv/identity/client.py

Tests the IdentityClient class including all methods and edge cases.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from bsv.identity.client import IdentityClient
from bsv.identity.types import DisplayableIdentity, IdentityClientOptions


class TestIdentityClientInit:
    """Test IdentityClient initialization."""
    
    def test_init_with_wallet(self):
        """Test initialization with provided wallet."""
        wallet = Mock()
        client = IdentityClient(wallet=wallet)
        assert client.wallet == wallet
        assert client.options is not None
        assert client.originator == ""
        assert client.contacts_manager is not None
    
    def test_init_without_wallet(self):
        """Test initialization without wallet creates default wallet."""
        with patch('bsv.wallet.wallet_impl.ProtoWallet') as mock_wallet_impl, \
             patch('bsv.keys.PrivateKey') as mock_private_key:
            mock_key = Mock()
            mock_private_key.return_value = mock_key
            mock_wallet = Mock()
            mock_wallet_impl.return_value = mock_wallet
            
            client = IdentityClient()
            
            mock_private_key.assert_called_once()
            mock_wallet_impl.assert_called_once_with(mock_key)
            assert client.wallet == mock_wallet
    
    def test_init_with_options(self):
        """Test initialization with custom options."""
        wallet = Mock()
        options = IdentityClientOptions(token_amount=100)
        client = IdentityClient(wallet=wallet, options=options)
        assert client.options == options
        assert client.options.token_amount == 100
    
    def test_init_with_originator(self):
        """Test initialization with originator."""
        wallet = Mock()
        originator = "test.example.com"
        client = IdentityClient(wallet=wallet, originator=originator)
        assert client.originator == originator


class TestRevealFieldsFromMasterCertificate:
    """Test _reveal_fields_from_master_certificate method."""
    
    def test_reveal_fields_with_valid_certificate(self):
        """Test revealing fields from master certificate."""
        wallet = Mock()
        client = IdentityClient(wallet=wallet)
        
        certificate = Mock()
        certificate.fields = {"name": "encrypted_name", "email": "encrypted_email"}
        certificate.master_keyring = "keyring_data"
        certificate.certifier = "certifier_data"
        
        with patch('bsv.auth.master_certificate.MasterCertificate') as mock_mc:
            mock_mc.decrypt_fields.return_value = {
                "name": "John Doe",
                "email": "john@example.com",
                "phone": "123-456-7890"
            }
            
            result = client._reveal_fields_from_master_certificate(
                certificate, ["name", "email"]
            )
            
            assert result == {"name": "John Doe", "email": "john@example.com"}
            mock_mc.decrypt_fields.assert_called_once()
    
    def test_reveal_fields_no_master_keyring(self):
        """Test revealing fields when master_keyring is None."""
        wallet = Mock()
        client = IdentityClient(wallet=wallet)
        
        certificate = Mock()
        certificate.fields = {"name": "encrypted_name"}
        certificate.master_keyring = None
        certificate.certifier = "certifier_data"
        
        result = client._reveal_fields_from_master_certificate(certificate, ["name"])
        assert result == {}
    
    def test_reveal_fields_no_cert_fields(self):
        """Test revealing fields when certificate has no fields."""
        wallet = Mock()
        client = IdentityClient(wallet=wallet)
        
        certificate = Mock()
        certificate.fields = None
        certificate.master_keyring = "keyring_data"
        certificate.certifier = "certifier_data"
        
        result = client._reveal_fields_from_master_certificate(certificate, ["name"])
        assert result == {}
    
    def test_reveal_fields_decrypt_exception(self):
        """Test revealing fields when decryption raises exception."""
        wallet = Mock()
        client = IdentityClient(wallet=wallet)
        
        certificate = Mock()
        certificate.fields = {"name": "encrypted_name"}
        certificate.master_keyring = "keyring_data"
        certificate.certifier = "certifier_data"
        
        with patch('bsv.auth.master_certificate.MasterCertificate') as mock_mc:
            mock_mc.decrypt_fields.side_effect = Exception("Decryption failed")
            
            result = client._reveal_fields_from_master_certificate(certificate, ["name"])
            assert result == {}


class TestRevealFieldsFromDict:
    """Test _reveal_fields_from_dict method."""
    
    def test_reveal_fields_from_dict(self):
        """Test revealing fields from dict certificate."""
        wallet = Mock()
        client = IdentityClient(wallet=wallet)
        
        certificate = {
            "decryptedFields": {
                "name": "Jane Doe",
                "email": "jane@example.com",
                "age": "30"
            }
        }
        
        result = client._reveal_fields_from_dict(certificate, ["name", "email"])
        assert result == {"name": "Jane Doe", "email": "jane@example.com"}
    
    def test_reveal_fields_from_dict_no_decrypted_fields(self):
        """Test revealing fields when decryptedFields is None."""
        wallet = Mock()
        client = IdentityClient(wallet=wallet)
        
        certificate = {"decryptedFields": None}
        result = client._reveal_fields_from_dict(certificate, ["name"])
        assert result == {}
    
    def test_reveal_fields_from_dict_missing_field(self):
        """Test revealing fields that don't exist in dict."""
        wallet = Mock()
        client = IdentityClient(wallet=wallet)
        
        certificate = {"decryptedFields": {"name": "Test"}}
        result = client._reveal_fields_from_dict(certificate, ["name", "missing"])
        assert result == {"name": "Test"}


class TestBuildOutputsForReveal:
    """Test _build_outputs_for_reveal method."""
    
    def test_build_outputs_simple(self):
        """Test building outputs with simple revealed fields."""
        wallet = Mock()
        options = IdentityClientOptions(token_amount=10)
        client = IdentityClient(wallet=wallet, options=options)
        
        revealed = {"name": "John", "email": "john@test.com"}
        
        with patch('bsv.transaction.pushdrop.build_pushdrop_locking_script') as mock_build:
            mock_build.return_value = b"locking_script"
            
            labels, description, outputs = client._build_outputs_for_reveal(revealed)
            
            assert labels == ["identity", "reveal"]
            assert description == "identity attribute revelation"
            assert len(outputs) == 1
            assert outputs[0]["satoshis"] == 10
            assert outputs[0]["lockingScript"] == b"locking_script"
            assert outputs[0]["tags"] == ["identity", "reveal"]
            
            # Check that pushdrop was called with correct items
            call_args = mock_build.call_args[0][0]
            assert call_args[0] == "identity.reveal"
            assert "name" in call_args
            assert "John" in call_args
    
    def test_build_outputs_empty_revealed(self):
        """Test building outputs with empty revealed dict."""
        wallet = Mock()
        client = IdentityClient(wallet=wallet)
        
        revealed = {}
        
        with patch('bsv.transaction.pushdrop.build_pushdrop_locking_script') as mock_build:
            mock_build.return_value = b"script"
            
            labels, _, outputs = client._build_outputs_for_reveal(revealed)
            
            assert labels == ["identity", "reveal"]
            assert len(outputs) == 1


class TestPubliclyRevealAttributes:
    """Test publicly_reveal_attributes method."""
    
    def test_reveal_attributes_with_master_certificate(self):
        """Test revealing attributes from MasterCertificate."""
        wallet = Mock()
        wallet.create_action.return_value = {"actionId": "test"}
        wallet.sign_action.return_value = {"signed": True}
        wallet.internalize_action.return_value = {"txid": "0x123"}
        
        client = IdentityClient(wallet=wallet)
        ctx = Mock()
        
        with patch('bsv.auth.master_certificate.MasterCertificate') as mock_mc_class, \
             patch('bsv.transaction.pushdrop.build_pushdrop_locking_script') as mock_build:
            mock_build.return_value = b"script"
            mock_mc_instance = Mock()
            mock_mc_class.return_value = mock_mc_instance
            mock_mc_class.decrypt_fields.return_value = {"name": "Test User"}
            
            # Make isinstance return True for MasterCertificate
            certificate = mock_mc_instance
            
            result = client.publicly_reveal_attributes(ctx, certificate, ["name"])
            
            assert "revealed" in result
            assert "txid" in result
            wallet.create_action.assert_called_once()
            wallet.sign_action.assert_called_once()
            wallet.internalize_action.assert_called_once()
    
    def test_reveal_attributes_with_dict_certificate(self):
        """Test revealing attributes from dict certificate."""
        wallet = Mock()
        wallet.create_action.return_value = {}
        wallet.sign_action.return_value = {}
        wallet.internalize_action.return_value = {"txid": "0x456"}
        
        client = IdentityClient(wallet=wallet)
        ctx = Mock()
        
        certificate = {
            "decryptedFields": {
                "name": "Jane Doe",
                "email": "jane@test.com"
            }
        }
        
        with patch('bsv.transaction.pushdrop.build_pushdrop_locking_script') as mock_build:
            mock_build.return_value = b"script"
            
            result = client.publicly_reveal_attributes(ctx, certificate, ["name", "email"])
            
            assert result["revealed"] == {"name": "Jane Doe", "email": "jane@test.com"}
            assert result["txid"] == "0x456"
    
    def test_reveal_attributes_exception_handling(self):
        """Test revealing attributes handles exceptions gracefully."""
        wallet = Mock()
        wallet.create_action.return_value = {}
        wallet.sign_action.return_value = {}
        wallet.internalize_action.return_value = {}
        
        client = IdentityClient(wallet=wallet)
        ctx = Mock()
        
        certificate = "invalid"
        
        with patch('bsv.transaction.pushdrop.build_pushdrop_locking_script') as mock_build:
            mock_build.return_value = b"script"
            
            result = client.publicly_reveal_attributes(ctx, certificate, ["name"])
            
            assert result["revealed"] == {}


class TestPubliclyRevealAttributesSimple:
    """Test publicly_reveal_attributes_simple method."""
    
    def test_reveal_attributes_simple(self):
        """Test simple reveal returns zero txid."""
        wallet = Mock()
        wallet.create_action.return_value = {}
        wallet.sign_action.return_value = {}
        wallet.internalize_action.return_value = {"txid": "real_txid"}
        
        client = IdentityClient(wallet=wallet)
        ctx = Mock()
        certificate = {"decryptedFields": {"name": "Test"}}
        
        with patch('bsv.transaction.pushdrop.build_pushdrop_locking_script') as mock_build:
            mock_build.return_value = b"script"
            
            result = client.publicly_reveal_attributes_simple(ctx, certificate, ["name"])
            
            assert result == "00" * 32


class TestResolveByIdentityKey:
    """Test resolve_by_identity_key method."""
    
    def test_resolve_with_contacts(self):
        """Test resolve returns contacts when override_with_contacts is True."""
        wallet = Mock()
        client = IdentityClient(wallet=wallet)
        
        expected_contacts = [DisplayableIdentity(name="Contact", identity_key="key1")]
        client.contacts_manager.get_contacts = Mock(return_value=expected_contacts)
        
        ctx = Mock()
        args = {"identityKey": "key1"}
        
        result = client.resolve_by_identity_key(ctx, args, override_with_contacts=True)
        
        assert result == expected_contacts
        client.contacts_manager.get_contacts.assert_called_once_with(identity_key="key1")
    
    def test_resolve_bytes_identity_key(self):
        """Test resolve converts bytes identity key to hex."""
        wallet = Mock()
        wallet.discover_by_identity_key = Mock(return_value={"certificates": []})
        
        client = IdentityClient(wallet=wallet)
        ctx = Mock()
        args = {"identityKey": b"\x01\x02\x03"}
        
        result = client.resolve_by_identity_key(ctx, args, override_with_contacts=False)
        
        assert isinstance(result, list)
    
    def test_resolve_no_wallet(self):
        """Test resolve returns empty list when wallet is None."""
        client = IdentityClient(wallet=None)
        ctx = Mock()
        args = {"identityKey": "key1"}
        
        result = client.resolve_by_identity_key(ctx, args, override_with_contacts=False)
        
        assert result == []
    
    def test_resolve_with_discover_method(self):
        """Test resolve calls wallet discover_by_identity_key."""
        wallet = Mock()
        wallet.discover_by_identity_key = Mock(return_value={
            "certificates": [
                {
                    "decryptedFields": {
                        "name": "Discovered User",
                        "identityKey": "key123"
                    },
                    "certifierInfo": {"name": "Certifier"}
                }
            ]
        })
        
        client = IdentityClient(wallet=wallet)
        ctx = Mock()
        args = {"identityKey": "key123"}
        
        result = client.resolve_by_identity_key(ctx, args, override_with_contacts=False)
        
        assert len(result) == 1
        assert result[0].name == "Discovered User"
        wallet.discover_by_identity_key.assert_called_once()
    
    def test_resolve_without_discover_method(self):
        """Test resolve returns empty when wallet has no discover method."""
        wallet = Mock(spec=[])  # No methods
        client = IdentityClient(wallet=wallet)
        ctx = Mock()
        args = {"identityKey": "key1"}
        
        result = client.resolve_by_identity_key(ctx, args, override_with_contacts=False)
        
        assert result == []
    
    def test_resolve_with_locking_script(self):
        """Test resolve parses locking script when provided."""
        wallet = Mock()
        wallet.discover_by_identity_key = Mock(return_value={
            "certificates": [
                {"lockingScript": b"test_locking_script"}
            ]
        })
        
        client = IdentityClient(wallet=wallet)
        ctx = Mock()
        args = {"identityKey": "key1"}
        
        with patch('bsv.transaction.pushdrop.parse_pushdrop_locking_script') as mock_parse, \
             patch('bsv.transaction.pushdrop.parse_identity_reveal') as mock_reveal:
            mock_parse.return_value = "parsed_script"
            mock_reveal.return_value = [("name", "Test"), ("identityKey", "key1")]
            
            result = client.resolve_by_identity_key(ctx, args, override_with_contacts=False)
            
            assert len(result) == 1
            mock_parse.assert_called_once_with(b"test_locking_script")
    
    def test_resolve_exception_handling(self):
        """Test resolve handles exceptions and returns empty list."""
        wallet = Mock()
        wallet.discover_by_identity_key = Mock(side_effect=Exception("Error"))
        
        client = IdentityClient(wallet=wallet)
        ctx = Mock()
        args = {"identityKey": "key1"}
        
        result = client.resolve_by_identity_key(ctx, args, override_with_contacts=False)
        
        assert result == []


class TestResolveByAttributes:
    """Test resolve_by_attributes method."""
    
    def test_resolve_with_contacts_by_identity_key(self):
        """Test resolve checks contacts when identityKey in attributes."""
        wallet = Mock()
        client = IdentityClient(wallet=wallet)
        
        expected_contacts = [DisplayableIdentity(name="Contact", identity_key="key1")]
        client.contacts_manager.get_contacts = Mock(return_value=expected_contacts)
        
        ctx = Mock()
        args = {"attributes": {"identityKey": "key1", "name": "Test"}}
        
        result = client.resolve_by_attributes(ctx, args, override_with_contacts=True)
        
        assert result == expected_contacts
    
    def test_resolve_no_wallet(self):
        """Test resolve returns empty list when wallet is None."""
        client = IdentityClient(wallet=None)
        ctx = Mock()
        args = {"attributes": {}}
        
        result = client.resolve_by_attributes(ctx, args, override_with_contacts=False)
        
        assert result == []
    
    def test_resolve_with_discover_method(self):
        """Test resolve calls wallet discover_by_attributes."""
        wallet = Mock()
        wallet.discover_by_attributes = Mock(return_value={
            "certificates": [
                {
                    "decryptedFields": {"name": "Found User", "email": "test@test.com"},
                    "certifierInfo": {}
                }
            ]
        })
        
        client = IdentityClient(wallet=wallet)
        ctx = Mock()
        args = {"attributes": {"name": "Found User"}}
        
        result = client.resolve_by_attributes(ctx, args, override_with_contacts=False)
        
        assert len(result) == 1
        wallet.discover_by_attributes.assert_called_once()
    
    def test_resolve_without_discover_method(self):
        """Test resolve returns empty when wallet has no discover method."""
        wallet = Mock(spec=[])
        client = IdentityClient(wallet=wallet)
        ctx = Mock()
        args = {"attributes": {}}
        
        result = client.resolve_by_attributes(ctx, args, override_with_contacts=False)
        
        assert result == []
    
    def test_resolve_with_locking_script(self):
        """Test resolve parses locking script for attributes."""
        wallet = Mock()
        wallet.discover_by_attributes = Mock(return_value={
            "certificates": [
                {"lockingScript": b"locking_data"}
            ]
        })
        
        client = IdentityClient(wallet=wallet)
        ctx = Mock()
        args = {"attributes": {"email": "test@example.com"}}
        
        with patch('bsv.transaction.pushdrop.parse_pushdrop_locking_script') as mock_parse, \
             patch('bsv.transaction.pushdrop.parse_identity_reveal') as mock_reveal:
            mock_parse.return_value = "parsed"
            mock_reveal.return_value = [("email", "test@example.com")]
            
            result = client.resolve_by_attributes(ctx, args, override_with_contacts=False)
            
            assert len(result) == 1
    
    def test_resolve_exception_handling(self):
        """Test resolve handles exceptions gracefully."""
        wallet = Mock()
        wallet.discover_by_attributes = Mock(side_effect=Exception("Failed"))
        
        client = IdentityClient(wallet=wallet)
        ctx = Mock()
        args = {"attributes": {}}
        
        result = client.resolve_by_attributes(ctx, args, override_with_contacts=False)
        
        assert result == []


class TestParseIdentity:
    """Test parse_identity static method."""
    
    def test_parse_identity_full_data(self):
        """Test parsing identity with full data."""
        identity = {
            "decryptedFields": {
                "name": "John Doe",
                "identityKey": "0123456789abcdef"
            },
            "certifierInfo": {
                "name": "Certifier",
                "iconUrl": "https://example.com/icon.png",
                "trust": 100
            }
        }
        
        result = IdentityClient.parse_identity(identity)
        
        assert result.name == "John Doe"
        assert result.identity_key == "0123456789abcdef"
        assert result.abbreviated_key == "012345…cdef"
        assert result.avatar_url == "https://example.com/icon.png"
    
    def test_parse_identity_display_name(self):
        """Test parsing identity uses displayName if name not present."""
        identity = {
            "decryptedFields": {
                "displayName": "Display Name",
                "identityKey": "key123"
            }
        }
        
        result = IdentityClient.parse_identity(identity)
        
        assert result.name == "Display Name"
    
    def test_parse_identity_unknown_name(self):
        """Test parsing identity defaults to 'Unknown' when no name."""
        identity = {
            "decryptedFields": {
                "identityKey": "key123"
            }
        }
        
        result = IdentityClient.parse_identity(identity)
        
        assert result.name == "Unknown"
    
    def test_parse_identity_short_key(self):
        """Test parsing identity with short key (no abbreviation)."""
        identity = {
            "decryptedFields": {
                "name": "Test",
                "identityKey": "short"
            }
        }
        
        result = IdentityClient.parse_identity(identity)
        
        assert result.abbreviated_key == ""
    
    def test_parse_identity_no_decrypted_fields(self):
        """Test parsing identity with no decryptedFields."""
        identity = {"certifierInfo": {}}
        
        result = IdentityClient.parse_identity(identity)
        
        assert result.name == "Unknown"
        assert result.identity_key == ""
    
    def test_parse_identity_invalid_input(self):
        """Test parsing identity with invalid input."""
        result = IdentityClient.parse_identity(None)
        
        assert result.name == "Unknown"
    
    def test_parse_identity_exception_handling(self):
        """Test parsing identity handles exceptions."""
        # Pass something that will cause an exception
        result = IdentityClient.parse_identity("invalid_string")
        
        assert isinstance(result, DisplayableIdentity)


class TestFromKv:
    """Test _from_kv static method."""
    
    def test_from_kv_full_data(self):
        """Test creating DisplayableIdentity from key-value pairs."""
        fields = [
            ("name", "Alice"),
            ("identityKey", "0123456789abcdef"),
            ("email", "alice@example.com")
        ]
        
        result = IdentityClient._from_kv(fields)
        
        assert result.name == "Alice"
        assert result.identity_key == "0123456789abcdef"
        assert result.abbreviated_key == "012345…cdef"
    
    def test_from_kv_display_name(self):
        """Test _from_kv uses displayName if name not present."""
        fields = [("displayName", "Display"), ("identityKey", "key")]
        
        result = IdentityClient._from_kv(fields)
        
        assert result.name == "Display"
    
    def test_from_kv_unknown_name(self):
        """Test _from_kv defaults to 'Unknown' when no name."""
        fields = [("identityKey", "key123")]
        
        result = IdentityClient._from_kv(fields)
        
        assert result.name == "Unknown"
    
    def test_from_kv_short_key(self):
        """Test _from_kv with short identity key."""
        fields = [("name", "Bob"), ("identityKey", "abc")]
        
        result = IdentityClient._from_kv(fields)
        
        assert result.abbreviated_key == ""
    
    def test_from_kv_empty_fields(self):
        """Test _from_kv with empty fields list."""
        result = IdentityClient._from_kv([])
        
        assert result.name == "Unknown"
        assert result.identity_key == ""
    
    def test_from_kv_none_fields(self):
        """Test _from_kv with None fields."""
        result = IdentityClient._from_kv(None)
        
        assert result.name == "Unknown"


class TestDecryptField:
    """Test _decrypt_field method."""
    
    def test_decrypt_field_not_encrypted(self):
        """Test decrypting field that is not encrypted."""
        wallet = Mock()
        client = IdentityClient(wallet=wallet)
        ctx = Mock()
        
        result = client._decrypt_field(ctx, "name", "plain_value")
        
        assert result == "plain_value"
    
    def test_decrypt_field_no_enc_prefix(self):
        """Test decrypting field without 'enc:' prefix."""
        wallet = Mock()
        client = IdentityClient(wallet=wallet)
        ctx = Mock()
        
        result = client._decrypt_field(ctx, "field", "value")
        
        assert result == "value"
    
    def test_decrypt_field_no_wallet(self):
        """Test decrypting field when wallet is None."""
        client = IdentityClient(wallet=None)
        ctx = Mock()
        
        result = client._decrypt_field(ctx, "field", "enc:data")
        
        assert result == "enc:data"
    
    def test_decrypt_field_with_decrypt_decoded(self):
        """Test decrypting field using decrypt_decoded method."""
        wallet = Mock()
        wallet.decrypt_decoded = Mock(return_value={"plaintext": b"decrypted_value"})
        
        options = IdentityClientOptions(protocol_id={"securityLevel": 2, "protocol": "test"})
        client = IdentityClient(wallet=wallet, options=options, originator="test.com")
        ctx = Mock()
        
        import base64
        encrypted = "enc:" + base64.b64encode(b"encrypted").decode('utf-8')
        
        result = client._decrypt_field(ctx, "email", encrypted)
        
        assert result == "decrypted_value"
        wallet.decrypt_decoded.assert_called_once()
    
    def test_decrypt_field_with_decrypt(self):
        """Test decrypting field using decrypt method (fallback)."""
        wallet = Mock(spec=['decrypt'])  # Only has decrypt, not decrypt_decoded
        wallet.decrypt = Mock(return_value={"plaintext": b"plain"})
        
        client = IdentityClient(wallet=wallet)
        ctx = Mock()
        
        import base64
        encrypted = "enc:" + base64.b64encode(b"data").decode('utf-8')
        
        result = client._decrypt_field(ctx, "field", encrypted)
        
        assert result == "plain"
        wallet.decrypt.assert_called_once()
    
    def test_decrypt_field_exception_handling(self):
        """Test decrypt_field handles exceptions."""
        wallet = Mock()
        wallet.decrypt_decoded = Mock(side_effect=Exception("Decryption failed"))
        
        client = IdentityClient(wallet=wallet)
        ctx = Mock()
        
        import base64
        encrypted = "enc:" + base64.b64encode(b"data").decode('utf-8')
        
        result = client._decrypt_field(ctx, "field", encrypted)
        
        # Should return original value on exception
        assert result == encrypted
    
    def test_decrypt_field_invalid_base64(self):
        """Test decrypt_field with invalid base64 data."""
        wallet = Mock()
        client = IdentityClient(wallet=wallet)
        ctx = Mock()
        
        result = client._decrypt_field(ctx, "field", "enc:invalid_base64!!!")
        
        # Should return original on error
        assert result == "enc:invalid_base64!!!"


class TestMaybeDecryptFields:
    """Test _maybe_decrypt_fields method."""
    
    def test_maybe_decrypt_fields_plain(self):
        """Test decrypting multiple plain fields."""
        wallet = Mock()
        client = IdentityClient(wallet=wallet)
        ctx = Mock()
        
        fields = [("name", "John"), ("email", "john@test.com")]
        
        result = client._maybe_decrypt_fields(ctx, fields)
        
        assert result == {"name": "John", "email": "john@test.com"}
    
    def test_maybe_decrypt_fields_mixed(self):
        """Test decrypting mix of plain and encrypted fields."""
        wallet = Mock()
        wallet.decrypt_decoded = Mock(return_value={"plaintext": b"decrypted"})
        
        client = IdentityClient(wallet=wallet)
        ctx = Mock()
        
        import base64
        encrypted_value = "enc:" + base64.b64encode(b"secret").decode('utf-8')
        fields = [("name", "Jane"), ("secret", encrypted_value)]
        
        result = client._maybe_decrypt_fields(ctx, fields)
        
        assert result["name"] == "Jane"
        assert result["secret"] == "decrypted"
    
    def test_maybe_decrypt_fields_empty(self):
        """Test decrypting empty fields list."""
        wallet = Mock()
        client = IdentityClient(wallet=wallet)
        ctx = Mock()
        
        result = client._maybe_decrypt_fields(ctx, [])
        
        assert result == {}

