"""Tests for ProtoWallet encrypt/decrypt - TS/Go SDK compatibility.

These tests verify that Python SDK produces the same encryption results
as TypeScript and Go SDKs using the BRC-2 compliance test vectors.
"""

import pytest

from bsv.keys import PrivateKey, PublicKey
from bsv.wallet import ProtoWallet
from bsv.wallet.key_deriver import Protocol, Counterparty, CounterpartyType


class TestProtoWalletEncryptDecryptBasic:
    """Basic encrypt/decrypt functionality tests."""

    def test_encrypt_decrypt_roundtrip(self):
        """Test basic encryption and decryption roundtrip."""
        wallet = ProtoWallet(PrivateKey(), permission_callback=lambda a: True)
        
        plaintext = b"Hello, World!"
        
        # Encrypt
        encrypt_result = wallet.encrypt({
            "plaintext": list(plaintext),
            "protocol_id": [2, "test encryption"],
            "key_id": "test-key-1",
            "counterparty": None  # self
        })
        
        assert "error" not in encrypt_result
        ciphertext = encrypt_result["ciphertext"]
        
        # Decrypt
        decrypt_result = wallet.decrypt({
            "ciphertext": ciphertext,
            "protocol_id": [2, "test encryption"],
            "key_id": "test-key-1",
            "counterparty": None  # self
        })
        
        assert "error" not in decrypt_result
        decrypted = bytes(decrypt_result["plaintext"])
        
        assert decrypted == plaintext

    def test_encrypt_decrypt_with_counterparty(self):
        """Test encryption with explicit counterparty."""
        # Create two wallets
        alice_priv = PrivateKey()
        bob_priv = PrivateKey()
        
        alice_wallet = ProtoWallet(alice_priv, permission_callback=lambda a: True)
        bob_wallet = ProtoWallet(bob_priv, permission_callback=lambda a: True)
        
        plaintext = b"Secret message from Alice to Bob"
        
        # Alice encrypts for Bob
        encrypt_result = alice_wallet.encrypt({
            "plaintext": list(plaintext),
            "protocol_id": [2, "secure messaging"],
            "key_id": "msg-001",
            "counterparty": {
                "type": CounterpartyType.OTHER,
                "counterparty": bob_priv.public_key()
            }
        })
        
        assert "error" not in encrypt_result
        ciphertext = encrypt_result["ciphertext"]
        
        # Bob decrypts (using Alice as counterparty)
        decrypt_result = bob_wallet.decrypt({
            "ciphertext": ciphertext,
            "protocol_id": [2, "secure messaging"],
            "key_id": "msg-001",
            "counterparty": {
                "type": CounterpartyType.OTHER,
                "counterparty": alice_priv.public_key()
            }
        })
        
        assert "error" not in decrypt_result
        decrypted = bytes(decrypt_result["plaintext"])
        
        assert decrypted == plaintext


class TestProtoWalletBRC2Compatibility:
    """BRC-2 compliance test vectors from Go SDK.
    
    These vectors ensure cross-SDK compatibility.
    """

    def test_brc2_encryption_compliance_vector(self):
        """Test BRC-2 encryption compliance vector from Go SDK.
        
        This is the exact test from go-sdk/wallet/proto_wallet_brc_test.go
        """
        # BRC-2 Encryption Compliance Vector
        private_key_hex = "6a2991c9de20e38b31d7ea147bf55f5039e4bbc073160f5e0d541d1f17e321b8"
        private_key = PrivateKey(bytes.fromhex(private_key_hex))
        
        counterparty_pub_key_hex = "0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1"
        counterparty_pub_key = PublicKey(counterparty_pub_key_hex)
        
        # Expected ciphertext from Go SDK test
        expected_ciphertext = bytes([
            252, 203, 216, 184, 29, 161, 223, 212, 16, 193, 94, 99, 31, 140, 99, 43,
            61, 236, 184, 67, 54, 105, 199, 47, 11, 19, 184, 127, 2, 165, 125, 9,
            188, 195, 196, 39, 120, 130, 213, 95, 186, 89, 64, 28, 1, 80, 20, 213,
            159, 133, 98, 253, 128, 105, 113, 247, 197, 152, 236, 64, 166, 207, 113, 134,
            65, 38, 58, 24, 127, 145, 140, 206, 47, 70, 146, 84, 186, 72, 95, 35,
            154, 112, 178, 55, 72, 124
        ])
        expected_plaintext = "BRC-2 Encryption Compliance Validated!"
        
        # Create wallet and decrypt
        wallet = ProtoWallet(private_key, permission_callback=lambda a: True)
        
        decrypt_result = wallet.decrypt({
            "ciphertext": list(expected_ciphertext),
            "protocol_id": {"security_level": 2, "protocol": "BRC2 Test"},
            "key_id": "42",
            "counterparty": {
                "type": CounterpartyType.OTHER,
                "counterparty": counterparty_pub_key
            }
        })
        
        assert "error" not in decrypt_result, f"Decryption failed: {decrypt_result.get('error')}"
        decrypted = bytes(decrypt_result["plaintext"])
        
        assert decrypted.decode('utf-8') == expected_plaintext

    def test_brc2_hmac_compliance_vector(self):
        """Test BRC-2 HMAC compliance vector from Go SDK."""
        # BRC-2 HMAC Compliance Vector
        private_key_hex = "6a2991c9de20e38b31d7ea147bf55f5039e4bbc073160f5e0d541d1f17e321b8"
        private_key = PrivateKey(bytes.fromhex(private_key_hex))
        
        counterparty_pub_key_hex = "0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1"
        counterparty_pub_key = PublicKey(counterparty_pub_key_hex)
        
        # Expected HMAC from Go SDK test
        expected_hmac = bytes([
            81, 240, 18, 153, 163, 45, 174, 85, 9, 246, 142, 125, 209, 133, 82, 76,
            254, 103, 46, 182, 86, 59, 219, 61, 126, 30, 176, 232, 233, 100, 234, 14
        ])
        data = b"BRC-2 HMAC Compliance Validated!"
        
        # Create wallet and compute HMAC
        wallet = ProtoWallet(private_key, permission_callback=lambda a: True)
        
        hmac_result = wallet.create_hmac({
            "data": data,
            "protocol_id": {"security_level": 2, "protocol": "BRC2 Test"},
            "key_id": "42",
            "counterparty": {
                "type": CounterpartyType.OTHER,
                "counterparty": counterparty_pub_key
            }
        })
        
        assert "error" not in hmac_result, f"HMAC creation failed: {hmac_result.get('error')}"
        computed_hmac = hmac_result["hmac"]
        
        assert computed_hmac == expected_hmac


class TestProtoWalletEncryptDecryptFormat:
    """Test ciphertext format matches TS/Go SDK."""

    def test_ciphertext_format(self):
        """Test that ciphertext has correct format: IV (32) + data + tag (16)."""
        wallet = ProtoWallet(PrivateKey(), permission_callback=lambda a: True)
        
        plaintext = b"test"
        
        encrypt_result = wallet.encrypt({
            "plaintext": list(plaintext),
            "protocol_id": [2, "format test"],
            "key_id": "key1"
        })
        
        assert "error" not in encrypt_result
        ciphertext = bytes(encrypt_result["ciphertext"])
        
        # Length should be: IV (32) + len(plaintext) + tag (16)
        expected_length = 32 + len(plaintext) + 16
        assert len(ciphertext) == expected_length

    def test_missing_protocol_returns_error(self):
        """Test that missing protocol returns error."""
        wallet = ProtoWallet(PrivateKey(), permission_callback=lambda a: True)
        
        encrypt_result = wallet.encrypt({
            "plaintext": [1, 2, 3]
            # Missing protocol_id and key_id
        })
        
        assert "error" in encrypt_result

    def test_missing_plaintext_returns_error(self):
        """Test that missing plaintext returns error."""
        wallet = ProtoWallet(PrivateKey(), permission_callback=lambda a: True)
        
        encrypt_result = wallet.encrypt({
            "protocol_id": [2, "test proto"],
            "key_id": "key1"
            # Missing plaintext
        })
        
        assert "error" in encrypt_result


class TestProtoWalletLegacyArgs:
    """Test backward compatibility with legacy nested args format."""

    def test_encryption_args_nested_format(self):
        """Test that nested encryption_args format still works."""
        wallet = ProtoWallet(PrivateKey(), permission_callback=lambda a: True)
        
        plaintext = b"legacy format test"
        
        # Use legacy nested format
        encrypt_result = wallet.encrypt({
            "plaintext": list(plaintext),
            "encryption_args": {
                "protocol_id": {"security_level": 2, "protocol": "legacy test"},
                "key_id": "legacy-key"
            }
        })
        
        assert "error" not in encrypt_result
        ciphertext = encrypt_result["ciphertext"]
        
        # Decrypt using same format
        decrypt_result = wallet.decrypt({
            "ciphertext": ciphertext,
            "encryption_args": {
                "protocol_id": {"security_level": 2, "protocol": "legacy test"},
                "key_id": "legacy-key"
            }
        })
        
        assert "error" not in decrypt_result
        decrypted = bytes(decrypt_result["plaintext"])
        
        assert decrypted == plaintext
