"""
Tests for ECIES compatibility implementation.

Translated from ts-sdk/src/compat/__tests/ECIES.test.ts
"""
import pytest
from bsv.compat.ecies import bitcore_encrypt, bitcore_decrypt, electrum_encrypt, electrum_decrypt
from bsv.keys import PrivateKey
from bsv.hash import sha256


class TestECIES:
    """Test ECIES encryption/decryption matching TS SDK tests."""

    def test_should_make_a_new_ecies_object(self):
        """Test that ECIES module is defined."""
        from bsv.compat import ecies
        assert ecies is not None

    def test_bitcore_encrypt_should_return_bytes(self):
        """Test that bitcoreEncrypt returns bytes."""
        from_key = PrivateKey(42)
        to_key = PrivateKey(88)
        message_buf = sha256(b'my message is the hash of this string')

        enc_buf = bitcore_encrypt(message_buf, to_key.public_key(), from_key)
        assert isinstance(enc_buf, bytes)

    def test_bitcore_encrypt_should_return_bytes_if_fromkey_not_present(self):
        """Test bitcoreEncrypt without fromkey."""
        to_key = PrivateKey(88)
        message_buf = sha256(b'my message is the hash of this string')

        enc_buf = bitcore_encrypt(message_buf, to_key.public_key())
        assert isinstance(enc_buf, bytes)

    def test_bitcore_decrypt_should_decrypt_that_which_was_encrypted(self):
        """Test that bitcoreDecrypt correctly decrypts encrypted data."""
        from_key = PrivateKey(42)
        to_key = PrivateKey(88)
        message_buf = sha256(b'my message is the hash of this string')

        enc_buf = bitcore_encrypt(message_buf, to_key.public_key(), from_key)
        message_buf2 = bitcore_decrypt(enc_buf, to_key)
        assert message_buf2 == message_buf

    def test_bitcore_decrypt_with_random_fromkey(self):
        """Test decryption when fromPrivateKey was randomly generated."""
        to_key = PrivateKey(88)
        message_buf = sha256(b'my message is the hash of this string')

        enc_buf = bitcore_encrypt(message_buf, to_key.public_key())
        message_buf2 = bitcore_decrypt(enc_buf, to_key)
        assert message_buf2 == message_buf

    def test_electrum_ecies_should_work_with_test_vectors(self):
        """Test Electrum ECIES with test vectors."""
        alice_private_key = PrivateKey(int('77e06abc52bf065cb5164c5deca839d0276911991a2730be4d8d0a0307de7ceb', 16))
        bob_private_key = PrivateKey(int('2b57c7c5e408ce927eef5e2efb49cfdadde77961d342daa72284bb3d6590862d', 16))

        message = b'this is my test message'

        # Test vector 1: Alice encrypts, Bob decrypts
        encrypted1 = electrum_encrypt(message, bob_private_key.public_key(), alice_private_key)
        decrypted1 = electrum_decrypt(encrypted1, bob_private_key)
        assert decrypted1 == message

        # Test vector 2: Bob encrypts, Alice decrypts
        encrypted2 = electrum_encrypt(message, alice_private_key.public_key(), bob_private_key)
        decrypted2 = electrum_decrypt(encrypted2, alice_private_key)
        assert decrypted2 == message

