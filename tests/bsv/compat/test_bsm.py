"""
Tests for BSM (Bitcoin Signed Message) implementation.

Translated from ts-sdk/src/compat/__tests/BSM.test.ts
"""
import pytest
from bsv.compat.bsm import sign, verify, magic_hash
from bsv.keys import PrivateKey, PublicKey
from bsv.utils import serialize_ecdsa_der, deserialize_ecdsa_der


class TestBSM:
    """Test BSM (Bitcoin Signed Message) matching TS SDK tests."""

    def test_magic_hash_should_return_a_hash(self):
        """Test that magicHash returns a 32-byte hash."""
        buf = bytes.fromhex('001122')
        hash_buf = magic_hash(buf)
        assert len(hash_buf) == 32

    def test_sign_should_return_a_signature(self):
        """Test that sign returns a signature."""
        message_buf = b'this is my message'
        private_key = PrivateKey(42)

        sig = sign(message_buf, private_key, mode='raw')

        # Should return a tuple (r, s) or bytes
        assert sig is not None
        # If it's DER format, should be 70 bytes
        if isinstance(sig, bytes):
            assert len(sig) == 70

    def test_sign_creates_the_correct_base64_signature(self):
        """Test that sign creates correct base64 signature."""
        private_key = PrivateKey('L211enC224G1kV8pyyq7bjVd9SxZebnRYEzzM3i7ZHCc1c5E7dQu')
        sig = sign(b'hello world', private_key, mode='base64')
        expected = 'H4T8Asr0WkC6wYfBESR6pCAfECtdsPM4fwiSQ2qndFi8dVtv/mrOFaySx9xQE7j24ugoJ4iGnsRwAC8QwaoHOXk='
        assert sig == expected

    def test_verify_should_verify_a_signed_message(self):
        """Test that verify correctly verifies a signed message."""
        message_buf = b'this is my message'
        private_key = PrivateKey(42)

        sig = sign(message_buf, private_key, mode='raw')
        result = verify(message_buf, sig, private_key.public_key())
        assert result is True

    def test_verify_should_verify_a_signed_message_in_base64(self):
        """Test verification of base64 signature."""
        message = b'Texas'
        # Signature in compact format (recoverable)
        signature_compact = 'IAV89EkfHSzAIA8cEWbbKHUYzJqcShkpWaXGJ5+mf4+YIlf3XNlr0bj9X60sNe1A7+x9qyk+zmXropMDY4370n8='
        public_key_hex = '03d4d1a6c5d8c03b0e671bc1891b69afaecb40c0686188fe9019f93581b43e8334'
        public_key = PublicKey(public_key_hex)

        # Convert compact signature to DER for verification
        from bsv.utils import unstringify_ecdsa_recoverable
        serialized_recoverable, _ = unstringify_ecdsa_recoverable(signature_compact)
        from bsv.utils import deserialize_ecdsa_recoverable
        r, s, _ = deserialize_ecdsa_recoverable(serialized_recoverable)
        der_sig = serialize_ecdsa_der((r, s))

        result = verify(message, der_sig, public_key)
        assert result is True

