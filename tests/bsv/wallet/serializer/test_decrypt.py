"""
Coverage tests for wallet/serializer/decrypt.py - untested branches.
"""
import pytest


def test_serialize_decrypt_args():
    """Test serialize_decrypt_args wrapper."""
    try:
        from bsv.wallet.serializer.decrypt import serialize_decrypt_args

        args = {"ciphertext": b'encrypted', "protocolID": {"securityLevel": 0, "protocol": "test"}, "keyID": "key1"}
        result = serialize_decrypt_args(args)
        assert isinstance(result, bytes)
        assert len(result) > 0
    except ImportError:
        pytest.skip("decrypt functions not available")


def test_deserialize_decrypt_args():
    """Test deserialize_decrypt_args wrapper."""
    try:
        from bsv.wallet.serializer.decrypt import serialize_decrypt_args, deserialize_decrypt_args

        args = {"ciphertext": b'encrypted', "protocolID": {"securityLevel": 0, "protocol": "test"}, "keyID": "key1"}
        serialized = serialize_decrypt_args(args)
        deserialized = deserialize_decrypt_args(serialized)
        assert "ciphertext" in deserialized
        assert deserialized["ciphertext"] == b'encrypted'
    except ImportError:
        pytest.skip("decrypt functions not available")


def test_serialize_decrypt_result():
    """Test serialize_decrypt_result wrapper."""
    try:
        from bsv.wallet.serializer.decrypt import serialize_decrypt_result

        result = {"plaintext": b'decrypted', "keyID": "key1"}
        serialized = serialize_decrypt_result(result)
        assert isinstance(serialized, bytes)
        assert len(serialized) > 0
    except ImportError:
        pytest.skip("decrypt functions not available")


def test_deserialize_decrypt_result():
    """Test deserialize_decrypt_result wrapper."""
    try:
        from bsv.wallet.serializer.decrypt import serialize_decrypt_result, deserialize_decrypt_result

        result = {"plaintext": b'decrypted'}
        serialized = serialize_decrypt_result(result)
        deserialized = deserialize_decrypt_result(serialized)
        assert "plaintext" in deserialized
        assert deserialized["plaintext"] == b'decrypted'
    except ImportError:
        pytest.skip("decrypt functions not available")


def test_decrypt_roundtrip():
    """Test full roundtrip for decrypt args and result."""
    try:
        from bsv.wallet.serializer.decrypt import (
            serialize_decrypt_args, deserialize_decrypt_args,
            serialize_decrypt_result, deserialize_decrypt_result
        )

        # Test args roundtrip
        args = {"ciphertext": b'encrypted data', "protocolID": {"securityLevel": 1, "protocol": "protocol"}, "keyID": "test_key"}
        serialized_args = serialize_decrypt_args(args)
        deserialized_args = deserialize_decrypt_args(serialized_args)
        assert "ciphertext" in deserialized_args
        assert deserialized_args["ciphertext"] == b'encrypted data'

        # Test result roundtrip
        result = {"plaintext": b'decrypted data'}
        serialized_result = serialize_decrypt_result(result)
        deserialized_result = deserialize_decrypt_result(serialized_result)
        assert "plaintext" in deserialized_result
        assert deserialized_result["plaintext"] == b'decrypted data'
    except ImportError:
        pytest.skip("decrypt functions not available")
