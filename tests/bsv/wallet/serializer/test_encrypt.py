"""
Coverage tests for wallet/serializer/encrypt.py - untested branches.
"""
import pytest


def test_serialize_encrypt_args():
    """Test serialize_encrypt_args wrapper."""
    try:
        from bsv.wallet.serializer.encrypt import serialize_encrypt_args

        args = {"plaintext": b'test', "protocolID": [0, "test"], "keyID": "key1"}
        result = serialize_encrypt_args(args)
        assert isinstance(result, bytes)
        assert len(result) > 0
    except ImportError:
        pytest.skip("encrypt functions not available")


def test_deserialize_encrypt_args():
    """Test deserialize_encrypt_args wrapper."""
    try:
        from bsv.wallet.serializer.encrypt import serialize_encrypt_args, deserialize_encrypt_args

        args = {"plaintext": b'test', "protocolID": [0, "test"], "keyID": "key1"}
        serialized = serialize_encrypt_args(args)
        deserialized = deserialize_encrypt_args(serialized)
        assert "plaintext" in deserialized
        assert deserialized["plaintext"] == b'test'
    except ImportError:
        pytest.skip("encrypt functions not available")


def test_serialize_encrypt_result():
    """Test serialize_encrypt_result wrapper."""
    try:
        from bsv.wallet.serializer.encrypt import serialize_encrypt_result

        result = {"ciphertext": b'encrypted', "keyID": "key1"}
        serialized = serialize_encrypt_result(result)
        assert isinstance(serialized, bytes)
        assert len(serialized) > 0
    except ImportError:
        pytest.skip("encrypt functions not available")


def test_deserialize_encrypt_result():
    """Test deserialize_encrypt_result wrapper."""
    try:
        from bsv.wallet.serializer.encrypt import serialize_encrypt_result, deserialize_encrypt_result

        result = {"ciphertext": b'encrypted'}
        serialized = serialize_encrypt_result(result)
        deserialized = deserialize_encrypt_result(serialized)
        assert "ciphertext" in deserialized
        assert deserialized["ciphertext"] == b'encrypted'
    except ImportError:
        pytest.skip("encrypt functions not available")


def test_encrypt_roundtrip():
    """Test full roundtrip for encrypt args and result."""
    try:
        from bsv.wallet.serializer.encrypt import (
            serialize_encrypt_args, deserialize_encrypt_args,
            serialize_encrypt_result, deserialize_encrypt_result
        )

        # Test args roundtrip
        args = {"plaintext": b'test data', "protocolID": [1, "protocol"], "keyID": "test_key"}
        serialized_args = serialize_encrypt_args(args)
        deserialized_args = deserialize_encrypt_args(serialized_args)
        assert "plaintext" in deserialized_args
        assert deserialized_args["plaintext"] == b'test data'

        # Test result roundtrip
        result = {"ciphertext": b'encrypted data'}
        serialized_result = serialize_encrypt_result(result)
        deserialized_result = deserialize_encrypt_result(serialized_result)
        assert "ciphertext" in deserialized_result
        assert deserialized_result["ciphertext"] == b'encrypted data'
    except ImportError:
        pytest.skip("encrypt functions not available")
