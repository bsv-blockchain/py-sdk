"""
Coverage tests for wallet/serializer/discover_by_identity_key.py - untested branches.
"""
import pytest


def test_serialize_discover_by_identity_key_args_basic():
    """Test serialize_discover_by_identity_key_args with basic args."""
    try:
        from bsv.wallet.serializer.discover_by_identity_key import serialize_discover_by_identity_key_args

        args = {"identityKey": b'\x02' * 33}
        result = serialize_discover_by_identity_key_args(args)
        assert isinstance(result, bytes)
        assert len(result) >= 33  # identityKey + nil markers for optional fields
    except ImportError:
        pytest.skip("discover_by_identity_key functions not available")


def test_serialize_discover_by_identity_key_args_with_options():
    """Test serialize_discover_by_identity_key_args with all optional args."""
    try:
        from bsv.wallet.serializer.discover_by_identity_key import serialize_discover_by_identity_key_args

        args = {
            "identityKey": b'\x03' * 33,
            "limit": 20,
            "offset": 10,
            "seekPermission": True
        }
        result = serialize_discover_by_identity_key_args(args)
        assert isinstance(result, bytes)
        assert len(result) > 33  # identityKey + options
    except ImportError:
        pytest.skip("discover_by_identity_key functions not available")


def test_serialize_discover_by_identity_key_args_none_values():
    """Test serialize_discover_by_identity_key_args with None optional values."""
    try:
        from bsv.wallet.serializer.discover_by_identity_key import serialize_discover_by_identity_key_args

        args = {"identityKey": b'\x04' * 33}
        result = serialize_discover_by_identity_key_args(args)
        assert isinstance(result, bytes)
        # Includes nil markers for optional fields even when None
        assert len(result) >= 33
    except ImportError:
        pytest.skip("discover_by_identity_key functions not available")


def test_deserialize_discover_by_identity_key_args_basic():
    """Test deserialize_discover_by_identity_key_args with basic data."""
    try:
        from bsv.wallet.serializer.discover_by_identity_key import (
            serialize_discover_by_identity_key_args,
            deserialize_discover_by_identity_key_args
        )

        # Create test data
        identity_key = b'\x05' * 33
        args = {"identityKey": identity_key}
        serialized = serialize_discover_by_identity_key_args(args)

        # Deserialize
        result = deserialize_discover_by_identity_key_args(serialized)
        assert isinstance(result, dict)
        assert "identityKey" in result
        assert result["identityKey"] == identity_key
    except ImportError:
        pytest.skip("discover_by_identity_key functions not available")


def test_deserialize_discover_by_identity_key_args_with_options():
    """Test deserialize_discover_by_identity_key_args with all options."""
    try:
        from bsv.wallet.serializer.discover_by_identity_key import (
            serialize_discover_by_identity_key_args,
            deserialize_discover_by_identity_key_args
        )

        # Create test data
        identity_key = b'\x06' * 33
        args = {
            "identityKey": identity_key,
            "limit": 15,
            "offset": 3,
            "seekPermission": False
        }
        serialized = serialize_discover_by_identity_key_args(args)

        # Deserialize
        result = deserialize_discover_by_identity_key_args(serialized)
        assert isinstance(result, dict)
        assert result["identityKey"] == identity_key
        assert result["limit"] == 15
        assert result["offset"] == 3
        assert result["seekPermission"] is False
    except ImportError:
        pytest.skip("discover_by_identity_key functions not available")


def test_deserialize_discover_by_identity_key_args_none_values():
    """Test deserialize_discover_by_identity_key_args with None optional values."""
    try:
        from bsv.wallet.serializer.discover_by_identity_key import (
            serialize_discover_by_identity_key_args,
            deserialize_discover_by_identity_key_args
        )

        # Create test data with None values
        identity_key = b'\x07' * 33
        args = {"identityKey": identity_key}
        serialized = serialize_discover_by_identity_key_args(args)

        # Deserialize
        result = deserialize_discover_by_identity_key_args(serialized)
        assert isinstance(result, dict)
        assert result["identityKey"] == identity_key
        assert result["limit"] is None
        assert result["offset"] is None
        assert result["seekPermission"] is None
    except ImportError:
        pytest.skip("discover_by_identity_key functions not available")


def test_discover_by_identity_key_roundtrip():
    """Test full roundtrip serialization/deserialization."""
    try:
        from bsv.wallet.serializer.discover_by_identity_key import (
            serialize_discover_by_identity_key_args,
            deserialize_discover_by_identity_key_args
        )

        test_cases = [
            {"identityKey": b'\x01' * 33},
            {"identityKey": b'\x02' * 33, "limit": 10},
            {"identityKey": b'\x03' * 33, "offset": 5},
            {"identityKey": b'\x04' * 33, "seekPermission": True},
            {"identityKey": b'\x05' * 33, "limit": 20, "offset": 10, "seekPermission": False},
        ]

        for args in test_cases:
            serialized = serialize_discover_by_identity_key_args(args)
            deserialized = deserialize_discover_by_identity_key_args(serialized)

            # Check that all keys are preserved
            for key in args:
                assert deserialized[key] == args[key]
    except ImportError:
        pytest.skip("discover_by_identity_key functions not available")


def test_discover_by_identity_key_edge_cases():
    """Test discover_by_identity_key with edge cases."""
    try:
        from bsv.wallet.serializer.discover_by_identity_key import (
            serialize_discover_by_identity_key_args,
            deserialize_discover_by_identity_key_args
        )

        # Test with different identity key lengths (should be 33 bytes)
        identity_key_33 = b'\x08' * 33
        args = {"identityKey": identity_key_33}
        serialized = serialize_discover_by_identity_key_args(args)
        deserialized = deserialize_discover_by_identity_key_args(serialized)
        assert deserialized["identityKey"] == identity_key_33
    except ImportError:
        pytest.skip("discover_by_identity_key functions not available")
