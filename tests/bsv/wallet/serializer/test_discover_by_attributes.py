"""
Coverage tests for wallet/serializer/discover_by_attributes.py - untested branches.
"""
import pytest


def test_serialize_discover_by_attributes_args_basic():
    """Test serialize_discover_by_attributes_args with basic args."""
    try:
        from bsv.wallet.serializer.discover_by_attributes import serialize_discover_by_attributes_args

        args = {"attributes": {"name": "alice", "email": "alice@example.com"}}
        result = serialize_discover_by_attributes_args(args)
        assert isinstance(result, bytes)
        assert len(result) > 0
    except ImportError:
        pytest.skip("discover_by_attributes functions not available")


def test_serialize_discover_by_attributes_args_with_options():
    """Test serialize_discover_by_attributes_args with all optional args."""
    try:
        from bsv.wallet.serializer.discover_by_attributes import serialize_discover_by_attributes_args

        args = {
            "attributes": {"name": "alice"},
            "limit": 10,
            "offset": 5,
            "seekPermission": True
        }
        result = serialize_discover_by_attributes_args(args)
        assert isinstance(result, bytes)
        assert len(result) > 0
    except ImportError:
        pytest.skip("discover_by_attributes functions not available")


def test_serialize_discover_by_attributes_args_empty_attrs():
    """Test serialize_discover_by_attributes_args with empty attributes."""
    try:
        from bsv.wallet.serializer.discover_by_attributes import serialize_discover_by_attributes_args

        args = {"attributes": {}}
        result = serialize_discover_by_attributes_args(args)
        assert isinstance(result, bytes)
        # Should contain varint 0 for empty attributes
        assert result[0] == 0
    except ImportError:
        pytest.skip("discover_by_attributes functions not available")


def test_serialize_discover_by_attributes_args_no_attrs():
    """Test serialize_discover_by_attributes_args with no attributes key."""
    try:
        from bsv.wallet.serializer.discover_by_attributes import serialize_discover_by_attributes_args

        args = {}
        result = serialize_discover_by_attributes_args(args)
        assert isinstance(result, bytes)
        # Should contain varint 0 for empty attributes
        assert result[0] == 0
    except ImportError:
        pytest.skip("discover_by_attributes functions not available")


def test_deserialize_discover_by_attributes_args_basic():
    """Test deserialize_discover_by_attributes_args with basic data."""
    try:
        from bsv.wallet.serializer.discover_by_attributes import (
            serialize_discover_by_attributes_args,
            deserialize_discover_by_attributes_args
        )

        # Create test data
        args = {"attributes": {"name": "alice"}}
        serialized = serialize_discover_by_attributes_args(args)

        # Deserialize
        result = deserialize_discover_by_attributes_args(serialized)
        assert isinstance(result, dict)
        assert "attributes" in result
        assert result["attributes"] == {"name": "alice"}
    except ImportError:
        pytest.skip("discover_by_attributes functions not available")


def test_deserialize_discover_by_attributes_args_with_options():
    """Test deserialize_discover_by_attributes_args with all options."""
    try:
        from bsv.wallet.serializer.discover_by_attributes import (
            serialize_discover_by_attributes_args,
            deserialize_discover_by_attributes_args
        )

        # Create test data
        args = {
            "attributes": {"name": "alice", "email": "alice@example.com"},
            "limit": 10,
            "offset": 5,
            "seekPermission": True
        }
        serialized = serialize_discover_by_attributes_args(args)

        # Deserialize
        result = deserialize_discover_by_attributes_args(serialized)
        assert isinstance(result, dict)
        assert result["attributes"] == {"name": "alice", "email": "alice@example.com"}
        assert result["limit"] == 10
        assert result["offset"] == 5
        assert result["seekPermission"] is True
    except ImportError:
        pytest.skip("discover_by_attributes functions not available")


def test_deserialize_discover_by_attributes_args_empty():
    """Test deserialize_discover_by_attributes_args with empty attributes."""
    try:
        from bsv.wallet.serializer.discover_by_attributes import (
            serialize_discover_by_attributes_args,
            deserialize_discover_by_attributes_args
        )

        # Create test data with empty attributes
        args = {"attributes": {}}
        serialized = serialize_discover_by_attributes_args(args)

        # Deserialize
        result = deserialize_discover_by_attributes_args(serialized)
        assert isinstance(result, dict)
        assert result["attributes"] == {}
    except ImportError:
        pytest.skip("discover_by_attributes functions not available")


def test_deserialize_discover_by_attributes_args_none_values():
    """Test deserialize_discover_by_attributes_args with None optional values."""
    try:
        from bsv.wallet.serializer.discover_by_attributes import (
            serialize_discover_by_attributes_args,
            deserialize_discover_by_attributes_args
        )

        # Create test data with None values
        args = {"attributes": {"name": "alice"}}
        serialized = serialize_discover_by_attributes_args(args)

        # Deserialize
        result = deserialize_discover_by_attributes_args(serialized)
        assert isinstance(result, dict)
        assert result["attributes"] == {"name": "alice"}
        assert result["limit"] is None
        assert result["offset"] is None
        assert result["seekPermission"] is None
    except ImportError:
        pytest.skip("discover_by_attributes functions not available")


def test_discover_by_attributes_roundtrip():
    """Test full roundtrip serialization/deserialization."""
    try:
        from bsv.wallet.serializer.discover_by_attributes import (
            serialize_discover_by_attributes_args,
            deserialize_discover_by_attributes_args
        )

        test_cases = [
            {"attributes": {}},
            {"attributes": {"name": "alice"}},
            {"attributes": {"name": "alice", "email": "alice@example.com"}},
            {"attributes": {"name": "alice"}, "limit": 10},
            {"attributes": {"name": "alice"}, "offset": 5},
            {"attributes": {"name": "alice"}, "seekPermission": True},
            {"attributes": {"name": "alice"}, "limit": 10, "offset": 5, "seekPermission": False},
        ]

        for args in test_cases:
            serialized = serialize_discover_by_attributes_args(args)
            deserialized = deserialize_discover_by_attributes_args(serialized)

            # Check that all keys are preserved
            for key in args:
                assert deserialized[key] == args[key]
    except ImportError:
        pytest.skip("discover_by_attributes functions not available")
