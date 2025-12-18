"""
Coverage tests for AuthMessage validation - missing ValueError branches.
"""
import pytest
from bsv.auth.auth_message import AuthMessage
from bsv.keys import PrivateKey


def test_auth_message_missing_version():
    """Test AuthMessage raises ValueError when version is empty."""
    priv_key = PrivateKey()

    with pytest.raises(ValueError, match="version is required and cannot be empty"):
        AuthMessage(
            version="",  # Empty version
            message_type="initialRequest",
            identity_key=priv_key.public_key()
        )


def test_auth_message_missing_message_type():
    """Test AuthMessage raises ValueError when message_type is empty."""
    priv_key = PrivateKey()

    with pytest.raises(ValueError, match="message_type is required and cannot be empty"):
        AuthMessage(
            version="1.0",
            message_type="",  # Empty message_type
            identity_key=priv_key.public_key()
        )


def test_auth_message_missing_identity_key():
    """Test AuthMessage raises ValueError when identity_key is None."""
    with pytest.raises(ValueError, match="identity_key is required and cannot be None"):
        AuthMessage(
            version="1.0",
            message_type="initialRequest",
            identity_key=None  # None identity_key
        )
