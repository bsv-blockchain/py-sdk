"""
Shared fixtures for auth_fetch tests.
"""
import pytest
from unittest.mock import Mock

from bsv.auth.clients.auth_fetch import AuthFetch
from bsv.auth.session_manager import DefaultSessionManager


@pytest.fixture
def mock_wallet():
    """Mock wallet for testing."""
    wallet = Mock()
    wallet.get_public_key = Mock(return_value={'publicKey': '02' + '00' * 32})
    wallet.create_signature = Mock(return_value={'signature': b'mock_signature'})
    wallet.verify_signature = Mock(return_value={'valid': True})
    wallet.create_action = Mock(return_value={
        'signableTransaction': {'tx': b'mock_tx', 'reference': b'mock_ref'},
        'txid': 'mock_txid'
    })
    return wallet


@pytest.fixture
def auth_fetch(mock_wallet):
    """AuthFetch instance for testing."""
    session_manager = DefaultSessionManager()
    return AuthFetch(mock_wallet, [], session_manager)

