import pytest
from unittest.mock import AsyncMock, MagicMock
from bsv.auth.clients.auth_fetch import AuthFetch, SimplifiedFetchRequestOptions
from bsv.auth.requested_certificate_set import RequestedCertificateSet
from bsv.auth.auth_message import AuthMessage
from bsv.auth.peer import Peer, PeerOptions


class DummyWallet:
    def get_public_key(self, ctx, args, originator):
        return {"publicKey": "02a1633c...", "derivationPrefix": "m/0"}

    def create_action(self, ctx, args, originator):
        return {"tx": "0100000001abcdef..."}

    def create_signature(self, ctx, args, originator):
        return {"signature": b"dummy_signature"}

    def verify_signature(self, ctx, args, originator):
        return {"valid": True}


@pytest.mark.asyncio
async def test_fetch_basic_request():
    wallet = DummyWallet()
    requested_certs = RequestedCertificateSet()
    auth_fetch = AuthFetch(wallet, requested_certs)
    url = "https://example.com/api"
    config = SimplifiedFetchRequestOptions(method="GET", headers={"Accept": "application/json"})

    # モックのPeerとTransport
    mock_transport = MagicMock()
    mock_transport.send = AsyncMock(return_value=None)
    mock_transport.on_data = MagicMock(return_value=None)
    peer_options = PeerOptions(wallet=wallet, transport=mock_transport, certificates_to_request=requested_certs)
    mock_peer = Peer(peer_options)
    mock_peer.get_authenticated_session = AsyncMock(return_value=MagicMock(peer_nonce="dummy", is_authenticated=True, peer_identity_key="dummy"))
    mock_peer.to_peer = MagicMock(return_value=None)  # 同期メソッドとしてモック
    mock_peer.listen_for_general_messages = MagicMock(return_value=1)
    mock_peer.stop_listening_for_general_messages = MagicMock()

    # peersにセット
    auth_peer = auth_fetch.peers["https://example.com"] = MagicMock()
    auth_peer.peer = mock_peer

    auth_fetch.fetch(None, url, config)
    mock_peer.to_peer.assert_called_once()

@pytest.mark.asyncio
async def test_fetch_with_auth_headers():
    wallet = DummyWallet()
    requested_certs = RequestedCertificateSet()
    auth_fetch = AuthFetch(wallet, requested_certs)
    url = "https://example.com/api"
    config = SimplifiedFetchRequestOptions(
        method="POST",
        headers={"Content-Type": "application/json", "X-Auth-Required": "true"},
        body=b'{"test": "data"}'
    )
    mock_transport = MagicMock()
    mock_transport.send = AsyncMock(return_value=None)
    mock_transport.on_data = MagicMock(return_value=None)
    peer_options = PeerOptions(wallet=wallet, transport=mock_transport, certificates_to_request=requested_certs)
    mock_peer = Peer(peer_options)
    mock_peer.get_authenticated_session = AsyncMock(return_value=MagicMock(peer_nonce="dummy", is_authenticated=True, peer_identity_key="dummy"))
    mock_peer.to_peer = MagicMock(return_value=None)  # 同期メソッドとしてモック
    mock_peer.listen_for_general_messages = MagicMock(return_value=1)
    mock_peer.stop_listening_for_general_messages = MagicMock()
    auth_peer = auth_fetch.peers["https://example.com"] = MagicMock()
    auth_peer.peer = mock_peer
    auth_fetch.fetch(None, url, config)
    mock_peer.to_peer.assert_called_once()

@pytest.mark.asyncio
async def test_fetch_error_handling():
    wallet = DummyWallet()
    requested_certs = RequestedCertificateSet()
    auth_fetch = AuthFetch(wallet, requested_certs)
    url = "https://example.com/api"
    config = SimplifiedFetchRequestOptions(method="GET")
    mock_transport = MagicMock()
    mock_transport.send = AsyncMock(side_effect=Exception("Network error"))
    mock_transport.on_data = MagicMock(return_value=None)
    peer_options = PeerOptions(wallet=wallet, transport=mock_transport, certificates_to_request=requested_certs)
    mock_peer = Peer(peer_options)
    mock_peer.get_authenticated_session = AsyncMock(return_value=MagicMock(peer_nonce="dummy", is_authenticated=True, peer_identity_key="dummy"))
    mock_peer.to_peer = MagicMock(side_effect=Exception("Network error"))  # 同期メソッドとして例外
    mock_peer.listen_for_general_messages = MagicMock(return_value=1)
    mock_peer.stop_listening_for_general_messages = MagicMock()
    auth_peer = auth_fetch.peers["https://example.com"] = MagicMock()
    auth_peer.peer = mock_peer
    with pytest.raises(RuntimeError, match="Network error"):
        auth_fetch.fetch(None, url, config)

def test_consume_received_certificates():
    wallet = DummyWallet()
    requested_certs = RequestedCertificateSet()
    auth_fetch = AuthFetch(wallet, requested_certs)
    mock_cert = {"type": "authrite", "validationKey": "test_key", "serialNumber": "123", "validFrom": 1000, "validUntil": 2000}
    auth_fetch.certificates_received = [mock_cert]
    certs = auth_fetch.consume_received_certificates()
    assert len(certs) == 1
    assert certs[0]["type"] == "authrite"
    assert certs[0]["serialNumber"] == "123"
    assert len(auth_fetch.certificates_received) == 0

def test_validate_request_options():
    config = SimplifiedFetchRequestOptions()
    assert config.method == "GET"
    assert isinstance(config.headers, dict)
    assert config.body is None
    assert config.retry_counter is None
    config = SimplifiedFetchRequestOptions(method="POST")
    assert config.method == "POST"
    config = SimplifiedFetchRequestOptions(headers={"X-Test": "value"})
    assert config.headers["X-Test"] == "value"
    config = SimplifiedFetchRequestOptions(body=b"test")
    assert config.body == b"test"


def test_fetch_with_retry_counter_at_zero():
    """Test that fetch fails when retry counter reaches zero"""
    from requests.exceptions import RetryError

    wallet = DummyWallet()
    requested_certs = RequestedCertificateSet()
    auth_fetch = AuthFetch(wallet, requested_certs)
    url = "https://example.com/api"
    config = SimplifiedFetchRequestOptions(method="GET", retry_counter=0)

    with pytest.raises(RetryError, match="request failed after maximum number of retries"):
        auth_fetch.fetch(None, url, config)


def test_fetch_with_unsupported_headers():
    """Test that fetch properly handles unsupported headers"""
    import logging
    from unittest.mock import patch

    wallet = DummyWallet()
    requested_certs = RequestedCertificateSet()
    auth_fetch = AuthFetch(wallet, requested_certs)

    # Test with x-bsv-auth header (should be excluded from serialization)
    url = "https://example.com/api"
    config = SimplifiedFetchRequestOptions(
        method="GET",
        headers={"x-bsv-auth": "should-be-excluded", "x-bsv-valid": "should-be-included"}
    )

    # Mock the peer to avoid actual network calls
    with patch.object(auth_fetch, 'peers', {}) as mock_peers:
        mock_peer = MagicMock()
        mock_peer.peer.to_peer = MagicMock(return_value=None)
        mock_peer.peer.listen_for_general_messages = MagicMock(return_value=1)
        mock_peer.peer.stop_listening_for_general_messages = MagicMock()
        mock_peers["https://example.com"] = mock_peer

        # Capture log warnings by patching the logger instance
        with patch.object(auth_fetch.logger, 'warning') as mock_warning:
            try:
                auth_fetch.fetch(None, url, config)
            except Exception:
                # May timeout or fail due to mocking, but that's ok for this test
                pass

            # Check that warnings were logged for unsupported headers
            mock_warning.assert_called()

            # Verify the warning was about the unsupported header
            warning_calls = [call.args[0] for call in mock_warning.call_args_list]
            assert any("Unsupported header in simplified fetch" in msg for msg in warning_calls)


def test_fetch_network_failure_handling():
    """Test that network failures are properly handled and re-raised as RuntimeError"""
    from unittest.mock import patch

    wallet = DummyWallet()
    requested_certs = RequestedCertificateSet()
    auth_fetch = AuthFetch(wallet, requested_certs)
    url = "https://example.com/api"
    config = SimplifiedFetchRequestOptions(method="GET")

    # Mock the peer to simulate network failure during to_peer call
    with patch.object(auth_fetch, 'peers', {}) as mock_peers:
        mock_peer = MagicMock()
        mock_peer.peer.to_peer = MagicMock(side_effect=Exception("Network connection failed"))
        mock_peer.peer.listen_for_general_messages = MagicMock(return_value=1)
        mock_peer.peer.stop_listening_for_general_messages = MagicMock()
        mock_peers["https://example.com"] = mock_peer

        with pytest.raises(RuntimeError, match="Network connection failed"):
            auth_fetch.fetch(None, url, config)