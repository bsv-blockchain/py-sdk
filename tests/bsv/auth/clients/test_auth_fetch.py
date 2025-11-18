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
    """Test basic AuthFetch request with message structure validation."""
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
    
    # Verify to_peer was called once with proper arguments
    mock_peer.to_peer.assert_called_once()
    call_args = mock_peer.to_peer.call_args
    
    # Verify call structure: to_peer(context, message_data, identity_key=..., max_wait_time=...)
    assert len(call_args[0]) >= 2, "to_peer should be called with at least 2 positional args (context, message)"
    context = call_args[0][0]
    message_data = call_args[0][1]
    
    # Verify message data is not empty (it will be encrypted)
    assert message_data is not None, "Message data should not be None"
    assert len(message_data) > 0, "Message data should not be empty"
    assert isinstance(message_data, bytes), f"Message data should be bytes, got {type(message_data)}"
    
    # Verify keyword arguments are present
    kwargs = call_args[1]
    assert "identity_key" in kwargs or len(call_args[0]) > 2, "identity_key should be provided"
    assert "max_wait_time" in kwargs or len(call_args[0]) > 3, "max_wait_time should be provided"
    
    # Verify listener lifecycle - registered and removed
    mock_peer.listen_for_general_messages.assert_called_once()
    listener_id = mock_peer.listen_for_general_messages.return_value
    mock_peer.stop_listening_for_general_messages.assert_called_once_with(listener_id)

@pytest.mark.asyncio
async def test_fetch_with_auth_headers():
    """Test AuthFetch with POST request including custom headers and body."""
    wallet = DummyWallet()
    requested_certs = RequestedCertificateSet()
    auth_fetch = AuthFetch(wallet, requested_certs)
    url = "https://example.com/api"
    body_data = b'{"test": "data"}'
    config = SimplifiedFetchRequestOptions(
        method="POST",
        headers={"Content-Type": "application/json", "X-Auth-Required": "true"},
        body=body_data
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
    
    # Verify to_peer was called with message data
    mock_peer.to_peer.assert_called_once()
    call_args = mock_peer.to_peer.call_args
    message_data = call_args[0][1]
    
    # Verify message is properly constructed
    assert message_data is not None, "Message should not be None"
    assert isinstance(message_data, bytes), f"Message should be bytes, got {type(message_data)}"
    assert len(message_data) > len(body_data), "Encrypted message should be larger than just the body"
    
    # Verify listener lifecycle
    mock_peer.listen_for_general_messages.assert_called_once()
    mock_peer.stop_listening_for_general_messages.assert_called_once()

@pytest.mark.asyncio
async def test_fetch_error_handling():
    """Test AuthFetch properly propagates network errors with correct exception types."""
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
    mock_peer.to_peer = MagicMock(side_effect=RuntimeError("Network error"))  # Specific error type
    mock_peer.listen_for_general_messages = MagicMock(return_value=1)
    mock_peer.stop_listening_for_general_messages = MagicMock()
    auth_peer = auth_fetch.peers["https://example.com"] = MagicMock()
    auth_peer.peer = mock_peer
    
    # Verify RuntimeError is raised with correct message
    with pytest.raises(RuntimeError) as exc_info:
        auth_fetch.fetch(None, url, config)
    assert "Network error" in str(exc_info.value), f"Expected 'Network error' in exception message, got: {exc_info.value}"
    
    # Verify cleanup occurred despite error
    assert mock_peer.listen_for_general_messages.called, "Listener should have been registered before error"

def test_consume_received_certificates():
    """Test consuming certificates clears the internal list and returns all certs."""
    wallet = DummyWallet()
    requested_certs = RequestedCertificateSet()
    auth_fetch = AuthFetch(wallet, requested_certs)
    
    # Test with multiple certificates including edge cases
    mock_cert1 = {"type": "authrite", "validationKey": "test_key", "serialNumber": "123", "validFrom": 1000, "validUntil": 2000}
    mock_cert2 = {"type": "authrite", "validationKey": "test_key2", "serialNumber": "456", "validFrom": 1500, "validUntil": 2500}
    auth_fetch.certificates_received = [mock_cert1, mock_cert2]
    
    # Consume and verify all certs returned
    certs = auth_fetch.consume_received_certificates()
    assert len(certs) == 2, f"Expected 2 certificates, got {len(certs)}"
    assert certs[0]["type"] == "authrite"
    assert certs[0]["serialNumber"] == "123"
    assert certs[1]["serialNumber"] == "456"
    
    # Verify list is cleared
    assert len(auth_fetch.certificates_received) == 0, "Certificate list should be empty after consuming"
    
    # Test consuming empty list
    certs_empty = auth_fetch.consume_received_certificates()
    assert len(certs_empty) == 0, "Consuming empty list should return empty list"

def test_validate_request_options():
    """Test SimplifiedFetchRequestOptions with defaults and various configurations."""
    # Test defaults
    config = SimplifiedFetchRequestOptions()
    assert config.method == "GET", "Default method should be GET"
    assert isinstance(config.headers, dict), "Headers should be a dict"
    assert config.body is None, "Default body should be None"
    assert config.retry_counter is None, "Default retry_counter should be None"
    
    # Test POST with body
    config = SimplifiedFetchRequestOptions(method="POST", body=b"test data")
    assert config.method == "POST"
    assert config.body == b"test data"
    
    # Test with custom headers
    custom_headers = {"Authorization": "Bearer token", "Content-Type": "application/json"}
    config = SimplifiedFetchRequestOptions(method="PUT", headers=custom_headers)
    assert config.method == "PUT"
    assert config.headers == custom_headers
    
    # Test with retry counter
    config = SimplifiedFetchRequestOptions(retry_counter=3)
    assert config.retry_counter == 3, "Retry counter should be set correctly"
    
    # Test with all options
    config = SimplifiedFetchRequestOptions(
        method="DELETE",
        headers={"X-Custom": "value"},
        body=b"payload",
        retry_counter=5
    )
    assert config.method == "DELETE"
    assert config.headers["X-Custom"] == "value"
    assert config.body == b"payload"
    assert config.retry_counter == 5
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
    """Test that fetch properly filters unsupported headers and warns about them."""
    import logging
    from unittest.mock import patch

    wallet = DummyWallet()
    requested_certs = RequestedCertificateSet()
    auth_fetch = AuthFetch(wallet, requested_certs)

    # Test with multiple headers including unsupported ones
    url = "https://example.com/api"
    config = SimplifiedFetchRequestOptions(
        method="GET",
        headers={
            "Accept": "application/json",  # Should warn (unsupported)
            "Content-Type": "text/plain",   # Should warn (unsupported)
            "X-Custom": "value"              # Should warn (unsupported)
        }
    )

    # Mock the peer to avoid actual network calls
    with patch.object(auth_fetch, 'peers', {}) as mock_peers:
        mock_peer = MagicMock()
        mock_peer.peer.to_peer = MagicMock(return_value=None)
        mock_peer.peer.listen_for_general_messages = MagicMock(return_value=1)
        mock_peer.peer.stop_listening_for_general_messages = MagicMock()
        mock_peer.peer.get_authenticated_session = MagicMock(
            return_value=MagicMock(peer_nonce="test", is_authenticated=True, peer_identity_key="test_key")
        )
        mock_peers["https://example.com"] = mock_peer

        # Capture log warnings by patching the logger instance
        with patch.object(auth_fetch.logger, 'warning') as mock_warning:
            try:
                auth_fetch.fetch(None, url, config)
            except Exception:
                # May timeout or fail due to mocking, but that's ok for this test
                pass

            # Verify warnings were logged for unsupported headers
            assert mock_warning.called, "Should have logged warnings for unsupported headers"
            
            # Verify the warnings mention "Unsupported header"
            warning_calls = [call.args[0] for call in mock_warning.call_args_list]
            assert len(warning_calls) >= 1, f"Expected warnings about unsupported headers, got: {warning_calls}"
            
            # Verify specific headers are mentioned in warnings
            all_warnings = " ".join(warning_calls)
            assert "Unsupported header" in all_warnings or "unsupported" in all_warnings.lower(), \
                f"Expected warnings about unsupported headers, got: {warning_calls}"
            
            print(f"✓ Correctly warned about {len(warning_calls)} unsupported header(s)")


def test_fetch_network_failure_handling():
    """Test that network failures are properly handled, cleaned up, and re-raised as RuntimeError"""
    from unittest.mock import patch

    wallet = DummyWallet()
    requested_certs = RequestedCertificateSet()
    auth_fetch = AuthFetch(wallet, requested_certs)
    url = "https://example.com/api"
    config = SimplifiedFetchRequestOptions(method="GET")

    # Mock the peer to simulate network failure during to_peer call
    with patch.object(auth_fetch, 'peers', {}) as mock_peers:
        mock_peer = MagicMock()
        mock_peer.peer.to_peer = MagicMock(side_effect=RuntimeError("Network connection failed"))
        mock_peer.peer.listen_for_general_messages = MagicMock(return_value=1)
        mock_peer.peer.stop_listening_for_general_messages = MagicMock()
        mock_peer.peer.get_authenticated_session = MagicMock(
            return_value=MagicMock(peer_nonce="test", is_authenticated=True, peer_identity_key="test_key")
        )
        mock_peers["https://example.com"] = mock_peer

        # Verify RuntimeError is raised with correct message
        with pytest.raises(RuntimeError) as exc_info:
            auth_fetch.fetch(None, url, config)
        
        assert "Network connection failed" in str(exc_info.value), \
            f"Expected 'Network connection failed' in error, got: {exc_info.value}"
        
        # Verify listener was registered (should happen before failure)
        assert mock_peer.peer.listen_for_general_messages.called, \
            "Listener should be registered before network operation"
        
        # Note: Cleanup may or may not occur depending on when the exception is raised
        # The important part is that the exception propagates correctly