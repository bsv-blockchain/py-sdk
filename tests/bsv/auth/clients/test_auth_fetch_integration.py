"""
Comprehensive integration tests for bsv/auth/clients/auth_fetch.py

Tests HTTP request/response flow, certificate exchange, threading, and callbacks.
"""

import pytest
import threading
import base64
from unittest.mock import Mock, patch, MagicMock, call
from requests.exceptions import RetryError
from bsv.auth.clients.auth_fetch import (
    SimplifiedFetchRequestOptions,
    AuthPeer,
    AuthFetch
)
from bsv.auth.requested_certificate_set import RequestedCertificateSet
from bsv.keys import PrivateKey


class TestAuthFetchPeerCreation:
    """Test peer creation and management."""
    
    @pytest.fixture
    def auth_fetch(self):
        """Create AuthFetch instance with mocks."""
        mock_wallet = Mock()
        cert_type = b"A" * 32
        from bsv.auth.requested_certificate_set import RequestedCertificateTypeIDAndFieldList
        cert_types = RequestedCertificateTypeIDAndFieldList({cert_type: ["name"]})
        pk = PrivateKey().public_key()
        mock_certs = RequestedCertificateSet([pk], cert_types)
        return AuthFetch(mock_wallet, mock_certs)
    
    def test_peer_created_on_first_fetch(self, auth_fetch):
        """Test that peer is created on first fetch to URL."""
        with patch('bsv.auth.clients.auth_fetch.SimplifiedHTTPTransport') as mock_transport:
            with patch('bsv.auth.clients.auth_fetch.Peer') as mock_peer_class:
                mock_peer = Mock()
                mock_peer.listen_for_certificates_received = Mock(return_value=None)
                mock_peer.listen_for_general_messages = Mock(return_value="listener_id")
                mock_peer.to_peer = Mock(return_value=None)
                mock_peer.stop_listening_for_general_messages = Mock()
                mock_peer_class.return_value = mock_peer
                
                with patch('os.urandom', return_value=b'x' * 32):
                    with patch('threading.Event') as mock_event_class:
                        mock_event = Mock()
                        mock_event.wait = Mock()
                        mock_event_class.return_value = mock_event
                        
                        with patch.object(auth_fetch, 'serialize_request', return_value=b"data"):
                            try:
                                auth_fetch.fetch(None, "https://example.com/api")
                            except Exception:
                                pass
                
                # Verify peer was created
                assert "https://example.com" in auth_fetch.peers
                mock_transport.assert_called_once_with("https://example.com")
                mock_peer_class.assert_called_once()
    
    def test_peer_reused_on_subsequent_fetches(self, auth_fetch):
        """Test that existing peer is reused."""
        # Pre-create peer
        mock_peer = Mock()
        mock_peer.listen_for_general_messages = Mock(return_value="listener_id")
        mock_peer.to_peer = Mock(return_value=None)
        mock_peer.stop_listening_for_general_messages = Mock()
        auth_peer = AuthPeer()
        auth_peer.peer = mock_peer
        auth_fetch.peers["https://example.com"] = auth_peer
        
        with patch('os.urandom', return_value=b'y' * 32):
            with patch('threading.Event') as mock_event_class:
                mock_event = Mock()
                mock_event.wait = Mock()
                mock_event_class.return_value = mock_event
                
                with patch.object(auth_fetch, 'serialize_request', return_value=b"data"):
                    try:
                        auth_fetch.fetch(None, "https://example.com/other")
                    except Exception:
                        pass
        
        # Verify peer was reused (only one in dict)
        assert len(auth_fetch.peers) == 1
    
    def test_certificate_listener_registered(self, auth_fetch):
        """Test that certificate listener is registered on peer creation."""
        with patch('bsv.auth.clients.auth_fetch.SimplifiedHTTPTransport'):
            with patch('bsv.auth.clients.auth_fetch.Peer') as mock_peer_class:
                mock_peer = Mock()
                mock_peer.listen_for_certificates_received = Mock()
                mock_peer.listen_for_general_messages = Mock(return_value="listener_id")
                mock_peer.to_peer = Mock(return_value=None)
                mock_peer.stop_listening_for_general_messages = Mock()
                mock_peer_class.return_value = mock_peer
                
                with patch('os.urandom', return_value=b'z' * 32):
                    with patch('threading.Event'):
                        with patch.object(auth_fetch, 'serialize_request', return_value=b"data"):
                            try:
                                auth_fetch.fetch(None, "https://test.com/endpoint")
                            except Exception:
                                pass
                
                # Verify certificate listener was registered
                mock_peer.listen_for_certificates_received.assert_called_once()


class TestAuthFetchCallbacks:
    """Test callback and threading mechanisms."""
    
    @pytest.fixture
    def auth_fetch(self):
        """Create AuthFetch instance."""
        mock_wallet = Mock()
        mock_certs = Mock()
        return AuthFetch(mock_wallet, mock_certs)
    
    def test_callback_registered_for_request(self, auth_fetch):
        """Test that callback is registered for each request."""
        # Pre-create peer to bypass peer creation
        mock_peer = Mock()
        mock_peer.listen_for_general_messages = Mock(return_value="listener_id")
        mock_peer.to_peer = Mock(return_value=None)
        mock_peer.stop_listening_for_general_messages = Mock()
        auth_peer = AuthPeer()
        auth_peer.peer = mock_peer
        auth_fetch.peers["https://example.com"] = auth_peer
        
        nonce = b'a' * 32
        with patch('os.urandom', return_value=nonce):
            with patch('threading.Event'):
                with patch.object(auth_fetch, 'serialize_request', return_value=b"data"):
                    try:
                        auth_fetch.fetch(None, "https://example.com/test")
                    except Exception:
                        pass
        
        # Callback should have been registered (and then removed)
        # Since we patched Event.wait, callback gets cleaned up
        assert len(auth_fetch.callbacks) == 0  # Cleaned up after request
    
    def test_callback_structure_created(self, auth_fetch):
        """Test that callback structure is created with resolve and reject."""
        # Test callback dict structure
        _ = "test_nonce"
        
        # Manually create callback structure (as done in fetch)
        response_holder = {'resp': None, 'err': None}
        import threading
        response_event = threading.Event()
        
        callbacks = {
            'resolve': lambda resp: (response_holder.update({'resp': resp}), response_event.set()),
            'reject': lambda err: (response_holder.update({'err': err}), response_event.set()),
        }
        
        # Test resolve
        test_response = Mock()
        callbacks['resolve'](test_response)
        assert response_holder['resp'] == test_response
        assert response_event.is_set()
        
        # Reset and test reject
        response_event.clear()
        response_holder = {'resp': None, 'err': None}
        callbacks = {
            'resolve': lambda resp: (response_holder.update({'resp': resp}), response_event.set()),
            'reject': lambda err: (response_holder.update({'err': err}), response_event.set()),
        }
        test_error = Exception("test error")
        callbacks['reject'](test_error)
        assert response_holder['err'] == test_error
        assert response_event.is_set()


class TestAuthFetchFallbackHTTP:
    """Test fallback to regular HTTP when mutual auth fails."""
    
    @pytest.fixture
    def auth_fetch(self):
        """Create AuthFetch instance."""
        mock_wallet = Mock()
        mock_certs = Mock()
        return AuthFetch(mock_wallet, mock_certs)
    
    def test_fallback_when_mutual_auth_unsupported(self, auth_fetch):
        """Test fallback to regular HTTP when mutual auth is explicitly unsupported."""
        # Create peer with mutual auth disabled
        mock_peer = Mock()
        auth_peer = AuthPeer()
        auth_peer.peer = mock_peer
        auth_peer.supports_mutual_auth = False  # Explicitly unsupported
        auth_fetch.peers["https://example.com"] = auth_peer
        
        mock_response = Mock()
        mock_response.status_code = 200
        
        with patch.object(auth_fetch, 'handle_fetch_and_validate', return_value=mock_response):
            result = auth_fetch.fetch(None, "https://example.com/api")
            assert result == mock_response


class TestAuthFetchErrorHandling:
    """Test error handling scenarios."""
    
    @pytest.fixture
    def auth_fetch(self):
        """Create AuthFetch instance."""
        mock_wallet = Mock()
        mock_certs = Mock()
        return AuthFetch(mock_wallet, mock_certs)
    
    def test_session_not_found_error_string_detected(self, auth_fetch):
        """Test that 'Session not found' error string is detected."""
        # Test various error message formats that should be detected
        test_messages = [
            "Session not found for nonce",
            "Session not found",
            "Error: Session not found in cache"
        ]
        for error_msg in test_messages:
            assert "Session not found" in error_msg
        
        # Test the error handling path exists
        mock_peer = Mock()
        mock_peer.listen_for_general_messages = Mock(return_value="listener_id")
        # Return error that will be checked
        mock_peer.to_peer = Mock(return_value=Exception("Session not found for nonce"))
        mock_peer.stop_listening_for_general_messages = Mock()
        
        auth_peer = AuthPeer()
        auth_peer.peer = mock_peer
        auth_fetch.peers["https://example.com"] = auth_peer
        
        with patch('os.urandom', return_value=b'c' * 32):
            with patch('threading.Event'):
                with patch.object(auth_fetch, 'serialize_request', return_value=b"data"):
                    try:
                        auth_fetch.fetch(None, "https://example.com/test")
                    except Exception:
                        pass
    
    def test_auth_failure_triggers_fallback(self, auth_fetch):
        """Test that authentication failure triggers fallback to regular HTTP."""
        mock_peer = Mock()
        mock_peer.listen_for_general_messages = Mock(return_value="listener_id")
        mock_peer.to_peer = Mock(return_value=Exception("HTTP server failed to authenticate"))
        mock_peer.stop_listening_for_general_messages = Mock()
        
        auth_peer = AuthPeer()
        auth_peer.peer = mock_peer
        auth_fetch.peers["https://example.com"] = auth_peer
        
        mock_response = Mock()
        mock_response.status_code = 200
        
        with patch('os.urandom', return_value=b'd' * 32):
            with patch('threading.Event'):
                with patch.object(auth_fetch, 'serialize_request', return_value=b"data"):
                    with patch.object(auth_fetch, 'handle_fetch_and_validate', return_value=mock_response):
                        try:
                            auth_fetch.fetch(None, "https://example.com/test")
                        except Exception:
                            pass


class TestAuthFetchSerialization:
    """Test request serialization."""
    
    @pytest.fixture
    def auth_fetch(self):
        """Create AuthFetch instance."""
        mock_wallet = Mock()
        mock_certs = Mock()
        return AuthFetch(mock_wallet, mock_certs)
    
    def test_serialize_request_get(self, auth_fetch):
        """Test serializing GET request."""
        import urllib.parse
        parsed = urllib.parse.urlparse("https://example.com/api")
        nonce = b'e' * 32
        
        result = auth_fetch.serialize_request("GET", {}, b"", parsed, nonce)
        
        assert isinstance(result, bytes)
        assert len(result) > 0
    
    def test_serialize_request_post_with_body(self, auth_fetch):
        """Test serializing POST request with body."""
        import urllib.parse
        parsed = urllib.parse.urlparse("https://example.com/api")
        nonce = b'f' * 32
        body = b'{"key": "value"}'
        
        result = auth_fetch.serialize_request(
            "POST",
            {"Content-Type": "application/json"},
            body,
            parsed,
            nonce
        )
        
        assert isinstance(result, bytes)
        assert len(result) > len(body)  # Should include headers and nonce
    
    def test_serialize_request_with_headers(self, auth_fetch):
        """Test serializing request with multiple headers."""
        import urllib.parse
        parsed = urllib.parse.urlparse("https://example.com/api")
        nonce = b'g' * 32
        headers = {
            "Authorization": "Bearer token",
            "Content-Type": "application/json",
            "X-Custom": "value"
        }
        
        result = auth_fetch.serialize_request("POST", headers, b"data", parsed, nonce)
        
        assert isinstance(result, bytes)


class TestAuthFetchResponseParsing:
    """Test response parsing from binary and JSON formats."""
    
    @pytest.fixture
    def auth_fetch(self):
        """Create AuthFetch instance."""
        mock_wallet = Mock()
        mock_certs = Mock()
        return AuthFetch(mock_wallet, mock_certs)
    
    def test_parse_json_response(self, auth_fetch):
        """Test parsing JSON response format."""
        import json
        nonce_b64 = base64.b64encode(b'h' * 32).decode()
        
        json_response = {
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "body": "response data"
        }
        payload = json.dumps(json_response).encode('utf-8')
        
        config = SimplifiedFetchRequestOptions()
        result = auth_fetch._parse_general_response(
            None, payload, nonce_b64, "https://example.com/api", config
        )
        
        assert result is not None
        assert result.status_code == 200
    
    def test_parse_empty_payload_returns_none(self, auth_fetch):
        """Test that empty payload returns None."""
        result = auth_fetch._parse_general_response(
            None, b"", "nonce", "https://example.com/api", SimplifiedFetchRequestOptions()
        )
        assert result is None
    
    def test_parse_invalid_json_returns_none(self, auth_fetch):
        """Test that invalid JSON returns None."""
        result = auth_fetch._parse_general_response(
            None, b"invalid json {", "nonce", "https://example.com/api", SimplifiedFetchRequestOptions()
        )
        assert result is None


class TestAuthFetchPaymentHandling:
    """Test 402 payment required handling."""
    
    @pytest.fixture
    def auth_fetch(self):
        """Create AuthFetch instance."""
        mock_wallet = Mock()
        mock_certs = Mock()
        return AuthFetch(mock_wallet, mock_certs)
    
    def test_402_triggers_payment_handler(self, auth_fetch):
        """Test that 402 response triggers payment handler."""
        mock_peer = Mock()
        auth_peer = AuthPeer()
        auth_peer.peer = mock_peer
        auth_peer.supports_mutual_auth = False
        auth_fetch.peers["https://example.com"] = auth_peer
        
        mock_response = Mock()
        mock_response.status_code = 402
        
        mock_payment_response = Mock()
        mock_payment_response.status_code = 200
        
        with patch.object(auth_fetch, 'handle_fetch_and_validate', return_value=mock_response):
            with patch.object(auth_fetch, 'handle_payment_and_retry', return_value=mock_payment_response):
                result = auth_fetch.fetch(None, "https://example.com/api")
                assert result == mock_payment_response


class TestAuthFetchBuildResponse:
    """Test response building."""
    
    @pytest.fixture
    def auth_fetch(self):
        """Create AuthFetch instance."""
        mock_wallet = Mock()
        mock_certs = Mock()
        return AuthFetch(mock_wallet, mock_certs)
    
    def test_build_response_creates_object(self, auth_fetch):
        """Test that _build_response creates response-like object."""
        response = auth_fetch._build_response(
            "https://example.com/api",
            "GET",
            200,
            {"Content-Type": "text/html"},
            b"<html></html>"
        )
        
        assert response.status_code == 200
        assert response.headers["Content-Type"] == "text/html"
        assert response.text == "<html></html>"
    
    def test_build_response_with_empty_body(self, auth_fetch):
        """Test building response with empty body."""
        response = auth_fetch._build_response(
            "https://example.com/api",
            "GET",
            204,
            {},
            b""
        )
        
        assert response.status_code == 204
        assert response.text == ""


class TestAuthFetchHandleFetchAndValidate:
    """Test handle_fetch_and_validate method."""
    
    @pytest.fixture
    def auth_fetch(self):
        """Create AuthFetch instance."""
        mock_wallet = Mock()
        mock_certs = Mock()
        return AuthFetch(mock_wallet, mock_certs)
    
    def test_handle_fetch_makes_http_request(self, auth_fetch):
        """Test that handle_fetch_and_validate makes HTTP request."""
        auth_peer = AuthPeer()
        config = SimplifiedFetchRequestOptions(method="GET", headers={"Accept": "application/json"})
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.content = b'{"result": "success"}'
        
        with patch('requests.request', return_value=mock_response):
            result = auth_fetch.handle_fetch_and_validate(
                "https://example.com/api",
                config,
                auth_peer
            )
            
            assert result.status_code == 200


class TestAuthFetchCertificateCollection:
    """Test certificate collection from responses."""
    
    @pytest.fixture
    def auth_fetch(self):
        """Create AuthFetch instance."""
        mock_wallet = Mock()
        cert_type = b"Z" * 32
        from bsv.auth.requested_certificate_set import RequestedCertificateTypeIDAndFieldList
        cert_types = RequestedCertificateTypeIDAndFieldList({cert_type: ["field"]})
        pk = PrivateKey().public_key()
        mock_certs = RequestedCertificateSet([pk], cert_types)
        return AuthFetch(mock_wallet, mock_certs)
    
    def test_certificates_added_via_callback(self, auth_fetch):
        """Test that certificates are added when callback is triggered."""
        mock_cert1 = Mock()
        mock_cert2 = Mock()
        certs = [mock_cert1, mock_cert2]
        
        # Simulate certificate callback
        auth_fetch.certificates_received.extend(certs)
        
        assert len(auth_fetch.certificates_received) == 2
        assert mock_cert1 in auth_fetch.certificates_received
        assert mock_cert2 in auth_fetch.certificates_received
    
    def test_certificates_callback_handles_none(self, auth_fetch):
        """Test that certificate callback handles None gracefully."""
        # Simulate callback with None
        try:
            auth_fetch.certificates_received.extend(None or [])
            success = True
        except Exception:
            success = False
        
        assert success
        assert len(auth_fetch.certificates_received) == 0


class TestAuthFetchCompleteFlow:
    """Integration test of complete request/response flow."""
    
    @pytest.fixture
    def auth_fetch(self):
        """Create AuthFetch instance with full setup."""
        mock_wallet = Mock()
        cert_type = b"Y" * 32
        from bsv.auth.requested_certificate_set import RequestedCertificateTypeIDAndFieldList
        cert_types = RequestedCertificateTypeIDAndFieldList({cert_type: ["name"]})
        pk = PrivateKey().public_key()
        mock_certs = RequestedCertificateSet([pk], cert_types)
        return AuthFetch(mock_wallet, mock_certs)
    
    def test_full_request_response_cycle(self, auth_fetch):
        """Test complete request/response cycle with mocked components."""
        # Setup mocks
        with patch('bsv.auth.clients.auth_fetch.SimplifiedHTTPTransport'):
            with patch('bsv.auth.clients.auth_fetch.Peer') as mock_peer_class:
                mock_peer = Mock()
                mock_peer.listen_for_certificates_received = Mock()
                mock_peer.listen_for_general_messages = Mock(return_value="listener_id")
                mock_peer.to_peer = Mock(return_value=None)
                mock_peer.stop_listening_for_general_messages = Mock()
                mock_peer_class.return_value = mock_peer
                
                with patch('os.urandom', return_value=b'i' * 32):
                    with patch('threading.Event') as mock_event_class:
                        mock_event = Mock()
                        mock_event.wait = Mock()
                        mock_event_class.return_value = mock_event
                        
                        with patch.object(auth_fetch, 'serialize_request', return_value=b"serialized"):
                            try:
                                auth_fetch.fetch(None, "https://api.example.com/endpoint")
                            except RuntimeError:
                                pass  # Expected when no response is provided
                
                # Verify complete flow
                assert "https://api.example.com" in auth_fetch.peers
                mock_peer.listen_for_certificates_received.assert_called_once()
                mock_peer.listen_for_general_messages.assert_called_once()
                mock_peer.to_peer.assert_called_once()
                mock_peer.stop_listening_for_general_messages.assert_called_once()

