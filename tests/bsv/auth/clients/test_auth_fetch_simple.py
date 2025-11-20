"""
Tests for bsv/auth/clients/auth_fetch.py

Focuses on initialization and basic functionality with minimal mocking.
"""

import pytest
from unittest.mock import Mock, patch
from requests.exceptions import RetryError
from bsv.auth.clients.auth_fetch import (
    SimplifiedFetchRequestOptions,
    AuthPeer,
    AuthFetch
)
from bsv.auth.requested_certificate_set import RequestedCertificateSet


class TestSimplifiedFetchRequestOptions:
    """Test SimplifiedFetchRequestOptions class."""
    
    def test_init_defaults(self):
        """Test initialization with defaults."""
        opts = SimplifiedFetchRequestOptions()
        assert opts.method == "GET"
        assert opts.headers == {}
        assert opts.body is None
        assert opts.retry_counter is None
    
    def test_init_all_params(self):
        """Test initialization with all parameters."""
        headers = {"Authorization": "Bearer token"}
        body = b"test data"
        opts = SimplifiedFetchRequestOptions(
            method="POST",
            headers=headers,
            body=body,
            retry_counter=3
        )
        assert opts.method == "POST"
        assert opts.headers == headers
        assert opts.body == body
        assert opts.retry_counter == 3
    
    def test_post_method(self):
        """Test POST method."""
        opts = SimplifiedFetchRequestOptions(method="POST")
        assert opts.method == "POST"
    
    def test_put_method(self):
        """Test PUT method."""
        opts = SimplifiedFetchRequestOptions(method="PUT")
        assert opts.method == "PUT"
    
    def test_delete_method(self):
        """Test DELETE method."""
        opts = SimplifiedFetchRequestOptions(method="DELETE")
        assert opts.method == "DELETE"
    
    def test_headers_empty_dict(self):
        """Test headers default to empty dict."""
        opts = SimplifiedFetchRequestOptions()
        assert isinstance(opts.headers, dict)
        assert len(opts.headers) == 0


class TestAuthPeer:
    """Test AuthPeer class."""
    
    def test_init(self):
        """Test AuthPeer initialization."""
        peer = AuthPeer()
        assert peer.peer is None
        assert peer.identity_key == ""
        assert peer.supports_mutual_auth is None
        assert isinstance(peer.pending_certificate_requests, list)
        assert len(peer.pending_certificate_requests) == 0
    
    def test_set_peer_attribute(self):
        """Test setting peer attribute."""
        auth_peer = AuthPeer()
        mock_peer = Mock()
        auth_peer.peer = mock_peer
        assert auth_peer.peer == mock_peer
    
    def test_set_identity_key(self):
        """Test setting identity key."""
        auth_peer = AuthPeer()
        auth_peer.identity_key = "test123"
        assert auth_peer.identity_key == "test123"
    
    def test_set_supports_mutual_auth_true(self):
        """Test setting supports_mutual_auth to True."""
        auth_peer = AuthPeer()
        auth_peer.supports_mutual_auth = True
        assert auth_peer.supports_mutual_auth is True
    
    def test_set_supports_mutual_auth_false(self):
        """Test setting supports_mutual_auth to False."""
        auth_peer = AuthPeer()
        auth_peer.supports_mutual_auth = False
        assert auth_peer.supports_mutual_auth is False
    
    def test_pending_requests_append(self):
        """Test appending to pending certificate requests."""
        auth_peer = AuthPeer()
        auth_peer.pending_certificate_requests.append(True)
        assert len(auth_peer.pending_certificate_requests) == 1


class TestAuthFetchInit:
    """Test AuthFetch initialization."""
    
    def test_init_with_session_manager(self):
        """Test initialization with provided session manager."""
        mock_wallet = Mock()
        mock_certs = Mock(spec=RequestedCertificateSet)
        mock_sm = Mock()
        
        auth_fetch = AuthFetch(mock_wallet, mock_certs, mock_sm)
        
        assert auth_fetch.wallet == mock_wallet
        assert auth_fetch.requested_certificates == mock_certs
        assert auth_fetch.session_manager == mock_sm
        assert isinstance(auth_fetch.callbacks, dict)
        assert isinstance(auth_fetch.certificates_received, list)
        assert isinstance(auth_fetch.peers, dict)
    
    def test_init_creates_default_session_manager(self):
        """Test that default session manager is created if not provided."""
        mock_wallet = Mock()
        mock_certs = Mock()
        
        with patch('bsv.auth.clients.auth_fetch.DefaultSessionManager') as mock_class:
            mock_sm = Mock()
            mock_class.return_value = mock_sm
            
            auth_fetch = AuthFetch(mock_wallet, mock_certs)
            
            assert auth_fetch.session_manager == mock_sm
            mock_class.assert_called_once()
    
    def test_init_empty_collections(self):
        """Test that collections are initialized empty."""
        mock_wallet = Mock()
        mock_certs = Mock()
        auth_fetch = AuthFetch(mock_wallet, mock_certs)
        
        assert len(auth_fetch.callbacks) == 0
        assert len(auth_fetch.certificates_received) == 0
        assert len(auth_fetch.peers) == 0
    
    def test_logger_initialized(self):
        """Test that logger is initialized."""
        mock_wallet = Mock()
        mock_certs = Mock()
        auth_fetch = AuthFetch(mock_wallet, mock_certs)
        
        assert auth_fetch.logger is not None
        assert auth_fetch.logger.name == "AuthHTTP"


class TestAuthFetchRetry:
    """Test retry logic in AuthFetch."""
    
    def test_fetch_retry_counter_zero_raises(self):
        """Test fetch with retry counter at 0 raises RetryError."""
        mock_wallet = Mock()
        mock_certs = Mock()
        auth_fetch = AuthFetch(mock_wallet, mock_certs)
        
        config = SimplifiedFetchRequestOptions(retry_counter=0)
        
        with pytest.raises(RetryError):
            auth_fetch.fetch(None, "https://example.com", config)
    
    def test_retry_error_message(self):
        """Test RetryError message content."""
        mock_wallet = Mock()
        mock_certs = Mock()
        auth_fetch = AuthFetch(mock_wallet, mock_certs)
        
        config = SimplifiedFetchRequestOptions(retry_counter=0)
        
        with pytest.raises(RetryError, match="maximum number of retries"):
            auth_fetch.fetch(None, "https://example.com", config)


class TestAuthFetchHelpers:
    """Test helper methods and URL parsing."""
    
    def test_url_parsing_https(self):
        """Test URL parsing for HTTPS."""
        import urllib.parse
        url = "https://api.example.com:443/v1/endpoint?param=value"
        parsed = urllib.parse.urlparse(url)
        assert parsed.scheme == "https"
        assert parsed.netloc == "api.example.com:443"
    
    def test_url_parsing_http(self):
        """Test URL parsing for HTTP."""
        import urllib.parse
        url = "http://localhost:8080/test"  # noqa: S113 - Testing URL parsing functionality with localhost
        parsed = urllib.parse.urlparse(url)
        assert parsed.scheme == "http"
        assert parsed.netloc == "localhost:8080"
    
    def test_base_url_extraction(self):
        """Test extracting base URL from full URL."""
        import urllib.parse
        url = "https://example.com:9000/path/to/resource?query=1"
        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        assert base_url == "https://example.com:9000"
    
    def test_certificates_received_extend(self):
        """Test extending certificates_received list."""
        mock_wallet = Mock()
        mock_certs = Mock()
        auth_fetch = AuthFetch(mock_wallet, mock_certs)
        
        mock_cert1 = Mock()
        mock_cert2 = Mock()
        auth_fetch.certificates_received.extend([mock_cert1, mock_cert2])
        
        assert len(auth_fetch.certificates_received) == 2
        assert mock_cert1 in auth_fetch.certificates_received


class TestAuthFetchMethodExistence:
    """Test that expected methods exist."""
    
    def test_has_fetch_method(self):
        """Test that fetch method exists."""
        mock_wallet = Mock()
        mock_certs = Mock()
        auth_fetch = AuthFetch(mock_wallet, mock_certs)
        assert hasattr(auth_fetch, 'fetch')
        assert callable(auth_fetch.fetch)
    
    def test_has_serialize_request(self):
        """Test that serialize_request method exists."""
        mock_wallet = Mock()
        mock_certs = Mock()
        auth_fetch = AuthFetch(mock_wallet, mock_certs)
        assert hasattr(auth_fetch, 'serialize_request')
    
    def test_has_method_create_peer(self):
        """Test that object can create peers."""
        mock_wallet = Mock()
        mock_certs = Mock()
        auth_fetch = AuthFetch(mock_wallet, mock_certs)
        # Test peers dictionary can be used
        auth_fetch.peers["test"] = AuthPeer()
        assert "test" in auth_fetch.peers
    
    def test_has_handle_fetch_and_validate(self):
        """Test that handle_fetch_and_validate method exists."""
        mock_wallet = Mock()
        mock_certs = Mock()
        auth_fetch = AuthFetch(mock_wallet, mock_certs)
        assert hasattr(auth_fetch, 'handle_fetch_and_validate')
    
    def test_has_handle_payment_and_retry(self):
        """Test that handle_payment_and_retry method exists."""
        mock_wallet = Mock()
        mock_certs = Mock()
        auth_fetch = AuthFetch(mock_wallet, mock_certs)
        assert hasattr(auth_fetch, 'handle_payment_and_retry')
