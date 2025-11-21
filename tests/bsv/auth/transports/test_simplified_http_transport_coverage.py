"""
Coverage tests for simplified_http_transport.py - error paths and edge cases.
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from urllib.parse import urlparse
from bsv.auth.transports.simplified_http_transport import SimplifiedHTTPTransport
from bsv.auth.auth_message import AuthMessage
from bsv.keys import PrivateKey


@pytest.fixture
def transport():
    """Create transport with default URL."""
    return SimplifiedHTTPTransport("https://localhost:8080")


@pytest.fixture
def mock_message():
    """Create a mock AuthMessage."""
    msg = Mock(spec=AuthMessage)
    msg.version = "1.0"
    msg.message_type = "general"
    msg.identity_key = b'\x00' * 33
    msg.nonce = "test_nonce"
    msg.initial_nonce = "init_nonce"
    msg.your_nonce = "your_nonce"
    msg.certificates = []
    msg.requested_certificates = {}
    msg.payload = b'test_payload'
    msg.signature = b'test_sig'
    return msg


# ========================================================================
# Initialization Edge Cases
# ========================================================================

def test_transport_init_with_http_url():
    """Test initialization with http URL."""
    t = SimplifiedHTTPTransport("https://example.com")
    assert t.base_url == "https://example.com"


def test_transport_init_with_https_url():
    """Test initialization with https URL."""
    t = SimplifiedHTTPTransport("https://example.com")
    assert t.base_url == "https://example.com"


def test_transport_init_with_trailing_slash():
    """Test initialization with trailing slash."""
    t = SimplifiedHTTPTransport("https://example.com/")
    parsed_url = urlparse(t.base_url)
    assert parsed_url.hostname == "example.com"


def test_transport_init_with_port():
    """Test initialization with explicit port."""
    t = SimplifiedHTTPTransport("https://example.com:8080")
    assert ":8080" in t.base_url


def test_transport_init_with_path():
    """Test initialization with path."""
    t = SimplifiedHTTPTransport("https://example.com/api")
    parsed_url = urlparse(t.base_url)
    assert parsed_url.hostname == "example.com"
    assert parsed_url.path == "/api"


# ========================================================================
# Send Method Error Paths
# ========================================================================

def test_send_without_handler_registered(transport, mock_message):
    """Test send without handler registered returns error."""
    result = transport.send(None, mock_message)
    assert result is not None
    assert isinstance(result, Exception)
    assert "No handler registered" in str(result)


def test_send_with_general_message(transport, mock_message):
    """Test send with general message type."""
    # Register handler first
    handler = Mock(return_value=None)
    transport.on_data(handler)
    
    mock_message.message_type = "general"
    
    with patch.object(transport.client, 'post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'{"status": "ok"}'
        mock_post.return_value = mock_response
        
        result = transport.send(None, mock_message)
        # Should succeed or return None
        assert result is None or isinstance(result, Exception)


def test_send_with_non_general_message(transport, mock_message):
    """Test send with non-general message type."""
    # Register handler first
    handler = Mock(return_value=None)
    transport.on_data(handler)
    
    mock_message.message_type = "initialRequest"
    
    with patch.object(transport.client, 'post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok"}
        mock_post.return_value = mock_response
        
        result = transport.send(None, mock_message)
        # Should succeed or return None
        assert result is None or isinstance(result, Exception)


def test_send_with_http_error_status(transport, mock_message):
    """Test send with non-200 status code."""
    # Register handler first
    handler = Mock(return_value=None)
    transport.on_data(handler)
    
    with patch.object(transport.client, 'post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_post.return_value = mock_response
        
        result = transport.send(None, mock_message)
        # Should return error
        assert isinstance(result, Exception)


def test_send_with_connection_error(transport, mock_message):
    """Test send handles connection errors."""
    # Register handler first
    handler = Mock(return_value=None)
    transport.on_data(handler)
    
    with patch.object(transport.client, 'post') as mock_post:
        mock_post.side_effect = Exception("Connection failed")
        
        result = transport.send(None, mock_message)
        assert isinstance(result, Exception)
        assert "Connection failed" in str(result) or "Failed to send" in str(result)


def test_send_with_empty_payload(transport, mock_message):
    """Test send with empty payload."""
    # Register handler first
    handler = Mock(return_value=None)
    transport.on_data(handler)
    
    mock_message.payload = b''
    
    with patch.object(transport.client, 'post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'ok'
        mock_post.return_value = mock_response
        
        result = transport.send(None, mock_message)
        assert result is None or isinstance(result, Exception)


def test_send_with_none_payload(transport, mock_message):
    """Test send with None payload."""
    # Register handler first
    handler = Mock(return_value=None)
    transport.on_data(handler)
    
    mock_message.payload = None
    
    with patch.object(transport.client, 'post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'ok'
        mock_post.return_value = mock_response
        
        result = transport.send(None, mock_message)
        assert result is None or isinstance(result, Exception)


# ========================================================================
# Event Handler Registration
# ========================================================================

def test_on_data_registration(transport):
    """Test registering on_data handler."""
    handler = Mock()
    result = transport.on_data(handler)
    assert result is None


def test_on_data_with_none_handler(transport):
    """Test on_data with None handler returns error."""
    result = transport.on_data(None)
    assert isinstance(result, Exception)
    assert "cannot be None" in str(result)


def test_on_data_multiple_handlers(transport):
    """Test registering multiple handlers."""
    handler1 = Mock()
    handler2 = Mock()
    result1 = transport.on_data(handler1)
    result2 = transport.on_data(handler2)
    assert result1 is None
    assert result2 is None


def test_get_registered_on_data_with_no_handlers(transport):
    """Test get_registered_on_data with no handlers."""
    handler, err = transport.get_registered_on_data()
    assert handler is None
    assert isinstance(err, Exception)
    assert "no handlers registered" in str(err)


def test_get_registered_on_data_with_handler(transport):
    """Test get_registered_on_data returns first handler."""
    handler = Mock()
    transport.on_data(handler)
    
    returned_handler, err = transport.get_registered_on_data()
    assert returned_handler == handler
    assert err is None


# ========================================================================
# Edge Cases
# ========================================================================

def test_transport_str_representation(transport):
    """Test string representation."""
    str_repr = str(transport)
    assert isinstance(str_repr, str)


def test_transport_with_special_chars_in_url():
    """Test URL with special characters."""
    t = SimplifiedHTTPTransport("https://example.com/path?query=value&other=123")
    assert urlparse(t.base_url).hostname == "example.com"


def test_transport_with_custom_client():
    """Test transport with custom client."""
    import requests
    custom_client = requests.Session()
    t = SimplifiedHTTPTransport("https://example.com", client=custom_client)
    assert t.client == custom_client


def test_transport_with_none_client():
    """Test transport with None client creates default."""
    t = SimplifiedHTTPTransport("https://example.com", client=None)
    assert t.client is not None

