"""
Coverage tests for AuthFetch - binary parsing, JSON fallback, retry logic, and payment flow.
"""
import pytest
import base64
import json
import struct
import os
from unittest.mock import Mock, patch

from bsv.auth.clients.auth_fetch import AuthFetch, SimplifiedFetchRequestOptions
from bsv.auth.transports.simplified_http_transport import SimplifiedHTTPTransport
from bsv.auth.peer import PeerOptions
from bsv.auth.session_manager import DefaultSessionManager
from bsv.keys import PrivateKey



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


# ========================================================================
# Binary Response Parsing Tests
# ========================================================================

def test_parse_binary_general_response_success(auth_fetch):
    """Test successful binary response parsing."""
    # Create a mock binary response: nonce(32) + status(8) + headers(1) + body
    request_nonce = b'A' * 32
    response_nonce = request_nonce  # Echo back
    status_code = 200
    headers = {b'content-type': b'application/json'}
    body = b'{"result": "success"}'

    # Build binary payload
    payload = bytearray()
    payload.extend(response_nonce)
    payload.extend(struct.pack('<Q', status_code))  # varint status
    payload.extend(struct.pack('<Q', len(headers)))  # header count

    # Add headers
    for key, value in headers.items():
        payload.extend(struct.pack('<Q', len(key)))
        payload.extend(key)
        payload.extend(struct.pack('<Q', len(value)))
        payload.extend(value)

    # Add body
    payload.extend(struct.pack('<Q', len(body)))
    payload.extend(body)

    # Mock the _parse_general_response method inputs
    result = auth_fetch._parse_general_response(
    sender_public_key=None,
    payload=bytes(payload),
    request_nonce_b64=base64.b64encode(request_nonce).decode(),
    url_str="http://test.com",  # NOSONAR - Test URL, not used in production
    config=SimplifiedFetchRequestOptions()
    )

    assert result is not None
    assert result.status_code == status_code
    assert result.url == "http://test.com"  # NOSONAR - Test URL, not used in production


def test_parse_binary_general_response_nonce_mismatch(auth_fetch):
    """Test binary parsing fails with nonce mismatch."""
    request_nonce = b'A' * 32
    wrong_nonce = b'B' * 32

    # Build payload with wrong nonce
    payload = bytearray()
    payload.extend(wrong_nonce)
    payload.extend(struct.pack('<Q', 200))  # status
    payload.extend(struct.pack('<Q', 0))   # no headers
    payload.extend(struct.pack('<Q', 0))   # empty body

    result = auth_fetch._parse_general_response(
    sender_public_key=None,
    payload=bytes(payload),
    request_nonce_b64=base64.b64encode(request_nonce).decode(),
    url_str="http://test.com",  # NOSONAR - Test URL, not used in production
    config=SimplifiedFetchRequestOptions()
    )

    assert result is None


def test_parse_binary_general_response_short_payload(auth_fetch):
    """Test binary parsing fails with payload too short."""
    short_payload = b'too_short'

    result = auth_fetch._parse_general_response(
    sender_public_key=None,
    payload=short_payload,
    request_nonce_b64=base64.b64encode(b'A' * 32).decode(),
    url_str="http://test.com",  # NOSONAR - Test URL, not used in production
    config=SimplifiedFetchRequestOptions()
    )

    assert result is None


# ========================================================================
# JSON Fallback Parsing Tests
# ========================================================================

def test_parse_json_fallback_success(auth_fetch):
    """Test JSON fallback parsing success."""
    json_payload = json.dumps({
    'status_code': 200,
    'headers': {'content-type': 'application/json'},
    'body': '{"result": "success"}'
    }).encode('utf-8')

    result = auth_fetch._parse_general_response(
    sender_public_key=None,
    payload=json_payload,
    request_nonce_b64=base64.b64encode(b'A' * 32).decode(),
    url_str="http://test.com",  # NOSONAR - Test URL, not used in production
    config=SimplifiedFetchRequestOptions()
    )

    assert result is not None
    assert result.status_code == 200
    assert 'content-type' in result.headers


def test_parse_json_fallback_invalid_json(auth_fetch):
    """Test JSON fallback fails with invalid JSON."""
    invalid_json = b'invalid json content'

    result = auth_fetch._parse_general_response(
    sender_public_key=None,
    payload=invalid_json,
    request_nonce_b64=base64.b64encode(b'A' * 32).decode(),
    url_str="http://test.com",  # NOSONAR - Test URL, not used in production
    config=SimplifiedFetchRequestOptions()
    )

    assert result is None


# ========================================================================
# Retry Logic Tests
# ========================================================================

def test_check_retry_limit_success(auth_fetch):
    """Test retry limit check allows retries when available."""
    config = SimplifiedFetchRequestOptions(retry_counter=3)

    # Should not raise
    auth_fetch._check_retry_limit(config)
    assert config.retry_counter == 2


def test_check_retry_limit_exhausted(auth_fetch):
    """Test retry limit check raises when exhausted."""
    config = SimplifiedFetchRequestOptions(retry_counter=0)

    with pytest.raises(Exception, match="maximum number of retries"):
        auth_fetch._check_retry_limit(config)


def test_handle_peer_error_session_not_found(auth_fetch, mock_wallet):
    """Test peer error handling for 'Session not found' triggers retry."""
    # Mock the callbacks
    callbacks = {
    'test_nonce': {
    'resolve': Mock(),
    'reject': Mock()
    }
    }
    auth_fetch.callbacks = callbacks

    # Add a peer to the peers dict so it can be deleted
    auth_fetch.peers["http://test.com"] = Mock()  # NOSONAR - Test URL, not used in production

    # Mock fetch method to return success
    with patch.object(auth_fetch, 'fetch', return_value='retry_result'):
        auth_fetch._handle_peer_error(
            Exception("Session not found for nonce"),
            "http://test.com",  # NOSONAR - Test URL, not used in production
            "http://test.com",  # NOSONAR - Test URL, not used in production
            SimplifiedFetchRequestOptions(),
            "test_nonce",
            Mock()
        )

    # Should have called resolve with retry result
    callbacks['test_nonce']['resolve'].assert_called_once_with('retry_result')

    # Should have removed the peer
    assert "http://test.com" not in auth_fetch.peers  # NOSONAR - Test URL, not used in production


def test_handle_peer_error_http_auth_failed(auth_fetch):
    """Test peer error handling for HTTP auth failure falls back to regular HTTP."""
    # Mock the callbacks
    callbacks = {
    'test_nonce': {
    'resolve': Mock(),
    'reject': Mock()
    }
    }
    auth_fetch.callbacks = callbacks

    mock_peer = Mock()
    fallback_response = Mock()

    # Mock handle_fetch_and_validate to return success
    with patch.object(auth_fetch, 'handle_fetch_and_validate', return_value=fallback_response):
        auth_fetch._handle_peer_error(
    Exception("HTTP server failed to authenticate"),
    "http://test.com",  # NOSONAR - Test URL, not used in production
    "http://test.com",  # NOSONAR - Test URL, not used in production
    SimplifiedFetchRequestOptions(),
    "test_nonce",
    mock_peer
    )

    # Should have called resolve with fallback response
    callbacks['test_nonce']['resolve'].assert_called_once_with(fallback_response)


# ========================================================================
# Payment Flow Tests
# ========================================================================

def test_validate_payment_headers_success(auth_fetch):
    """Test payment header validation success."""
    response = Mock()
    response.headers = {
    'x-bsv-payment-version': '1.0',
    'x-bsv-payment-satoshis-required': '1000',
    'x-bsv-auth-identity-key': 'server_key',
    'x-bsv-payment-derivation-prefix': 'prefix'
    }

    result = auth_fetch._validate_payment_headers(response)

    assert result['satoshis_required'] == 1000
    assert result['server_identity_key'] == 'server_key'
    assert result['derivation_prefix'] == 'prefix'


def test_validate_payment_headers_missing_version(auth_fetch):
    """Test payment header validation fails with missing version."""
    response = Mock()
    response.headers = {
    'x-bsv-payment-satoshis-required': '1000',
    }

    with pytest.raises(ValueError, match="unsupported.*version"):
        auth_fetch._validate_payment_headers(response)


def test_validate_payment_headers_invalid_satoshis(auth_fetch):
    """Test payment header validation fails with invalid satoshis."""
    response = Mock()
    response.headers = {
    'x-bsv-payment-version': '1.0',
    'x-bsv-payment-satoshis-required': '-100',
    }

    with pytest.raises(ValueError, match="invalid.*satoshis"):
        auth_fetch._validate_payment_headers(response)


def test_generate_derivation_suffix(auth_fetch):
    """Test derivation suffix generation."""
    with patch('os.urandom', return_value=b'\x01' * 8):
        suffix = auth_fetch._generate_derivation_suffix()
        assert len(base64.b64decode(suffix)) == 8


def test_create_payment_transaction(auth_fetch, mock_wallet):
    """Test payment transaction creation."""
    # Mock the required methods
    auth_fetch._get_payment_public_key = Mock(return_value='mock_pubkey')
    auth_fetch._build_locking_script = Mock(return_value=b'mock_script')

    result = auth_fetch._create_payment_transaction(
    "http://test.com",  # NOSONAR - Test URL, not used in production
    {'satoshis_required': 1000, 'server_identity_key': 'server_key', 'derivation_prefix': 'prefix'},
    'suffix',
    b'mock_script'
    )

    assert result is not None


# ========================================================================
# Integration Tests with Local Server
# ========================================================================

def test_fetch_with_local_server(auth_fetch):
    """Test fetch response structure using mocked HTTP fallback."""
    # Test a simple fetch using mocked HTTP fallback
    config = SimplifiedFetchRequestOptions(
    method="GET",
    headers={"test": "value"}
    )

    # Mock the fallback HTTP response since auth server setup is complex
    mock_response = type('MockResponse', (), {
        'status_code': 200,
        'headers': {'content-type': 'application/json'},
        'text': '{"status": "ok"}',
        'json': lambda: {"status": "ok"}
    })()

    with patch.object(auth_fetch, '_try_fallback_http', return_value=mock_response):
        response = auth_fetch.fetch("http://mock-server/health", config)  # NOSONAR - Test URL, not used in production

    # The response should be a requests-like object
    assert hasattr(response, 'status_code')
    assert response.status_code == 200


def test_peer_creation_and_certificates_listener(auth_fetch, mock_wallet):
    """Test peer creation and certificates listener setup."""
    base_url = "http://test.com"  # NOSONAR - Test URL, not used in production

    # Initially no peers
    assert base_url not in auth_fetch.peers

    # Create peer
    peer = auth_fetch._get_or_create_peer(base_url)

    # Should have created a peer
    assert base_url in auth_fetch.peers
    assert peer == auth_fetch.peers[base_url]

    # Should have set up certificates listener
    assert hasattr(peer.peer, 'listen_for_certificates_received')


def test_serialize_request_binary_format(auth_fetch):
    """Test request serialization to binary format."""
    method = "POST"
    headers = {"content-type": "application/json", "x-custom": "value"}
    body = b'{"test": "data"}'
    parsed_url = Mock()
    parsed_url.path = "/api/test"
    parsed_url.query = ""
    request_nonce = b'N' * 32

    result = auth_fetch.serialize_request(method, headers, body, parsed_url, request_nonce)

    # Should return bytes
    assert isinstance(result, bytes)
    assert len(result) > 0

    # Should start with nonce
    assert result.startswith(request_nonce)


def test_select_headers_filters_correctly(auth_fetch):
    """Test header selection for serialization."""
    headers = {
    "content-type": "application/json",
    "authorization": "Bearer token",
    "x-bsv-custom": "bsv-value",
    "x-bsv-auth-internal": "filtered-out",  # Should be filtered
    "normal-header": "normal-value",       # Should be filtered
    }

    selected = auth_fetch._select_headers(headers)

    # Should include content-type, authorization, and x-bsv-custom (but not x-bsv-auth*)
    expected_keys = ["content-type", "authorization", "x-bsv-custom"]
    actual_keys = [key for key, value in selected]

    for key in expected_keys:
        assert key in actual_keys

    # Should not include filtered headers
    assert "x-bsv-auth-internal" not in actual_keys
    assert "normal-header" not in actual_keys


def test_determine_body_adds_json_for_post(auth_fetch):
    """Test body determination adds empty JSON for POST without body."""
    method = "POST"
    body = b""  # Empty body

    result = auth_fetch._determine_body(body, method, [("content-type", "application/json")])

    assert result == b'{}'


def test_determine_body_preserves_existing_body(auth_fetch):
    """Test body determination preserves existing body."""
    method = "POST"
    headers = []
    body = b'existing body'

    result = auth_fetch._determine_body(body, method, headers)

    assert result == body