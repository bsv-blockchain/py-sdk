"""
Coverage tests for AuthFetch - binary parsing, JSON fallback, retry logic, and payment flow.
"""
import pytest
from unittest.mock import Mock, patch

from bsv.auth.clients.auth_fetch import SimplifiedFetchRequestOptions

# Import shared tests from common module
from .test_auth_fetch_coverage_common import (
    test_parse_binary_general_response_success,
    test_parse_binary_general_response_nonce_mismatch,
    test_parse_binary_general_response_short_payload,
    test_parse_json_fallback_success,
    test_parse_json_fallback_invalid_json,
    test_check_retry_limit_success,
    test_check_retry_limit_exhausted,
    test_handle_peer_error_session_not_found,
    test_handle_peer_error_http_auth_failed,
    test_validate_payment_headers_success,
    test_validate_payment_headers_missing_version,
    test_validate_payment_headers_invalid_satoshis,
    test_generate_derivation_suffix,
    test_peer_creation_and_certificates_listener,
    test_serialize_request_binary_format,
    test_select_headers_filters_correctly,
    test_determine_body_adds_json_for_post,
    test_determine_body_preserves_existing_body,
)


# ========================================================================
# Additional Tests (not in simple version)
# ========================================================================

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
