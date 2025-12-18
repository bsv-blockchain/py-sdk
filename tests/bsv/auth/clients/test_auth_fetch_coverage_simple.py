"""
Coverage tests for AuthFetch - key missing branches.
"""
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
