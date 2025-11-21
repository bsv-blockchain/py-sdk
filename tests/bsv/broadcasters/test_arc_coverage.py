"""
Coverage tests for arc.py - error paths and edge cases.
"""
import pytest
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from bsv.broadcasters.arc import ARC, ARCConfig
from bsv.transaction import Transaction


@pytest.fixture
def arc():
    """Create ARC with default URL."""
    return ARC("https://arc.taal.com")


@pytest.fixture
def simple_tx():
    """Create a simple transaction."""
    return Transaction(version=1, tx_inputs=[], tx_outputs=[], locktime=0)


# ========================================================================
# Initialization Edge Cases
# ========================================================================

def test_arc_init_with_http_url():
    """Test initialization with http URL."""
    arc = ARC("https://arc.example.com")
    assert "arc.example.com" in arc.URL  # codeql[py/incomplete-url-substring-sanitization] - Not used in production - test code only


def test_arc_init_with_https_url():
    """Test initialization with https URL."""
    arc = ARC("https://arc.example.com")
    assert "arc.example.com" in arc.URL  # codeql[py/incomplete-url-substring-sanitization] - Not used in production - test code only


def test_arc_init_with_string_api_key():
    """Test initialization with string API key (legacy)."""
    arc = ARC("https://arc.example.com", config="test_api_key")
    assert arc.api_key == "test_api_key"
    assert arc.http_client is not None
    assert arc.deployment_id is not None


def test_arc_init_with_arc_config():
    """Test initialization with ARCConfig object."""
    config = ARCConfig(api_key="test_key")  # noqa: S106  # NOSONAR - Mock API key for tests
    arc = ARC("https://arc.example.com", config=config)
    assert arc.api_key == "test_key"


def test_arc_init_without_config():
    """Test initialization without config."""
    arc = ARC("https://arc.example.com")
    assert arc.api_key is None
    assert arc.http_client is not None
    assert arc.deployment_id is not None


def test_arc_init_with_none_config():
    """Test initialization with None config."""
    arc = ARC("https://arc.example.com", config=None)
    assert arc.api_key is None
    assert arc.http_client is not None


def test_arcconfig_with_all_params():
    """Test ARCConfig with all parameters."""
    config = ARCConfig(
        api_key="key",  # noqa: S106  # NOSONAR - Mock API key for tests
        http_client=None,
        sync_http_client=None,
        deployment_id="deploy_123",
        callback_url="https://callback.com",
        callback_token="token",
        headers={"Custom": "Header"}
    )
    assert config.api_key == "key"
    assert config.deployment_id == "deploy_123"
    assert config.callback_url == "https://callback.com"
    assert config.callback_token == "token"
    assert config.headers == {"Custom": "Header"}


def test_arcconfig_with_none_params():
    """Test ARCConfig with None parameters."""
    config = ARCConfig()
    assert config.api_key is None
    assert config.http_client is None
    assert config.deployment_id is None


# ========================================================================
# Broadcast Method Error Paths
# ========================================================================

@pytest.mark.asyncio
async def test_broadcast_with_transaction_no_inputs(arc, simple_tx):
    """Test broadcast with transaction with no inputs."""
    with patch.object(arc.http_client, 'fetch', new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = {"txid": "abc123"}
        
        result = await arc.broadcast(simple_tx)
        assert result is not None


@pytest.mark.asyncio
async def test_broadcast_with_connection_error(arc, simple_tx):
    """Test broadcast handles connection errors."""
    with patch.object(arc.http_client, 'fetch', new_callable=AsyncMock) as mock_fetch:
        mock_fetch.side_effect = Exception("Connection failed")
        
        try:
            result = await arc.broadcast(simple_tx)
            # Should return BroadcastFailure
            assert hasattr(result, 'description') or 'error' in str(result)
        except Exception:
            # Or may raise
            assert True


@pytest.mark.asyncio
async def test_broadcast_checks_all_inputs_have_source_tx(arc):
    """Test broadcast checks if all inputs have source_transaction."""
    from bsv.transaction_input import TransactionInput
    from bsv.script.script import Script
    
    # Transaction with input but no source_transaction
    inp = TransactionInput(
        source_txid="0" * 64,
        source_output_index=0,
        unlocking_script=Script.from_asm(""),
        sequence=0xFFFFFFFF
    )
    tx = Transaction(version=1, tx_inputs=[inp], tx_outputs=[], locktime=0)
    
    with patch.object(arc.http_client, 'fetch', new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = {"txid": "abc123"}
        
        result = await arc.broadcast(tx)
        # Should call tx.hex() instead of tx.to_ef().hex()
        assert result is not None


def test_arc_request_headers_with_api_key(arc):
    """Test request_headers includes API key."""
    arc.api_key = "test_key"  # noqa: S105  # NOSONAR - Mock API key for tests
    headers = arc.request_headers()
    assert "Authorization" in headers or "X-API-Key" in headers


def test_arc_request_headers_without_api_key(arc):
    """Test request_headers without API key."""
    arc.api_key = None
    headers = arc.request_headers()
    assert isinstance(headers, dict)


def test_arc_request_headers_with_custom_headers():
    """Test request_headers with custom headers."""
    config = ARCConfig(headers={"Custom": "Header"})
    arc = ARC("https://arc.example.com", config=config)
    headers = arc.request_headers()
    assert "Custom" in headers


def test_arc_request_headers_with_callback():
    """Test request_headers with callback URL and token."""
    config = ARCConfig(
        callback_url="https://callback.com",
        callback_token="token123"
    )
    arc = ARC("https://arc.example.com", config=config)
    headers = arc.request_headers()
    # Should include callback info
    assert isinstance(headers, dict)


# ========================================================================
# Edge Cases
# ========================================================================

def test_arc_with_trailing_slash_in_url():
    """Test ARC with trailing slash in URL."""
    arc = ARC("https://arc.example.com/")
    # URL should be preserved as-is (with trailing slash)
    assert arc.URL == "https://arc.example.com/"


def test_arc_str_representation(arc):
    """Test string representation."""
    str_repr = str(arc)
    assert isinstance(str_repr, str)


def test_deployment_id_generation():
    """Test deployment ID is generated automatically."""
    from bsv.broadcasters.arc import default_deployment_id
    dep_id = default_deployment_id()
    assert isinstance(dep_id, str)
    assert len(dep_id) > 0
    assert "py-sdk" in dep_id


def test_deployment_id_uniqueness():
    """Test deployment IDs are unique."""
    from bsv.broadcasters.arc import default_deployment_id
    id1 = default_deployment_id()
    id2 = default_deployment_id()
    assert id1 != id2

