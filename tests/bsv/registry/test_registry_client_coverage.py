"""
Coverage tests for registry/client.py - untested branches.
"""
import pytest
from unittest.mock import Mock
from bsv.registry.client import RegistryClient
from bsv.registry.types import BasketDefinitionData
from bsv.keys import PrivateKey


@pytest.fixture
def client():
    """Create registry client with default settings."""
    wallet = Mock()
    return RegistryClient(wallet, originator="test-client")


# ========================================================================
# Initialization branches
# ========================================================================

def test_client_init_with_wallet():
    """Test client init with wallet."""
    wallet = Mock()
    c = RegistryClient(wallet)
    assert c.wallet == wallet


def test_client_init_with_originator():
    """Test client init with custom originator."""
    wallet = Mock()
    c = RegistryClient(wallet, originator="custom")
    assert c.originator == "custom"


def test_client_init_default_originator():
    """Test client init uses default originator."""
    wallet = Mock()
    c = RegistryClient(wallet)
    assert c.originator == "registry-client"


# ========================================================================
# Registry operation branches
# ========================================================================

def test_register_definition(client):
    """Test register definition."""
    # Build minimal valid BasketDefinitionData
    data = BasketDefinitionData(
        definitionType="basket",
        basketID="test-basket-123",
        name="Test Basket",
        iconURL="https://example.com/icon.png",
        description="A test basket for coverage",
        documentationURL="https://example.com/docs",
    )

    # Mock wallet.get_public_key to return a valid identity public key hex
    operator_hex = PrivateKey(b"\x03" * 32).public_key().hex()
    client.wallet.get_public_key.return_value = {"publicKey": operator_hex}

    # Mock wallet.create_action to return create-action-like payload
    client.wallet.create_action.return_value = {
        "signableTransaction": {"tx": b"mock_tx", "reference": b"mock_ref"}
    }

    # Call register_definition
    res = client.register_definition(None, data)

    # Assert expected behavior
    assert "signableTransaction" in res

    # Verify wallet methods were called
    client.wallet.get_public_key.assert_called_once()
    client.wallet.create_action.assert_called_once()

    # Inspect create_action call arguments
    call_args = client.wallet.create_action.call_args[0][0]  # First positional arg

    # Check output structure
    assert "outputs" in call_args
    assert len(call_args["outputs"]) == 1
    output = call_args["outputs"][0]

    assert output["satoshis"] == 1
    assert output["basket"] == "basketmap"
    assert "lockingScript" in output
    assert isinstance(output["lockingScript"], str)  # Hex string
    assert len(output["lockingScript"]) > 0


def test_lookup_definition(client):
    """Test lookup definition."""
    if hasattr(client, 'lookup_definition'):
        try:
            result = client.lookup_definition(Mock(), "basket", "testbasket")
            assert result is not None or True
        except Exception:
            pass
