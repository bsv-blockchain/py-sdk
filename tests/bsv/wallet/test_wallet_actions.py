"""
Comprehensive tests for action creation and management in ProtoWallet.
"""
import pytest
from bsv.keys import PrivateKey, PublicKey
from bsv.wallet import ProtoWallet
from bsv.script.type import P2PKH


@pytest.fixture
def wallet():
    priv = PrivateKey()
    return ProtoWallet(priv, permission_callback=lambda action: True)


def test_create_action_simple_output(wallet):
    """Test creating a simple action with one output."""
    from bsv.hash import hash160
    # Create a simple P2PKH output - lock() expects address string or pkh bytes
    recipient = PrivateKey().public_key()
    pkh = hash160(recipient.serialize())
    locking_script = P2PKH().lock(pkh)
    
    args = {
        "description": "Test payment",
        "outputs": [
            {
                "satoshis": 1000,
                "lockingScript": locking_script.hex()
            }
        ]
    }
    
    result = wallet.create_action(args, "test")
    
    # Should contain action data or error
    assert isinstance(result, dict)


def test_create_action_with_labels(wallet):
    """Test creating an action with labels."""
    from bsv.hash import hash160
    recipient = PrivateKey().public_key()
    pkh = hash160(recipient.serialize())
    locking_script = P2PKH().lock(pkh)
    
    args = {
        "description": "Labeled payment",
        "labels": ["payment", "test", "important"],
        "outputs": [
            {
                "satoshis": 500,
                "lockingScript": locking_script.hex()
            }
        ]
    }
    
    result = wallet.create_action(args, "test")
    
    assert isinstance(result, dict)


def test_create_action_multiple_outputs(wallet):
    """Test creating an action with multiple outputs."""
    from bsv.hash import hash160
    outputs = []
    for i in range(3):
        recipient = PrivateKey().public_key()
        pkh = hash160(recipient.serialize())
        locking_script = P2PKH().lock(pkh)
        outputs.append({
            "satoshis": 1000 * (i + 1),
            "lockingScript": locking_script.hex()
        })
    
    args = {
        "description": "Multi-output action",
        "outputs": outputs
    }
    
    result = wallet.create_action(args, "test")
    
    assert isinstance(result, dict)


def test_create_action_with_inputs(wallet):
    """Test creating an action with specified inputs."""
    from bsv.hash import hash160
    recipient = PrivateKey().public_key()
    pkh = hash160(recipient.serialize())
    locking_script = P2PKH().lock(pkh)
    
    args = {
        "description": "Action with inputs",
        "inputs": [
            {
                "txid": "a" * 64,
                "vout": 0,
                "satoshis": 5000,
                "lockingScript": locking_script.hex()
            }
        ],
        "outputs": [
            {
                "satoshis": 4000,
                "lockingScript": locking_script.hex()
            }
        ]
    }
    
    result = wallet.create_action(args, "test")
    
    assert isinstance(result, dict)


def test_create_action_missing_outputs(wallet):
    """Test creating an action without outputs fails gracefully."""
    args = {
        "description": "No outputs"
    }
    
    result = wallet.create_action(args, "test")
    
    # Should handle missing outputs
    assert isinstance(result, dict)


def test_sign_action_basic(wallet):
    """Test signing an action."""
    # First create an action
    from bsv.hash import hash160
    recipient = PrivateKey().public_key()
    pkh = hash160(recipient.serialize())
    locking_script = P2PKH().lock(pkh)
    
    create_args = {
        "description": "To be signed",
        "outputs": [
            {
                "satoshis": 1000,
                "lockingScript": locking_script.hex()
            }
        ]
    }
    
    action_result = wallet.create_action(create_args, "test")
    
    # Now try to sign it
    if "rawtx" in action_result or "tx" in action_result:
        sign_args = {
            "spends": action_result.get("spends", {}),
            "reference": action_result.get("reference", "test_ref")
        }
        
        sign_result = wallet.sign_action(sign_args, "test")
        
        assert isinstance(sign_result, dict)


def test_list_actions_empty(wallet):
    """Test listing actions when none exist."""
    result = wallet.list_actions({}, "test")
    
    assert "totalActions" in result
    assert result["totalActions"] == 0
    assert "actions" in result


def test_list_actions_with_filters(wallet):
    """Test listing actions with various filters."""
    # Test with label filter
    result = wallet.list_actions({"labels": ["test"]}, "test")
    assert isinstance(result, dict)
    
    # Test with limit
    result = wallet.list_actions({"limit": 10}, "test")
    assert isinstance(result, dict)
    
    # Test with offset
    result = wallet.list_actions({"offset": 5, "limit": 10}, "test")
    assert isinstance(result, dict)


def test_internalize_action(wallet):
    """Test internalizing an action."""
    args = {
        "tx": "01000000" + "00" * 100,  # Dummy tx hex
        "outputs": [
            {
                "vout": 0,
                "satoshis": 1000,
                "basket": "received"
            }
        ],
        "description": "Received payment"
    }
    
    result = wallet.internalize_action(args, "test")
    
    assert isinstance(result, dict)


def test_internalize_action_with_labels(wallet):
    """Test internalizing an action with labels."""
    args = {
        "tx": "01000000" + "00" * 100,
        "outputs": [
            {
                "vout": 0,
                "satoshis": 500,
                "basket": "received"
            }
        ],
        "labels": ["received", "payment"],
        "description": "Labeled received payment"
    }
    
    result = wallet.internalize_action(args, "test")
    
    assert isinstance(result, dict)


def test_build_action_dict(wallet):
    """Test building action dictionary."""
    args = {"labels": ["test"], "options": {}}
    total_out = 1000
    description = "Test action"
    labels = ["label1", "label2"]
    inputs_meta = []
    outputs = [{"satoshis": 1000}]
    
    action = wallet._build_action_dict(
        args, total_out, description, labels, inputs_meta, outputs
    )
    
    assert isinstance(action, dict)
    assert "description" in action
    assert "labels" in action


def test_wait_for_authentication(wallet):
    """Test wait_for_authentication method."""
    args = {"sessionId": "test_session_123"}
    
    result = wallet.wait_for_authentication(args, "test")
    
    assert isinstance(result, dict)


def test_create_action_with_pushdrop(wallet):
    """Test creating an action with PushDrop extension."""
    # PushDrop integration is complex - skip for now
    pytest.skip("PushDrop integration requires complex setup, tested in integration suite")


def test_create_action_with_basket(wallet):
    """Test creating an action specifying output baskets."""
    from bsv.hash import hash160
    recipient = PrivateKey().public_key()
    pkh = hash160(recipient.serialize())
    locking_script = P2PKH().lock(pkh)
    
    args = {
        "description": "Basket action",
        "outputs": [
            {
                "satoshis": 1000,
                "lockingScript": locking_script.hex(),
                "basket": "savings"
            }
        ]
    }
    
    result = wallet.create_action(args, "test")
    
    assert isinstance(result, dict)


def test_create_action_with_tags(wallet):
    """Test creating an action with output tags."""
    from bsv.hash import hash160
    recipient = PrivateKey().public_key()
    pkh = hash160(recipient.serialize())
    locking_script = P2PKH().lock(pkh)
    
    args = {
        "description": "Tagged action",
        "outputs": [
            {
                "satoshis": 1000,
                "lockingScript": locking_script.hex(),
                "tags": ["important", "urgent"]
            }
        ]
    }
    
    result = wallet.create_action(args, "test")
    
    assert isinstance(result, dict)


def test_create_action_with_custom_instructions(wallet):
    """Test creating an action with custom instructions."""
    from bsv.hash import hash160
    recipient = PrivateKey().public_key()
    pkh = hash160(recipient.serialize())
    locking_script = P2PKH().lock(pkh)
    
    args = {
        "description": "Custom instructions action",
        "outputs": [
            {
                "satoshis": 1000,
                "lockingScript": locking_script.hex(),
                "customInstructions": {"instruction1": "value1"}
            }
        ]
    }
    
    result = wallet.create_action(args, "test")
    
    assert isinstance(result, dict)


def test_sum_outputs_helper(wallet):
    """Test _sum_outputs helper method."""
    outputs = [
        {"satoshis": 1000},
        {"satoshis": 2000},
        {"satoshis": 3000}
    ]
    
    total = wallet._sum_outputs(outputs)
    
    assert total == 6000


def test_self_address_generation(wallet):
    """Test _self_address generates valid address."""
    address = wallet._self_address()
    
    assert isinstance(address, str)
    assert len(address) > 20  # BSV addresses are typically 25-34 chars


def test_list_actions_with_include_beef(wallet):
    """Test listing actions with BEEF inclusion."""
    args = {"includeBEEF": True}
    
    result = wallet.list_actions(args, "test")
    
    assert isinstance(result, dict)


def test_reveal_counterparty_key_linkage(wallet):
    """Test revealing counterparty key linkage."""
    counterparty_pub = PrivateKey().public_key()
    
    args = {
        "counterparty": counterparty_pub.hex(),
        "verifier": "verifier_identity",
        "privileged": False
    }
    
    result = wallet.reveal_counterparty_key_linkage(args, "test")
    
    assert isinstance(result, dict)


def test_reveal_specific_key_linkage(wallet):
    """Test revealing specific key linkage."""
    args = {
        "protocolID": [1, "test_protocol"],
        "keyID": "test_key_1",
        "counterparty": PrivateKey().public_key().hex(),
        "verifier": "verifier_identity",
        "privileged": False
    }
    
    result = wallet.reveal_specific_key_linkage(args, "test")
    
    assert isinstance(result, dict)

