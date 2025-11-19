"""
Proper tests for PushDrop class - testing the ACTUAL API.
Tests the existing methods: decode(), lock(), unlock()
"""
import pytest
from bsv.transaction.pushdrop import PushDrop


@pytest.fixture
def mock_wallet():
    """Create a mock wallet for PushDrop testing."""
    from unittest.mock import Mock
    from bsv.keys import PrivateKey
    
    wallet = Mock()
    
    # Mock get_public_key
    priv = PrivateKey()
    pub = priv.public_key()
    wallet.get_public_key = Mock(return_value={
        'publicKey': pub.serialize().hex()
    })
    
    # Mock create_signature
    wallet.create_signature = Mock(return_value={
        'signature': b'\x01\x02\x03'
    })
    
    return wallet


def test_pushdrop_initialization(mock_wallet):
    """Test PushDrop class initialization."""
    # Test the REAL constructor
    pd = PushDrop(wallet=mock_wallet, originator="test_originator")
    
    assert pd.wallet == mock_wallet
    assert pd.originator == "test_originator"


def test_pushdrop_decode_static_method():
    """Test PushDrop.decode() static method."""
    # Test with empty script
    result = PushDrop.decode(b'')
    
    assert isinstance(result, dict)
    assert 'lockingPublicKey' in result
    assert 'fields' in result


def test_pushdrop_decode_with_valid_script():
    """Test decode() with a valid pushdrop script."""
    # Create a simple pushdrop-like script
    # This is a simplified test - real scripts are more complex
    script = b'\x00\x51'  # OP_FALSE OP_1
    
    result = PushDrop.decode(script)
    
    assert isinstance(result, dict)
    assert 'fields' in result
    assert isinstance(result['fields'], list)


def test_pushdrop_lock_method(mock_wallet):
    """Test PushDrop.lock() method with actual API."""
    pd = PushDrop(wallet=mock_wallet, originator="test")
    
    # Test the REAL lock() method
    result = pd.lock(
        ctx=None,
        fields=[b'field1', b'field2'],
        protocol_id="test_protocol",
        key_id="test_key",
        counterparty="test_counterparty",
        for_self=False,
        include_signature=True,
        lock_position="before"
    )
    
    # Should return hex string
    assert isinstance(result, str)
    
    # Verify wallet methods were called
    assert mock_wallet.get_public_key.called


def test_pushdrop_lock_without_signature(mock_wallet):
    """Test lock() without signature."""
    pd = PushDrop(wallet=mock_wallet)
    
    result = pd.lock(
        ctx=None,
        fields=[b'data'],
        protocol_id="protocol",
        key_id="key",
        counterparty="counterparty",
        include_signature=False
    )
    
    assert isinstance(result, str)


def test_pushdrop_lock_with_empty_fields(mock_wallet):
    """Test lock() with empty fields list."""
    pd = PushDrop(wallet=mock_wallet)
    
    result = pd.lock(
        ctx=None,
        fields=[],
        protocol_id="protocol",
        key_id="key",
        counterparty="counterparty"
    )
    
    assert isinstance(result, str)


def test_pushdrop_lock_for_self(mock_wallet):
    """Test lock() with for_self=True."""
    pd = PushDrop(wallet=mock_wallet)
    
    result = pd.lock(
        ctx=None,
        fields=[b'self_data'],
        protocol_id="protocol",
        key_id="key",
        counterparty="self",
        for_self=True
    )
    
    assert isinstance(result, str)


def test_pushdrop_lock_position_after(mock_wallet):
    """Test lock() with lock_position='after'."""
    pd = PushDrop(wallet=mock_wallet)
    
    result = pd.lock(
        ctx=None,
        fields=[b'data'],
        protocol_id="protocol",
        key_id="key",
        counterparty="counterparty",
        lock_position="after"
    )
    
    assert isinstance(result, str)


def test_pushdrop_unlock_method(mock_wallet):
    """Test PushDrop.unlock() method."""
    pd = PushDrop(wallet=mock_wallet)
    
    # Test the REAL unlock() method
    result = pd.unlock(
        protocol_id="protocol",
        key_id="key",
        counterparty="counterparty",
        sign_outputs='all',
        anyone_can_pay=False
    )
    
    # Returns a PushDropUnlocker instance
    assert result is not None


def test_pushdrop_unlock_with_none_sign_outputs(mock_wallet):
    """Test unlock() with sign_outputs='none'."""
    pd = PushDrop(wallet=mock_wallet)
    
    result = pd.unlock(
        protocol_id="protocol",
        key_id="key",
        counterparty="counterparty",
        sign_outputs='none'
    )
    
    assert result is not None


def test_pushdrop_unlock_with_single_sign_outputs(mock_wallet):
    """Test unlock() with sign_outputs='single'."""
    pd = PushDrop(wallet=mock_wallet)
    
    result = pd.unlock(
        protocol_id="protocol",
        key_id="key",
        counterparty="counterparty",
        sign_outputs='single'
    )
    
    assert result is not None


def test_pushdrop_unlock_with_anyonecanpay(mock_wallet):
    """Test unlock() with anyone_can_pay=True."""
    pd = PushDrop(wallet=mock_wallet)
    
    result = pd.unlock(
        protocol_id="protocol",
        key_id="key",
        counterparty="counterparty",
        anyone_can_pay=True
    )
    
    assert result is not None


def test_pushdrop_unlock_with_prev_tx_data(mock_wallet):
    """Test unlock() with previous transaction data."""
    pd = PushDrop(wallet=mock_wallet)
    
    result = pd.unlock(
        protocol_id="protocol",
        key_id="key",
        counterparty="counterparty",
        prev_txid="a" * 64,
        prev_vout=0,
        prev_satoshis=1000,
        prev_locking_script=b'\x51'
    )
    
    assert result is not None


def test_pushdrop_decode_with_various_scripts():
    """Test decode() with various script formats."""
    test_scripts = [
        b'',
        b'\x00',
        b'\x51',
        b'\x00\x51',
        b'\x01\x42',
    ]
    
    for script in test_scripts:
        result = PushDrop.decode(script)
        assert isinstance(result, dict)
        assert 'lockingPublicKey' in result
        assert 'fields' in result


def test_pushdrop_lock_with_large_fields(mock_wallet):
    """Test lock() with large field data."""
    pd = PushDrop(wallet=mock_wallet)
    
    large_field = b'x' * 1000
    
    result = pd.lock(
        ctx=None,
        fields=[large_field],
        protocol_id="protocol",
        key_id="key",
        counterparty="counterparty"
    )
    
    assert isinstance(result, str)


def test_pushdrop_lock_with_multiple_fields(mock_wallet):
    """Test lock() with many fields."""
    pd = PushDrop(wallet=mock_wallet)
    
    fields = [f'field{i}'.encode() for i in range(10)]
    
    result = pd.lock(
        ctx=None,
        fields=fields,
        protocol_id="protocol",
        key_id="key",
        counterparty="counterparty"
    )
    
    assert isinstance(result, str)


def test_pushdrop_without_originator(mock_wallet):
    """Test PushDrop without originator."""
    pd = PushDrop(wallet=mock_wallet, originator=None)
    
    assert pd.originator is None
    
    result = pd.lock(
        ctx=None,
        fields=[b'data'],
        protocol_id="protocol",
        key_id="key",
        counterparty="counterparty"
    )
    
    assert isinstance(result, str)


def test_pushdrop_lock_with_dict_protocol_id(mock_wallet):
    """Test lock() with dict protocol_id."""
    pd = PushDrop(wallet=mock_wallet)
    
    protocol_dict = {
        "securityLevel": 0,
        "protocol": "test_protocol"
    }
    
    result = pd.lock(
        ctx=None,
        fields=[b'data'],
        protocol_id=protocol_dict,
        key_id="key",
        counterparty="counterparty"
    )
    
    assert isinstance(result, str)


def test_pushdrop_lock_wallet_error_handling(mock_wallet):
    """Test lock() when wallet methods fail."""
    # Make get_public_key return invalid data
    mock_wallet.get_public_key.return_value = {'publicKey': 'short'}
    
    pd = PushDrop(wallet=mock_wallet)
    
    result = pd.lock(
        ctx=None,
        fields=[b'data'],
        protocol_id="protocol",
        key_id="key",
        counterparty="counterparty"
    )
    
    # Should return OP_TRUE (51) as fallback
    assert isinstance(result, str)


def test_pushdrop_lock_signature_error_handling(mock_wallet):
    """Test lock() when signature creation fails."""
    # Make create_signature raise an exception
    mock_wallet.create_signature.side_effect = Exception("Signature failed")
    
    pd = PushDrop(wallet=mock_wallet)
    
    # Should handle gracefully
    result = pd.lock(
        ctx=None,
        fields=[b'data'],
        protocol_id="protocol",
        key_id="key",
        counterparty="counterparty",
        include_signature=True
    )
    
    assert isinstance(result, str)

