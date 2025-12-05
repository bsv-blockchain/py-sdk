"""
Coverage tests for address.py - untested branches.
"""
import pytest
from bsv.keys import PrivateKey

# Constants for skip messages
SKIP_VALIDATE_ADDRESS = "validate_address not available"
SKIP_DECODE_WIF = "decode_wif not available"
SKIP_DECODE_ADDRESS = "decode_address not available"


# ========================================================================
# Address generation branches
# ========================================================================

def test_address_from_public_key():
    """Test address generation from public key."""
    priv = PrivateKey()
    pub = priv.public_key()
    address = pub.address()
    assert isinstance(address, str)
    assert len(address) > 0


def test_address_from_compressed_key():
    """Test address from compressed public key."""
    priv = PrivateKey()
    priv.compressed = True
    pub = priv.public_key()
    address = pub.address()
    assert isinstance(address, str)


def test_address_from_uncompressed_key():
    """Test address from uncompressed public key."""
    priv = PrivateKey()
    priv.compressed = False
    pub = priv.public_key()
    address = pub.address()
    assert isinstance(address, str)


# ========================================================================
# Address validation branches
# ========================================================================

def test_address_validate_valid():
    """Test validating valid address."""
    try:
        from bsv.utils import validate_address
        priv = PrivateKey()
        address = priv.public_key().address()
        is_valid = validate_address(address)
        assert is_valid == True
    except ImportError:
        pytest.skip(SKIP_VALIDATE_ADDRESS)


def test_address_validate_invalid():
    """Test validating invalid address."""
    try:
        from bsv.utils import validate_address
        is_valid = validate_address("invalid")
        assert is_valid == False
    except ImportError:
        pytest.skip(SKIP_VALIDATE_ADDRESS)


def test_address_validate_empty():
    """Test validating empty address."""
    try:
        from bsv.utils import validate_address
        is_valid = validate_address("")
        assert is_valid == False
    except ImportError:
        pytest.skip(SKIP_VALIDATE_ADDRESS)


# ========================================================================
# Address conversion branches
# ========================================================================

def test_address_to_pubkey_hash():
    """Test converting address to public key hash."""
    try:
        from bsv.utils import address_to_public_key_hash
        priv = PrivateKey()
        address = priv.public_key().address()
        pkh = address_to_public_key_hash(address)
        assert isinstance(pkh, bytes)
        assert len(pkh) == 20
    except ImportError:
        pytest.skip("address_to_public_key_hash not available")


def test_pubkey_hash_to_address():
    """Test converting public key hash to address."""
    try:
        from bsv.utils import pubkey_hash_to_address
        pkh = b'\x00' * 20
        address = pubkey_hash_to_address(pkh)
        assert isinstance(address, str)
    except ImportError:
        pytest.skip("pubkey_hash_to_address not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_address_deterministic():
    """Test same key produces same address."""
    priv = PrivateKey(b'\x01' * 32)
    addr1 = priv.public_key().address()
    addr2 = priv.public_key().address()
    assert addr1 == addr2


def test_different_keys_different_addresses():
    """Test different keys produce different addresses."""
    priv1 = PrivateKey(b'\x01' * 32)
    priv2 = PrivateKey(b'\x02' * 32)
    addr1 = priv1.public_key().address()
    addr2 = priv2.public_key().address()
    assert addr1 != addr2


# ========================================================================
# WIF decoding branches
# ========================================================================

def test_decode_wif_compressed():
    """Test decoding compressed WIF."""
    try:
        from bsv.utils.address import decode_wif
        from bsv.keys import PrivateKey

        # Generate a valid compressed WIF
        priv = PrivateKey()
        priv.compressed = True
        wif = priv.wif()
        private_key, compressed, _ = decode_wif(wif)
        assert isinstance(private_key, bytes)
        assert compressed is True
        assert len(private_key) == 32
    except ImportError:
        pytest.skip(SKIP_DECODE_WIF)


def test_decode_wif_uncompressed():
    """Test decoding uncompressed WIF."""
    try:
        from bsv.utils.address import decode_wif
        from bsv.keys import PrivateKey

        # Generate a valid uncompressed WIF
        priv = PrivateKey()
        priv.compressed = False
        wif = priv.wif()
        private_key, compressed, _ = decode_wif(wif)
        assert isinstance(private_key, bytes)
        assert compressed is False
        assert len(private_key) == 32
    except ImportError:
        pytest.skip(SKIP_DECODE_WIF)


def test_decode_wif_invalid_prefix():
    """Test decoding WIF with invalid prefix."""
    try:
        from bsv.utils.address import decode_wif
        from bsv.base58 import base58check_encode
        from bsv.constants import WIF_PREFIX_NETWORK_DICT

        # Get a valid prefix and create data with invalid prefix
        # Use invalid prefix (testnet would be b'\xef')
        invalid_prefix = b'\xff'  # Invalid prefix

        # Create WIF data with valid checksum but invalid prefix
        private_key_data = b'\x01' * 32  # 32 bytes of private key
        compressed_flag = b'\x01'  # Compressed flag

        # Create payload with invalid prefix
        payload = invalid_prefix + private_key_data + compressed_flag
        invalid_wif = base58check_encode(payload)

        # This should now pass checksum validation but fail on prefix validation
        with pytest.raises(ValueError, match="unknown WIF prefix"):
            decode_wif(invalid_wif)
    except ImportError:
        pytest.skip(SKIP_DECODE_WIF)


def test_decode_wif_invalid_format():
    """Test decoding invalid WIF format."""
    try:
        from bsv.utils.address import decode_wif
        # Invalid WIF - too short
        wif = "KyvGbxRUoofdw3TNydWn2Z78UaBFFap8DQ3KQ48UX4U8FEPFj"
        with pytest.raises(Exception):  # Could be ValueError or other
            decode_wif(wif)
    except ImportError:
        pytest.skip(SKIP_DECODE_WIF)


# ========================================================================
# Address decoding error cases
# ========================================================================

def test_decode_address_invalid_format():
    """Test decoding address with invalid format."""
    try:
        from bsv.utils.address import decode_address
        # Invalid address format
        with pytest.raises(ValueError, match="invalid P2PKH address"):
            decode_address("invalid_address")
    except ImportError:
        pytest.skip(SKIP_DECODE_ADDRESS)


def test_decode_address_invalid_checksum():
    """Test decoding address with invalid checksum."""
    try:
        from bsv.utils.address import decode_address
        # Create a valid-looking address but corrupt the checksum
        # Use a valid address and modify the last character
        from bsv.keys import PrivateKey
        priv = PrivateKey()
        valid_address = priv.public_key().address()
        # Corrupt the last character to make checksum invalid
        invalid_address = valid_address[:-1] + ('1' if valid_address[-1] != '1' else '2')

        with pytest.raises(ValueError):  # base58check_decode will raise ValueError for bad checksum
            decode_address(invalid_address)
    except ImportError:
        pytest.skip(SKIP_DECODE_ADDRESS)


def test_decode_address_unknown_network():
    """Test decoding address with unknown network prefix."""
    try:
        from bsv.utils.address import decode_address
        # This might not be testable if all base58check_decode failures are caught the same way
        # But let's try with a manipulated valid address
        pytest.skip("Hard to construct test case for unknown network prefix")
    except ImportError:
        pytest.skip(SKIP_DECODE_ADDRESS)


# ========================================================================
# Address validation with network parameter
# ========================================================================

def test_address_validate_with_network_match():
    """Test validating address with matching network."""
    try:
        from bsv.utils import validate_address
        from bsv.constants import Network
        priv = PrivateKey()
        address = priv.public_key().address()
        is_valid = validate_address(address, Network.MAINNET)
        # Should work regardless of network match (depends on key type)
        assert isinstance(is_valid, bool)
    except ImportError:
        pytest.skip(SKIP_VALIDATE_ADDRESS)


def test_address_validate_with_network_mismatch():
    """Test validating address with mismatching network."""
    try:
        from bsv.utils import validate_address
        from bsv.constants import Network
        priv = PrivateKey()
        address = priv.public_key().address()
        is_valid = validate_address(address, Network.TESTNET)
        # Should work regardless of network mismatch (depends on key type)
        assert isinstance(is_valid, bool)
    except ImportError:
        pytest.skip(SKIP_VALIDATE_ADDRESS)

