"""
Test address-related functions in bsv/utils.py
"""

import pytest
from bsv.utils import decode_address, validate_address, address_to_public_key_hash, decode_wif
from bsv.constants import Network


class TestDecodeAddress:
    """Test decode_address() function."""
    
    def test_decode_mainnet_address(self):
        """Test decoding a valid mainnet P2PKH address."""
        # Example mainnet address
        address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        pubkey_hash, network = decode_address(address)
        assert isinstance(pubkey_hash, bytes)
        assert len(pubkey_hash) == 20
        assert network == Network.MAINNET
    
    def test_decode_testnet_address(self):
        """Test decoding a valid testnet P2PKH address."""
        # Example testnet address (starts with 'm' or 'n')
        address = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"
        pubkey_hash, network = decode_address(address)
        assert isinstance(pubkey_hash, bytes)
        assert len(pubkey_hash) == 20
        assert network == Network.TESTNET
    
    def test_decode_address_invalid_prefix(self):
        """Test that addresses with invalid prefix raise ValueError."""
        with pytest.raises(ValueError, match="invalid P2PKH address"):
            decode_address("3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy")  # P2SH address
    
    def test_decode_address_too_short(self):
        """Test that too short addresses raise ValueError."""
        with pytest.raises(ValueError, match="invalid P2PKH address"):
            decode_address("1A1zP1eP")
    
    def test_decode_address_too_long(self):
        """Test that too long addresses raise ValueError."""
        with pytest.raises(ValueError, match="invalid P2PKH address"):
            decode_address("1" * 50)
    
    def test_decode_address_invalid_chars(self):
        """Test that addresses with invalid characters raise ValueError."""
        with pytest.raises(ValueError, match="invalid P2PKH address"):
            decode_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf0a")  # Contains '0'
    
    def test_decode_address_with_O(self):
        """Test that addresses with 'O' raise ValueError."""
        with pytest.raises(ValueError, match="invalid P2PKH address"):
            decode_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfOa")
    
    def test_decode_address_with_I(self):
        """Test that addresses with 'I' raise ValueError."""
        with pytest.raises(ValueError, match="invalid P2PKH address"):
            decode_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfIa")
    
    def test_decode_address_with_l(self):
        """Test that addresses with 'l' raise ValueError."""
        with pytest.raises(ValueError, match="invalid P2PKH address"):
            decode_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divfla")
    
    def test_decode_address_empty_string(self):
        """Test that empty string raises ValueError."""
        with pytest.raises(ValueError, match="invalid P2PKH address"):
            decode_address("")
    
    def test_decode_address_wrong_prefix_letter(self):
        """Test that addresses starting with wrong letter raise ValueError."""
        with pytest.raises(ValueError, match="invalid P2PKH address"):
            decode_address("zzzzzzzzzzzzzzzzzzzzzzzzzz")


class TestValidateAddress:
    """Test validate_address() function."""
    
    def test_validate_valid_mainnet_address(self):
        """Test validating a valid mainnet address."""
        address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        assert validate_address(address) is True
    
    def test_validate_valid_testnet_address(self):
        """Test validating a valid testnet address."""
        address = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"
        assert validate_address(address) is True
    
    def test_validate_with_network_match(self):
        """Test validating address with matching network."""
        address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        assert validate_address(address, Network.MAINNET) is True
    
    def test_validate_with_network_mismatch(self):
        """Test validating address with non-matching network."""
        address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        assert validate_address(address, Network.TESTNET) is False
    
    def test_validate_invalid_address(self):
        """Test validating an invalid address."""
        assert validate_address("invalid") is False
    
    def test_validate_empty_address(self):
        """Test validating empty string."""
        assert validate_address("") is False
    
    def test_validate_address_with_invalid_chars(self):
        """Test validating address with invalid characters."""
        assert validate_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf0a") is False
    
    def test_validate_p2sh_address(self):
        """Test that P2SH addresses are invalid."""
        assert validate_address("3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy") is False
    
    def test_validate_testnet_with_mainnet_network(self):
        """Test testnet address validation with mainnet network specified."""
        address = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"
        assert validate_address(address, Network.MAINNET) is False
    
    def test_validate_none_network(self):
        """Test validation with None network accepts any valid address."""
        mainnet_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        testnet_addr = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"
        assert validate_address(mainnet_addr, None) is True
        assert validate_address(testnet_addr, None) is True


class TestAddressToPubKeyHash:
    """Test address_to_public_key_hash() function."""
    
    def test_extract_pubkey_hash_mainnet(self):
        """Test extracting public key hash from mainnet address."""
        address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        pubkey_hash = address_to_public_key_hash(address)
        assert isinstance(pubkey_hash, bytes)
        assert len(pubkey_hash) == 20
    
    def test_extract_pubkey_hash_testnet(self):
        """Test extracting public key hash from testnet address."""
        address = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"
        pubkey_hash = address_to_public_key_hash(address)
        assert isinstance(pubkey_hash, bytes)
        assert len(pubkey_hash) == 20
    
    def test_extract_pubkey_hash_invalid_raises(self):
        """Test that invalid address raises ValueError."""
        with pytest.raises(ValueError):
            address_to_public_key_hash("invalid")
    
    def test_extract_pubkey_hash_consistency(self):
        """Test that same address always returns same hash."""
        address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        hash1 = address_to_public_key_hash(address)
        hash2 = address_to_public_key_hash(address)
        assert hash1 == hash2


class TestDecodeWIF:
    """Test decode_wif() function."""
    
    def test_decode_wif_compressed_mainnet(self):
        """Test decoding compressed mainnet WIF."""
        # Example compressed WIF (52 chars)
        wif = "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1"
        privkey, compressed, network = decode_wif(wif)
        assert isinstance(privkey, bytes)
        assert len(privkey) == 32
        assert compressed is True
        assert network == Network.MAINNET
    
    def test_decode_wif_uncompressed_mainnet(self):
        """Test decoding uncompressed mainnet WIF."""
        # Example uncompressed WIF (51 chars)
        wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        privkey, compressed, network = decode_wif(wif)
        assert isinstance(privkey, bytes)
        assert len(privkey) == 32
        assert compressed is False
        assert network == Network.MAINNET
    
    def test_decode_wif_compressed_testnet(self):
        """Test decoding compressed testnet WIF."""
        wif = "cNJFgo1driFnPcBdBX8BrJrpxchBWXwXCvNH5SoSkdcF6JXXwHMm"
        privkey, compressed, network = decode_wif(wif)
        assert isinstance(privkey, bytes)
        assert len(privkey) == 32
        assert compressed is True
        assert network == Network.TESTNET
    
    def test_decode_wif_uncompressed_testnet(self):
        """Test decoding uncompressed testnet WIF."""
        wif = "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgwmaKkrx"
        privkey, compressed, network = decode_wif(wif)
        assert isinstance(privkey, bytes)
        assert len(privkey) == 32
        assert compressed is False
        assert network == Network.TESTNET
    
    def test_decode_wif_invalid_prefix_raises(self):
        """Test that WIF with invalid prefix raises exception."""
        # WIF with invalid prefix or checksum - will raise an exception
        with pytest.raises(Exception):  # Could be ValueError or checksum error
            decode_wif("9" * 52)
    
    def test_decode_wif_invalid_checksum_raises(self):
        """Test that WIF with invalid checksum raises exception."""
        # This should raise during base58check decode
        with pytest.raises(Exception):
            decode_wif("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyT0")
    
    def test_decode_wif_length_detection(self):
        """Test that WIF length correctly determines compression flag."""
        compressed_wif = "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1"
        uncompressed_wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        
        _, comp1, _ = decode_wif(compressed_wif)
        _, comp2, _ = decode_wif(uncompressed_wif)
        
        assert comp1 is True
        assert comp2 is False
    
    def test_decode_wif_empty_raises(self):
        """Test that empty WIF raises exception."""
        with pytest.raises(Exception):
            decode_wif("")


class TestAddressRoundTrip:
    """Test address encoding and decoding round trips."""
    
    def test_decode_and_validate_consistency(self):
        """Test that decode and validate give consistent results."""
        valid_addresses = [
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
        ]
        
        for address in valid_addresses:
            # If decode succeeds, validate should return True
            try:
                decode_address(address)
                assert validate_address(address) is True
            except ValueError:
                assert validate_address(address) is False

