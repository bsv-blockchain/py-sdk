"""
Tests for BIP276 encoding/decoding.

Ported from go-sdk/script/bip276_test.go (if it exists) and based on the BIP276 specification.
"""

import pytest
from bsv.script.bip276 import (
    BIP276,
    encode_bip276,
    decode_bip276,
    encode_script,
    encode_template,
    decode_script,
    decode_template,
    InvalidBIP276Format,
    InvalidChecksum,
    PREFIX_SCRIPT,
    PREFIX_TEMPLATE,
    NETWORK_MAINNET,
    NETWORK_TESTNET,
    CURRENT_VERSION,
)


class TestBIP276Encoding:
    """Test BIP276 encoding functionality."""
    
    def test_encode_simple_script(self):
        """Test encoding a simple script."""
        data = bytes.fromhex("76a914")  # OP_DUP OP_HASH160 OP_PUSH20
        script = BIP276(
            prefix=PREFIX_SCRIPT,
            version=CURRENT_VERSION,
            network=NETWORK_MAINNET,
            data=data
        )
        
        result = encode_bip276(script)
        
        # Result should be: bitcoin-script:0101<data><checksum>
        assert result.startswith("bitcoin-script:0101")
        assert "76a914" in result
        # Should have 8 hex digit checksum at the end
        assert len(result) >= len("bitcoin-script:0101") + len("76a914") + 8
    
    def test_encode_with_testnet(self):
        """Test encoding with testnet network."""
        data = bytes.fromhex("abcd")
        script = BIP276(
            prefix=PREFIX_SCRIPT,
            version=CURRENT_VERSION,
            network=NETWORK_TESTNET,
            data=data
        )
        
        result = encode_bip276(script)
        
        # Network should be 02 for testnet
        assert result.startswith("bitcoin-script:0201")
    
    def test_encode_template(self):
        """Test encoding a template."""
        data = bytes.fromhex("deadbeef")
        script = BIP276(
            prefix=PREFIX_TEMPLATE,
            version=CURRENT_VERSION,
            network=NETWORK_MAINNET,
            data=data
        )
        
        result = encode_bip276(script)
        
        assert result.startswith("bitcoin-template:0101")
        assert "deadbeef" in result
    
    def test_encode_invalid_version_zero(self):
        """Test that version 0 raises ValueError."""
        script = BIP276(
            prefix=PREFIX_SCRIPT,
            version=0,
            network=NETWORK_MAINNET,
            data=b"test"
        )
        
        with pytest.raises(ValueError, match="Invalid version"):
            encode_bip276(script)
    
    def test_encode_invalid_version_too_large(self):
        """Test that version > 255 raises ValueError."""
        script = BIP276(
            prefix=PREFIX_SCRIPT,
            version=256,
            network=NETWORK_MAINNET,
            data=b"test"
        )
        
        with pytest.raises(ValueError, match="Invalid version"):
            encode_bip276(script)
    
    def test_encode_invalid_network_zero(self):
        """Test that network 0 raises ValueError."""
        script = BIP276(
            prefix=PREFIX_SCRIPT,
            version=CURRENT_VERSION,
            network=0,
            data=b"test"
        )
        
        with pytest.raises(ValueError, match="Invalid network"):
            encode_bip276(script)
    
    def test_encode_invalid_network_too_large(self):
        """Test that network > 255 raises ValueError."""
        script = BIP276(
            prefix=PREFIX_SCRIPT,
            version=CURRENT_VERSION,
            network=256,
            data=b"test"
        )
        
        with pytest.raises(ValueError, match="Invalid network"):
            encode_bip276(script)


class TestBIP276Decoding:
    """Test BIP276 decoding functionality."""
    
    def test_decode_valid_script(self):
        """Test decoding a valid BIP276 script."""
        # First encode to get a valid string
        data = bytes.fromhex("76a914")
        script = BIP276(
            prefix=PREFIX_SCRIPT,
            version=CURRENT_VERSION,
            network=NETWORK_MAINNET,
            data=data
        )
        encoded = encode_bip276(script)
        
        # Now decode it
        decoded = decode_bip276(encoded)
        
        assert decoded.prefix == PREFIX_SCRIPT
        assert decoded.version == CURRENT_VERSION
        assert decoded.network == NETWORK_MAINNET
        assert decoded.data == data
    
    def test_decode_valid_template(self):
        """Test decoding a valid BIP276 template."""
        data = bytes.fromhex("deadbeef")
        script = BIP276(
            prefix=PREFIX_TEMPLATE,
            version=CURRENT_VERSION,
            network=NETWORK_TESTNET,
            data=data
        )
        encoded = encode_bip276(script)
        
        decoded = decode_bip276(encoded)
        
        assert decoded.prefix == PREFIX_TEMPLATE
        assert decoded.version == CURRENT_VERSION
        assert decoded.network == NETWORK_TESTNET
        assert decoded.data == data
    
    def test_decode_invalid_format_no_colon(self):
        """Test that invalid format (no colon) raises InvalidBIP276Format."""
        with pytest.raises(InvalidBIP276Format):
            decode_bip276("bitcoin-script0101abcd12345678")
    
    def test_decode_invalid_format_short_checksum(self):
        """Test that short checksum raises InvalidBIP276Format."""
        with pytest.raises(InvalidBIP276Format):
            decode_bip276("bitcoin-script:0101abcd123")
    
    def test_decode_invalid_hex_data(self):
        """Test that invalid hex data raises InvalidBIP276Format."""
        with pytest.raises(InvalidBIP276Format):
            decode_bip276("bitcoin-script:0101GGGG12345678")
    
    def test_decode_invalid_checksum(self):
        """Test that invalid checksum raises InvalidChecksum."""
        # Create a valid encoded string
        data = bytes.fromhex("abcd")
        script = BIP276(
            prefix=PREFIX_SCRIPT,
            version=CURRENT_VERSION,
            network=NETWORK_MAINNET,
            data=data
        )
        encoded = encode_bip276(script)
        
        # Corrupt the checksum
        corrupted = encoded[:-8] + "00000000"
        
        with pytest.raises(InvalidChecksum):
            decode_bip276(corrupted)
    
    def test_roundtrip_encoding_decoding(self):
        """Test that encode -> decode produces the same data."""
        test_cases = [
            (PREFIX_SCRIPT, NETWORK_MAINNET, bytes.fromhex("76a914")),
            (PREFIX_TEMPLATE, NETWORK_TESTNET, bytes.fromhex("deadbeef")),
            (PREFIX_SCRIPT, NETWORK_MAINNET, b"Hello, Bitcoin!"),
            ("custom-prefix", NETWORK_MAINNET, bytes.fromhex("0123456789abcdef")),
        ]
        
        for prefix, network, data in test_cases:
            script = BIP276(
                prefix=prefix,
                version=CURRENT_VERSION,
                network=network,
                data=data
            )
            
            encoded = encode_bip276(script)
            decoded = decode_bip276(encoded)
            
            assert decoded.prefix == prefix
            assert decoded.version == CURRENT_VERSION
            assert decoded.network == network
            assert decoded.data == data


class TestBIP276ConvenienceFunctions:
    """Test convenience functions for encoding/decoding scripts and templates."""
    
    def test_encode_decode_script_convenience(self):
        """Test encode_script and decode_script convenience functions."""
        data = bytes.fromhex("76a914")
        
        encoded = encode_script(data)
        decoded = decode_script(encoded)
        
        assert decoded == data
    
    def test_encode_decode_template_convenience(self):
        """Test encode_template and decode_template convenience functions."""
        data = bytes.fromhex("deadbeef")
        
        encoded = encode_template(data)
        decoded = decode_template(encoded)
        
        assert decoded == data
    
    def test_encode_script_with_testnet(self):
        """Test encode_script with testnet network."""
        data = bytes.fromhex("abcd")
        
        encoded = encode_script(data, network=NETWORK_TESTNET)
        
        assert encoded.startswith("bitcoin-script:0201")
    
    def test_decode_script_wrong_prefix_raises_error(self):
        """Test that decode_script raises error if prefix is not bitcoin-script."""
        data = bytes.fromhex("abcd")
        encoded = encode_template(data)  # Encode as template
        
        with pytest.raises(InvalidBIP276Format, match="Expected prefix 'bitcoin-script'"):
            decode_script(encoded)
    
    def test_decode_template_wrong_prefix_raises_error(self):
        """Test that decode_template raises error if prefix is not bitcoin-template."""
        data = bytes.fromhex("abcd")
        encoded = encode_script(data)  # Encode as script
        
        with pytest.raises(InvalidBIP276Format, match="Expected prefix 'bitcoin-template'"):
            decode_template(encoded)


class TestBIP276RealWorldExamples:
    """Test BIP276 with real-world-like examples."""
    
    def test_p2pkh_locking_script(self):
        """Test encoding/decoding a P2PKH locking script."""
        # P2PKH locking script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        # 76 a9 14 <20 bytes> 88 ac
        pubkey_hash = bytes.fromhex("89abcdefabbaabbaabbaabbaabbaabbaabbaabba")
        script_bytes = bytes.fromhex("76a914") + pubkey_hash + bytes.fromhex("88ac")
        
        encoded = encode_script(script_bytes)
        decoded = decode_script(encoded)
        
        assert decoded == script_bytes
    
    def test_empty_data(self):
        """Test encoding/decoding empty data."""
        data = b""
        
        encoded = encode_script(data)
        decoded = decode_script(encoded)
        
        assert decoded == data
    
    def test_large_data(self):
        """Test encoding/decoding large data."""
        data = bytes(range(256)) * 10  # 2560 bytes
        
        encoded = encode_script(data)
        decoded = decode_script(encoded)
        
        assert decoded == data


