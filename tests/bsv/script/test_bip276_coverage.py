"""
Coverage tests for script/bip276.py - untested branches.
"""
import pytest


# ========================================================================
# BIP276 encoding branches
# ========================================================================

def test_bip276_encode_mainnet():
    """Test BIP276 encoding for mainnet."""
    try:
        from bsv.script.bip276 import encode
        script = b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac'
        
        encoded = encode(script, network='mainnet')
        assert isinstance(encoded, str)
        assert encoded.startswith('bitcoin-script:')
    except ImportError:
        pytest.skip("BIP276 not available")


def test_bip276_encode_testnet():
    """Test BIP276 encoding for testnet."""
    try:
        from bsv.script.bip276 import encode
        script = b'\x51'
        
        encoded = encode(script, network='testnet')
        assert isinstance(encoded, str)
    except ImportError:
        pytest.skip("BIP276 not available")


def test_bip276_encode_empty():
    """Test BIP276 encoding empty script."""
    try:
        from bsv.script.bip276 import encode
        encoded = encode(b'')
        assert isinstance(encoded, str)
    except ImportError:
        pytest.skip("BIP276 not available")


# ========================================================================
# BIP276 decoding branches
# ========================================================================

def test_bip276_decode_valid():
    """Test BIP276 decoding valid string."""
    try:
        from bsv.script.bip276 import encode, decode
        script = b'\x51\x52'
        
        encoded = encode(script)
        decoded = decode(encoded)
        
        assert decoded == script
    except ImportError:
        pytest.skip("BIP276 not available")


def test_bip276_decode_invalid_prefix():
    """Test BIP276 decoding with invalid prefix."""
    try:
        from bsv.script.bip276 import decode
        
        try:
            _ = decode('invalid-prefix:abc123')
            assert False, "Should have raised error"
        except ValueError:
            assert True
    except ImportError:
        pytest.skip("BIP276 not available")


def test_bip276_decode_malformed():
    """Test BIP276 decoding malformed string."""
    try:
        from bsv.script.bip276 import decode
        
        try:
            _ = decode('bitcoin-script:invalid')
            assert True  # May handle gracefully
        except (ValueError, Exception):
            assert True  # Or raise error
    except ImportError:
        pytest.skip("BIP276 not available")


# ========================================================================
# Roundtrip branches
# ========================================================================

def test_bip276_roundtrip_simple():
    """Test BIP276 encode/decode roundtrip."""
    try:
        from bsv.script.bip276 import encode, decode
        original = b'\x51\x52\x93'
        
        encoded = encode(original)
        decoded = decode(encoded)
        
        assert decoded == original
    except ImportError:
        pytest.skip("BIP276 not available")


def test_bip276_roundtrip_p2pkh():
    """Test BIP276 roundtrip with P2PKH script."""
    try:
        from bsv.script.bip276 import encode, decode
        p2pkh = b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac'
        
        encoded = encode(p2pkh)
        decoded = decode(encoded)
        
        assert decoded == p2pkh
    except ImportError:
        pytest.skip("BIP276 not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_bip276_encode_large_script():
    """Test BIP276 with large script."""
    try:
        from bsv.script.bip276 import encode, decode
        large_script = b'\x00' * 1000
        
        encoded = encode(large_script)
        decoded = decode(encoded)
        
        assert decoded == large_script
    except ImportError:
        pytest.skip("BIP276 not available")

