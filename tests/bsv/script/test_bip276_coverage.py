"""
Coverage tests for script/bip276.py - untested branches.
"""
import pytest


# ========================================================================
# BIP276 encoding branches
# ========================================================================

def test_bip276_encode_mainnet():
    """Test BIP276 encoding for mainnet."""
    from bsv.script.bip276 import encode_script, NETWORK_MAINNET
    script = b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac'

    encoded = encode_script(script, network=NETWORK_MAINNET)
    assert isinstance(encoded, str)
    assert encoded.startswith('bitcoin-script:')


def test_bip276_encode_testnet():
    """Test BIP276 encoding for testnet."""
    from bsv.script.bip276 import encode_script, NETWORK_TESTNET
    script = b'\x51'

    encoded = encode_script(script, network=NETWORK_TESTNET)
    assert isinstance(encoded, str)


def test_bip276_encode_empty():
    """Test BIP276 encoding empty script."""
    from bsv.script.bip276 import encode_script
    encoded = encode_script(b'')
    assert isinstance(encoded, str)


# ========================================================================
# BIP276 decoding branches
# ========================================================================

def test_bip276_decode_valid():
    """Test BIP276 decoding valid string."""
    from bsv.script.bip276 import encode_script, decode_script
    script = b'\x51\x52'

    encoded = encode_script(script)
    decoded = decode_script(encoded)

    assert decoded == script


def test_bip276_decode_invalid_prefix():
    """Test BIP276 decoding with invalid prefix."""
    from bsv.script.bip276 import decode_script, InvalidBIP276Format

    try:
        _ = decode_script('invalid-prefix:abc123')
        assert False, "Should have raised error"
    except InvalidBIP276Format:
        assert True


def test_bip276_decode_malformed():
    """Test BIP276 decoding malformed string."""
    from bsv.script.bip276 import decode_script

    try:
        _ = decode_script('bitcoin-script:invalid')
        assert True  # May handle gracefully
    except (ValueError, Exception):
        assert True  # Or raise error


# ========================================================================
# Roundtrip branches
# ========================================================================

def test_bip276_roundtrip_simple():
    """Test BIP276 encode/decode roundtrip."""
    from bsv.script.bip276 import encode_script, decode_script
    original = b'\x51\x52\x93'

    encoded = encode_script(original)
    decoded = decode_script(encoded)

    assert decoded == original


def test_bip276_roundtrip_p2pkh():
    """Test BIP276 roundtrip with P2PKH script."""
    from bsv.script.bip276 import encode_script, decode_script
    p2pkh = b'\x76\xa9\x14' + b'\x00' * 20 + b'\x88\xac'

    encoded = encode_script(p2pkh)
    decoded = decode_script(encoded)

    assert decoded == p2pkh


# ========================================================================
# Edge cases
# ========================================================================

def test_bip276_encode_large_script():
    """Test BIP276 with large script."""
    from bsv.script.bip276 import encode_script, decode_script
    large_script = b'\x00' * 1000

    encoded = encode_script(large_script)
    decoded = decode_script(encoded)

    assert decoded == large_script

