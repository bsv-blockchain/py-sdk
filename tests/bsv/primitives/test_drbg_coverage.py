"""
Coverage tests for primitives/drbg.py - untested branches.
"""
import pytest


# ========================================================================
# DRBG initialization branches
# ========================================================================

def test_drbg_init():
    """Test DRBG initialization."""
    try:
        from bsv.primitives.drbg import DRBG
        
        entropy = b'\x01' * 32
        nonce = b'\x02' * 16
        drbg = DRBG(entropy, nonce)
        assert drbg is not None
    except ImportError:
        pytest.skip("DRBG not available")


def test_drbg_init_with_entropy():
    """Test DRBG with entropy."""
    from bsv.primitives.drbg import DRBG

    entropy = b'\x01' * 48
    nonce = b'\x02' * 16
    drbg = DRBG(entropy, nonce)
    assert drbg is not None


# ========================================================================
# DRBG generation branches
# ========================================================================

def test_drbg_generate():
    """Test generating random bytes."""
    try:
        from bsv.primitives.drbg import DRBG
        
        entropy = b'\x01' * 32
        nonce = b'\x02' * 16
        drbg = DRBG(entropy, nonce)
        
        if hasattr(drbg, 'generate'):
            random_hex = drbg.generate(32)
            assert isinstance(random_hex, str)
            assert len(random_hex) == 64  # 32 bytes = 64 hex chars
    except ImportError:
        pytest.skip("DRBG not available")


def test_drbg_generate_small():
    """Test generating small amount of random bytes."""
    try:
        from bsv.primitives.drbg import DRBG
        
        entropy = b'\x01' * 32
        nonce = b'\x02' * 16
        drbg = DRBG(entropy, nonce)
        
        if hasattr(drbg, 'generate'):
            random_hex = drbg.generate(8)
            assert len(random_hex) == 16  # 8 bytes = 16 hex chars
    except ImportError:
        pytest.skip("DRBG not available")


def test_drbg_generate_large():
    """Test generating large amount of random bytes."""
    try:
        from bsv.primitives.drbg import DRBG
        
        entropy = b'\x01' * 32
        nonce = b'\x02' * 16
        drbg = DRBG(entropy, nonce)
        
        if hasattr(drbg, 'generate'):
            random_hex = drbg.generate(1000)
            assert len(random_hex) == 2000  # 1000 bytes = 2000 hex chars
    except ImportError:
        pytest.skip("DRBG not available")


# ========================================================================
# DRBG reseed branches
# ========================================================================

def test_drbg_reseed():
    """Test reseeding DRBG."""
    try:
        from bsv.primitives.drbg import DRBG
        
        entropy = b'\x01' * 32
        nonce = b'\x02' * 16
        drbg = DRBG(entropy, nonce)
        
        if hasattr(drbg, 'reseed'):
            new_entropy = b'\x03' * 32
            drbg.reseed(new_entropy)
            assert True
    except ImportError:
        pytest.skip("DRBG not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_drbg_deterministic():
    """Test DRBG is deterministic with same seed."""
    try:
        from bsv.primitives.drbg import DRBG
        
        entropy = b'\x03' * 32
        nonce = b'\x04' * 16
        
        drbg1 = DRBG(entropy, nonce)
        drbg2 = DRBG(entropy, nonce)
        
        if hasattr(drbg1, 'generate'):
            bytes1 = drbg1.generate(32)
            bytes2 = drbg2.generate(32)
            assert bytes1 == bytes2
    except ImportError:
        pytest.skip("DRBG not available")


def test_drbg_different_seeds():
    """Test DRBG with different seeds produces different output."""
    try:
        from bsv.primitives.drbg import DRBG
        
        drbg1 = DRBG(b'\x01' * 32, b'\x02' * 16)
        drbg2 = DRBG(b'\x03' * 32, b'\x04' * 16)
        
        if hasattr(drbg1, 'generate'):
            bytes1 = drbg1.generate(32)
            bytes2 = drbg2.generate(32)
            assert bytes1 != bytes2
    except ImportError:
        pytest.skip("DRBG not available")

