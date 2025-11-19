"""
Coverage tests for hd/bip32.py - untested branches.
"""
import pytest
from bsv.hd.bip32 import master_xprv_from_seed, Xprv, Xpub, bip32_derive_xkeys_from_xkey


# ========================================================================
# Master key generation branches
# ========================================================================

def test_master_xprv_from_seed():
    """Test generating master xprv from seed."""
    seed = b'\x01' * 64
    xprv = master_xprv_from_seed(seed)
    assert isinstance(xprv, Xprv)


def test_master_xprv_from_short_seed():
    """Test master xprv from short seed."""
    seed = b'\x01' * 16
    with pytest.raises(AssertionError, match='invalid seed byte length'):
        master_xprv_from_seed(seed)


def test_master_xprv_from_long_seed():
    """Test master xprv from long seed."""
    seed = b'\x01' * 64
    xprv = master_xprv_from_seed(seed)
    assert isinstance(xprv, Xprv)


# ========================================================================
# Key derivation branches
# ========================================================================

def test_derive_child_normal():
    """Test deriving normal (non-hardened) child."""
    seed = b'\x01' * 64
    master = master_xprv_from_seed(seed)
    
    children = bip32_derive_xkeys_from_xkey(master, 0, 1)
    assert isinstance(children, list)
    assert len(children) > 0
    assert isinstance(children[0], Xprv)


def test_derive_child_hardened():
    """Test deriving hardened child."""
    seed = b'\x01' * 64
    master = master_xprv_from_seed(seed)
    
    # Hardened derivation (index with high bit set)
    children = bip32_derive_xkeys_from_xkey(master, 0x80000000, 0x80000001)
    assert isinstance(children, list)
    assert len(children) > 0
    assert isinstance(children[0], Xprv)


def test_derive_multiple_levels():
    """Test deriving multiple levels."""
    seed = b'\x01' * 64
    master = master_xprv_from_seed(seed)
    
    children1 = bip32_derive_xkeys_from_xkey(master, 0, 1)
    children2 = bip32_derive_xkeys_from_xkey(children1[0], 1, 2)
    assert isinstance(children2[0], Xprv)


# ========================================================================
# Xprv/Xpub serialization branches
# ========================================================================

def test_xprv_string_representation():
    """Test Xprv string representation."""
    seed = b'\x01' * 64
    xprv = master_xprv_from_seed(seed)
    xprv_str = str(xprv)
    assert isinstance(xprv_str, str)
    assert xprv_str.startswith('xprv') or xprv_str.startswith('tprv')


def test_xpub_from_xprv():
    """Test getting xpub from xprv."""
    seed = b'\x01' * 64
    xprv = master_xprv_from_seed(seed)
    xpub = Xpub.from_xprv(xprv)
    assert isinstance(xpub, Xpub)


def test_xpub_string_representation():
    """Test Xpub string representation."""
    seed = b'\x01' * 64
    xprv = master_xprv_from_seed(seed)
    xpub = Xpub.from_xprv(xprv)
    xpub_str = str(xpub)
    assert isinstance(xpub_str, str)
    assert xpub_str.startswith('xpub') or xpub_str.startswith('tpub')


# ========================================================================
# Edge cases
# ========================================================================

def test_deterministic_derivation():
    """Test same seed produces same keys."""
    seed = b'\x02' * 64
    xprv1 = master_xprv_from_seed(seed)
    xprv2 = master_xprv_from_seed(seed)
    assert str(xprv1) == str(xprv2)


def test_different_seeds():
    """Test different seeds produce different keys."""
    xprv1 = master_xprv_from_seed(b'\x01' * 64)
    xprv2 = master_xprv_from_seed(b'\x02' * 64)
    assert str(xprv1) != str(xprv2)


def test_derivation_index_zero():
    """Test derivation with index 0."""
    seed = b'\x03' * 64
    master = master_xprv_from_seed(seed)
    children1 = bip32_derive_xkeys_from_xkey(master, 0, 1)
    children2 = bip32_derive_xkeys_from_xkey(master, 0, 1)
    assert str(children1[0]) == str(children2[0])


def test_derivation_different_indices():
    """Test different indices produce different keys."""
    seed = b'\x04' * 64
    master = master_xprv_from_seed(seed)
    children1 = bip32_derive_xkeys_from_xkey(master, 0, 1)
    children2 = bip32_derive_xkeys_from_xkey(master, 1, 2)
    assert str(children1[0]) != str(children2[0])

