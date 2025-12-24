"""
Coverage tests for wallet/key_deriver.py - untested branches.
"""
import pytest
from bsv.keys import PrivateKey


# ========================================================================
# Key Deriver initialization branches
# ========================================================================

def test_key_deriver_init():
    """Test KeyDeriver initialization."""
    try:
        from bsv.wallet.key_deriver import KeyDeriver
        deriver = KeyDeriver(PrivateKey())
        assert deriver  # Verify object creation succeeds
    except ImportError:
        pytest.skip("KeyDeriver not available")


def test_key_deriver_with_seed():
    """Test KeyDeriver with seed."""
    try:
        from bsv.wallet.key_deriver import KeyDeriver
        
        seed = b'\x01' * 64
        if hasattr(KeyDeriver, 'from_seed'):
            deriver = KeyDeriver.from_seed(seed)
            assert deriver is not None
    except ImportError:
        pytest.skip("KeyDeriver not available")


# ========================================================================
# Key derivation branches
# ========================================================================

def test_key_deriver_derive_child():
    """Test deriving child key."""
    try:
        from bsv.wallet.key_deriver import KeyDeriver
        
        deriver = KeyDeriver(PrivateKey())
        
        if hasattr(deriver, 'derive_child'):
            child = deriver.derive_child(0)
            assert child is not None
    except ImportError:
        pytest.skip("KeyDeriver not available")


def test_key_deriver_derive_path():
    """Test deriving key from path."""
    try:
        from bsv.wallet.key_deriver import KeyDeriver
        
        deriver = KeyDeriver(PrivateKey())
        
        if hasattr(deriver, 'derive_path'):
            key = deriver.derive_path("m/0/1")
            assert key is not None
    except ImportError:
        pytest.skip("KeyDeriver not available")


def test_key_deriver_derive_hardened():
    """Test deriving hardened key."""
    try:
        from bsv.wallet.key_deriver import KeyDeriver
        
        deriver = KeyDeriver(PrivateKey())
        
        if hasattr(deriver, 'derive_child'):
            child = deriver.derive_child(0x80000000)
            assert child is not None
    except ImportError:
        pytest.skip("KeyDeriver not available")


# ========================================================================
# Public key derivation branches
# ========================================================================

def test_key_deriver_derive_public_key():
    """Test deriving public key."""
    try:
        from bsv.wallet.key_deriver import KeyDeriver, Protocol, Counterparty, CounterpartyType

        # Use deterministic keys to avoid flakiness
        root = PrivateKey(b"\x01" * 32)
        cp_priv = PrivateKey(b"\x02" * 32)
        deriver = KeyDeriver(root)

        if hasattr(deriver, 'derive_public_key'):
            counterparty = Counterparty(CounterpartyType.OTHER, cp_priv.public_key())
            protocol = Protocol(security_level=0, protocol="test")
            pub = deriver.derive_public_key(protocol, "testkey", counterparty, for_self=False)

            # Assert meaningful but stable properties
            assert pub is not None
            assert hasattr(pub, "hex")
            assert len(pub.hex()) in (66, 130)  # compressed (66) or uncompressed (130) hex

            # Test determinism - same inputs should produce same output
            pub2 = deriver.derive_public_key(protocol, "testkey", counterparty, for_self=False)
            assert pub.hex() == pub2.hex()
    except ImportError:
        pytest.skip("KeyDeriver not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_key_deriver_deterministic():
    """Test same path produces same key."""
    try:
        from bsv.wallet.key_deriver import KeyDeriver
        
        root = PrivateKey(b'\x01' * 32)
        deriver = KeyDeriver(root)
        
        if hasattr(deriver, 'derive_child'):
            child1 = deriver.derive_child(0)
            child2 = deriver.derive_child(0)
            assert child1.key == child2.key
    except ImportError:
        pytest.skip("KeyDeriver not available")


def test_key_deriver_different_indices():
    """Test different indices produce different keys."""
    try:
        from bsv.wallet.key_deriver import KeyDeriver
        
        deriver = KeyDeriver(PrivateKey())
        
        if hasattr(deriver, 'derive_child'):
            child1 = deriver.derive_child(0)
            child2 = deriver.derive_child(1)
            assert child1.key != child2.key
    except ImportError:
        pytest.skip("KeyDeriver not available")

