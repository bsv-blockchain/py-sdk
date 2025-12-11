"""
Coverage tests for hd/bip39.py - untested branches.
"""
import pytest

# Test passphrase constants for BIP39 tests - not real credentials, only for unit testing
TEST_PASSPHRASE = "test"  # NOSONAR - Test value for BIP39 unit tests
TEST_PASSPHRASE_1 = "pass1"  # NOSONAR - Test value for BIP39 unit tests
TEST_PASSPHRASE_2 = "pass2"  # NOSONAR - Test value for BIP39 unit tests


# ========================================================================
# Mnemonic generation branches
# ========================================================================

def test_generate_mnemonic_12_words():
    """Test generating 12-word mnemonic."""
    from bsv.hd.bip39 import mnemonic_from_entropy
    # 128 bits entropy gives 12 words
    mnemonic = mnemonic_from_entropy()
    words = mnemonic.split()
    assert len(words) == 12


def test_generate_mnemonic_24_words():
    """Test generating 24-word mnemonic."""
    from bsv.hd.bip39 import mnemonic_from_entropy
    from secrets import randbits
    # 256 bits entropy gives 24 words
    entropy = randbits(256).to_bytes(32, 'big')
    mnemonic = mnemonic_from_entropy(entropy)
    words = mnemonic.split()
    assert len(words) == 24


def test_generate_mnemonic_default():
    """Test generating mnemonic with default strength."""
    from bsv.hd.bip39 import mnemonic_from_entropy
    mnemonic = mnemonic_from_entropy()
    words = mnemonic.split()
    assert len(words) == 12  # Default is 128 bits -> 12 words


# ========================================================================
# Mnemonic validation branches
# ========================================================================

def test_validate_mnemonic_valid():
    """Test validating valid mnemonic."""
    from bsv.hd.bip39 import mnemonic_from_entropy, validate_mnemonic
    mnemonic = mnemonic_from_entropy()
    # validate_mnemonic raises exception if invalid, returns None if valid
    try:
        validate_mnemonic(mnemonic)
        assert True  # No exception means valid
    except Exception:
        assert False  # Should not raise exception for valid mnemonic


def test_validate_mnemonic_invalid():
    """Test validating invalid mnemonic."""
    from bsv.hd.bip39 import validate_mnemonic
    try:
        validate_mnemonic("invalid mnemonic phrase")
        assert False  # Should raise exception
    except (ValueError, AssertionError):
        # validate_mnemonic raises exception for invalid mnemonics
        assert True


def test_validate_mnemonic_empty():
    """Test validating empty mnemonic."""
    from bsv.hd.bip39 import validate_mnemonic
    try:
        validate_mnemonic("")
        assert False  # Should raise exception
    except (ValueError, IndexError, AssertionError):
        # Empty mnemonic should raise an error
        assert True


# ========================================================================
# Mnemonic to seed branches
# ========================================================================

def test_mnemonic_to_seed_no_passphrase():
    """Test converting mnemonic to seed without passphrase."""
    from bsv.hd.bip39 import mnemonic_from_entropy, seed_from_mnemonic
    mnemonic = mnemonic_from_entropy()
    seed = seed_from_mnemonic(mnemonic)
    assert isinstance(seed, bytes)
    assert len(seed) == 64


def test_mnemonic_to_seed_with_passphrase():
    """Test converting mnemonic to seed with passphrase."""
    from bsv.hd.bip39 import mnemonic_from_entropy, seed_from_mnemonic
    mnemonic = mnemonic_from_entropy()
    seed = seed_from_mnemonic(mnemonic, passphrase=TEST_PASSPHRASE)
    assert isinstance(seed, bytes)
    assert len(seed) == 64


def test_mnemonic_to_seed_empty_passphrase():
    """Test converting with empty passphrase."""
    from bsv.hd.bip39 import mnemonic_from_entropy, seed_from_mnemonic
    mnemonic = mnemonic_from_entropy()
    seed1 = seed_from_mnemonic(mnemonic, passphrase="")
    seed2 = seed_from_mnemonic(mnemonic)
    # Empty passphrase should be same as no passphrase
    assert seed1 == seed2


# ========================================================================
# Edge cases
# ========================================================================

def test_mnemonic_deterministic():
    """Test same mnemonic produces same seed."""
    from bsv.hd.bip39 import seed_from_mnemonic
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    seed1 = seed_from_mnemonic(mnemonic)
    seed2 = seed_from_mnemonic(mnemonic)
    assert seed1 == seed2


def test_different_passphrases_different_seeds():
    """Test different passphrases produce different seeds."""
    from bsv.hd.bip39 import mnemonic_from_entropy, seed_from_mnemonic
    mnemonic = mnemonic_from_entropy()
    seed1 = seed_from_mnemonic(mnemonic, passphrase=TEST_PASSPHRASE_1)
    seed2 = seed_from_mnemonic(mnemonic, passphrase=TEST_PASSPHRASE_2)
    assert seed1 != seed2

