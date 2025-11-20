"""
Coverage tests for hd/bip39.py - untested branches.
"""
import pytest

# Test passphrase constants for BIP39 tests
# SonarQube ignore:start - These are test values, not real credentials
TEST_PASSPHRASE = "test"  # noqa: S105
TEST_PASSPHRASE_1 = "pass1"  # noqa: S105
TEST_PASSPHRASE_2 = "pass2"  # noqa: S105
# SonarQube ignore:end


# ========================================================================
# Mnemonic generation branches
# ========================================================================

def test_generate_mnemonic_12_words():
    """Test generating 12-word mnemonic."""
    try:
        from bsv.hd.bip39 import generate_mnemonic
        mnemonic = generate_mnemonic(strength=128)
        words = mnemonic.split()
        assert len(words) == 12
    except ImportError:
        pytest.skip("BIP39 not available")


def test_generate_mnemonic_24_words():
    """Test generating 24-word mnemonic."""
    try:
        from bsv.hd.bip39 import generate_mnemonic
        mnemonic = generate_mnemonic(strength=256)
        words = mnemonic.split()
        assert len(words) == 24
    except ImportError:
        pytest.skip("BIP39 not available")


def test_generate_mnemonic_default():
    """Test generating mnemonic with default strength."""
    try:
        from bsv.hd.bip39 import generate_mnemonic
        mnemonic = generate_mnemonic()
        words = mnemonic.split()
        assert len(words) in [12, 15, 18, 21, 24]
    except ImportError:
        pytest.skip("BIP39 not available")


# ========================================================================
# Mnemonic validation branches
# ========================================================================

def test_validate_mnemonic_valid():
    """Test validating valid mnemonic."""
    try:
        from bsv.hd.bip39 import generate_mnemonic, validate_mnemonic
        mnemonic = generate_mnemonic()
        is_valid = validate_mnemonic(mnemonic)
        assert is_valid == True
    except ImportError:
        pytest.skip("BIP39 not available")


def test_validate_mnemonic_invalid():
    """Test validating invalid mnemonic."""
    try:
        from bsv.hd.bip39 import validate_mnemonic
        try:
            is_valid = validate_mnemonic("invalid mnemonic phrase")
            assert is_valid == False
        except ValueError:
            # validate_mnemonic raises ValueError for invalid mnemonics
            assert True
    except ImportError:
        pytest.skip("BIP39 not available")


def test_validate_mnemonic_empty():
    """Test validating empty mnemonic."""
    try:
        from bsv.hd.bip39 import validate_mnemonic
        try:
            is_valid = validate_mnemonic("")
            assert is_valid == False
        except (ValueError, IndexError):
            # Empty mnemonic may raise an error
            assert True
    except ImportError:
        pytest.skip("BIP39 not available")


# ========================================================================
# Mnemonic to seed branches
# ========================================================================

def test_mnemonic_to_seed_no_passphrase():
    """Test converting mnemonic to seed without passphrase."""
    try:
        from bsv.hd.bip39 import generate_mnemonic, mnemonic_to_seed
        mnemonic = generate_mnemonic()
        seed = mnemonic_to_seed(mnemonic)
        assert isinstance(seed, bytes)
        assert len(seed) == 64
    except ImportError:
        pytest.skip("BIP39 not available")


def test_mnemonic_to_seed_with_passphrase():
    """Test converting mnemonic to seed with passphrase."""
    try:
        from bsv.hd.bip39 import generate_mnemonic, mnemonic_to_seed
        mnemonic = generate_mnemonic()
        seed = mnemonic_to_seed(mnemonic, passphrase=TEST_PASSPHRASE)
        assert isinstance(seed, bytes)
        assert len(seed) == 64
    except ImportError:
        pytest.skip("BIP39 not available")


def test_mnemonic_to_seed_empty_passphrase():
    """Test converting with empty passphrase."""
    try:
        from bsv.hd.bip39 import generate_mnemonic, mnemonic_to_seed
        mnemonic = generate_mnemonic()
        seed1 = mnemonic_to_seed(mnemonic, passphrase="")
        seed2 = mnemonic_to_seed(mnemonic)
        # Empty passphrase should be same as no passphrase
        assert seed1 == seed2
    except ImportError:
        pytest.skip("BIP39 not available")


# ========================================================================
# Edge cases
# ========================================================================

def test_mnemonic_deterministic():
    """Test same mnemonic produces same seed."""
    try:
        from bsv.hd.bip39 import mnemonic_to_seed
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        seed1 = mnemonic_to_seed(mnemonic)
        seed2 = mnemonic_to_seed(mnemonic)
        assert seed1 == seed2
    except ImportError:
        pytest.skip("BIP39 not available")


def test_different_passphrases_different_seeds():
    """Test different passphrases produce different seeds."""
    try:
        from bsv.hd.bip39 import generate_mnemonic, mnemonic_to_seed
        mnemonic = generate_mnemonic()
        seed1 = mnemonic_to_seed(mnemonic, passphrase=TEST_PASSPHRASE_1)
        seed2 = mnemonic_to_seed(mnemonic, passphrase=TEST_PASSPHRASE_2)
        assert seed1 != seed2
    except ImportError:
        pytest.skip("BIP39 not available")

