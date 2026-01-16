import pytest

from bsv.hd.bip32 import master_xprv_from_seed, bip32_derive_xprvs_from_mnemonic, bip32_derive_xkeys_from_xkey
from bsv.hd.bip39 import seed_from_mnemonic
from bsv.hd.bip44 import bip44_derive_xprvs_from_mnemonic

from bsv.constants import BIP32_DERIVATION_PATH, BIP44_DERIVATION_PATH

# BIP32_DERIVATION_PATH = "m/"
# BIP44_DERIVATION_PATH = "m/44'/236'/0'"

def test_key_derivation_consistency():
    # Test mnemonic phrase
    test_mnemonic = "skin index hair zone brush soldier airport found stuff rare wonder physical"

    # Generate seed from mnemonic
    seed = seed_from_mnemonic(test_mnemonic, lang='en')

    # Generate master keys
    master_xprv = master_xprv_from_seed(seed)
    master_xpub = master_xprv.xpub()

    # Key derivation using different methods
    # 1. BIP32 derivation from master extended private key
    keys_from_bip32_xprv = bip32_derive_xkeys_from_xkey(master_xprv, 0, 2, BIP32_DERIVATION_PATH, 0)
    # 2. BIP32 derivation from master extended public key
    keys_from_bip32_xpub = bip32_derive_xkeys_from_xkey(master_xpub, 0, 2, BIP32_DERIVATION_PATH, 0)
    # 3. BIP32 derivation directly from mnemonic
    keys_from_bip32_mnemonic = bip32_derive_xprvs_from_mnemonic(test_mnemonic, 0, 2, path=BIP32_DERIVATION_PATH, change=0)

    # Test BIP32 derivation consistency
    for i in range(2):
        assert keys_from_bip32_xprv[i].address() == keys_from_bip32_xpub[i].address(), \
            f"BIP32 xprv/xpub derivation mismatch at index {i}"
        assert keys_from_bip32_xprv[i].address() == keys_from_bip32_mnemonic[i].address(), \
            f"BIP32 xprv/mnemonic derivation mismatch at index {i}"

    # Test BIP44 derivation
    keys_from_bip32_mnemonic = bip32_derive_xprvs_from_mnemonic(test_mnemonic, 0, 2, path=BIP44_DERIVATION_PATH, change=0)
    keys_from_bip44_mnemonic = bip44_derive_xprvs_from_mnemonic(test_mnemonic, 0, 2, path=BIP44_DERIVATION_PATH, change=0)

    # Test BIP44 derivation consistency
    for i in range(2):
        assert keys_from_bip32_mnemonic[i].address() == keys_from_bip44_mnemonic[i].address(), \
            f"BIP32/BIP44 derivation mismatch at index {i}"

def test_invalid_mnemonic():
    with pytest.raises(ValueError):
        invalid_mnemonic = "invalid mnemonic phrase"
        bip32_derive_xprvs_from_mnemonic(invalid_mnemonic, 0, 2, path=BIP32_DERIVATION_PATH, change=0)

def test_invalid_derivation_path():
    test_mnemonic = "skin index hair zone brush soldier airport found stuff rare wonder physical"
    with pytest.raises(ValueError):
        invalid_path = "m/invalid"
        bip32_derive_xprvs_from_mnemonic(test_mnemonic, 0, 2, path=invalid_path, change=0)