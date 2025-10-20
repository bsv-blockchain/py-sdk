import pytest
from Cryptodome.Random import get_random_bytes
from bsv.primitives.aescbc import AESCBCEncrypt, AESCBCDecrypt, InvalidPadding


def test_aescbc_encrypt_decrypt():
    key = b"0123456789abcdef0123456789abcdef"  # 32 bytes
    iv = b"0123456789abcdef"  # 16 bytes
    data = b"Test data"

    # Normal encryption/decryption
    ct = AESCBCEncrypt(data, key, iv, concat_iv=False)
    pt = AESCBCDecrypt(ct, key, iv)
    assert pt == data

    # With concat_iv
    ct2 = AESCBCEncrypt(data, key, iv, concat_iv=True)
    assert ct2[:16] == iv
    pt2 = AESCBCDecrypt(ct2[16:], key, iv)
    assert pt2 == data

    # Long message
    long_data = b"This is a longer message that spans multiple AES blocks. " * 3
    ct3 = AESCBCEncrypt(long_data, key, iv, concat_iv=False)
    pt3 = AESCBCDecrypt(ct3, key, iv)
    assert pt3 == long_data

    # Invalid key length
    with pytest.raises(ValueError):
        AESCBCEncrypt(data, b"shortkey", iv, concat_iv=False)

    # Invalid IV length
    with pytest.raises(ValueError):
        AESCBCEncrypt(data, key, b"shortiv", concat_iv=False)

    # Invalid padding (tampered ciphertext)
    bad_ct = bytearray(ct)
    bad_ct[-1] ^= 0xFF
    with pytest.raises(InvalidPadding):
        AESCBCDecrypt(bytes(bad_ct), key, iv)
