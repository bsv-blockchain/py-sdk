import pytest
from Cryptodome.Random import get_random_bytes
from bsv.primitives.aescbc import (
    AESCBCEncrypt,
    AESCBCDecrypt,
    InvalidPadding,
    PKCS7Padd,
    PKCS7Unpad,
    aes_encrypt_with_iv,
    aes_decrypt_with_iv,
    aes_cbc_encrypt_mac,
    aes_cbc_decrypt_mac,
)


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


def test_pkcs7_padding():
    """Test PKCS7 padding and unpadding."""
    # Test padding for different data lengths
    data1 = b"test"
    padded1 = PKCS7Padd(data1, 16)
    assert len(padded1) % 16 == 0
    unpadded1 = PKCS7Unpad(padded1, 16)
    assert unpadded1 == data1
    
    # Test with exact block size
    data2 = b"0123456789abcdef"  # Exactly 16 bytes
    padded2 = PKCS7Padd(data2, 16)
    assert len(padded2) == 32  # Should add full block of padding
    unpadded2 = PKCS7Unpad(padded2, 16)
    assert unpadded2 == data2
    
    # Test empty data
    data3 = b""
    padded3 = PKCS7Padd(data3, 16)
    assert len(padded3) == 16  # Should be one block of padding
    unpadded3 = PKCS7Unpad(padded3, 16)
    assert unpadded3 == b""


def test_pkcs7_unpad_errors():
    """Test PKCS7 unpadding error conditions."""
    # Test with invalid padding length (not multiple of block size)
    with pytest.raises(InvalidPadding, match="invalid padding length"):
        PKCS7Unpad(b"test", 16)
    
    # Test with empty data
    with pytest.raises(InvalidPadding, match="invalid padding length"):
        PKCS7Unpad(b"", 16)
    
    # Test with invalid padding byte (too large)
    bad_padding = b"\x00" * 15 + b"\x11"  # 17 > block_size 16
    with pytest.raises(InvalidPadding, match="invalid padding byte"):
        PKCS7Unpad(bad_padding, 16)


def test_aes_encrypt_decrypt_with_iv_wrappers():
    """Test the aes_encrypt_with_iv and aes_decrypt_with_iv wrapper functions."""
    key = b"0123456789abcdef0123456789abcdef"  # 32 bytes
    iv = b"0123456789abcdef"  # 16 bytes
    data = b"Test data for wrappers"
    
    # Test encryption wrapper
    encrypted = aes_encrypt_with_iv(key, iv, data)
    assert isinstance(encrypted, bytes)
    assert len(encrypted) > len(data)  # Should be padded
    
    # Test decryption wrapper
    decrypted = aes_decrypt_with_iv(key, iv, encrypted)
    assert decrypted == data
    
    # Round trip test
    for test_data in [b"short", b"exactly16bytes!!", b"a" * 100]:
        enc = aes_encrypt_with_iv(key, iv, test_data)
        dec = aes_decrypt_with_iv(key, iv, enc)
        assert dec == test_data


def test_aes_cbc_encrypt_mac():
    """Test AES-CBC encryption with HMAC."""
    key_e = b"0123456789abcdef0123456789abcdef"  # 32 bytes AES key
    mac_key = b"fedcba9876543210fedcba9876543210"  # 32 bytes MAC key
    iv = b"0123456789abcdef"  # 16 bytes IV
    data = b"Test data for encrypt-then-MAC"
    
    # Test with concat_iv=True (default)
    encrypted_mac = aes_cbc_encrypt_mac(data, key_e, iv, mac_key, concat_iv=True)
    assert isinstance(encrypted_mac, bytes)
    assert len(encrypted_mac) > len(data)
    # Should include: iv (16) + ciphertext + mac (32)
    assert len(encrypted_mac) >= 16 + 16 + 32  # At least iv + one block + mac
    
    # Test with concat_iv=False
    encrypted_mac_no_iv = aes_cbc_encrypt_mac(data, key_e, iv, mac_key, concat_iv=False)
    assert isinstance(encrypted_mac_no_iv, bytes)
    # Should include: ciphertext + mac (32)
    assert len(encrypted_mac_no_iv) >= 16 + 32  # At least one block + mac
    
    # Test with empty data
    empty_encrypted = aes_cbc_encrypt_mac(b"", key_e, iv, mac_key)
    assert isinstance(empty_encrypted, bytes)
    assert len(empty_encrypted) > 0  # Should have padding, iv, and mac


def test_aes_cbc_decrypt_mac():
    """Test AES-CBC decryption with HMAC verification."""
    key_e = b"0123456789abcdef0123456789abcdef"
    mac_key = b"fedcba9876543210fedcba9876543210"
    iv = b"0123456789abcdef"
    data = b"Test data for encrypt-then-MAC round trip"
    
    # Test with concat_iv=True
    encrypted_mac = aes_cbc_encrypt_mac(data, key_e, iv, mac_key, concat_iv=True)
    decrypted = aes_cbc_decrypt_mac(encrypted_mac, key_e, None, mac_key, concat_iv=True)
    assert decrypted == data
    
    # Test with concat_iv=False
    encrypted_mac_no_iv = aes_cbc_encrypt_mac(data, key_e, iv, mac_key, concat_iv=False)
    decrypted_no_iv = aes_cbc_decrypt_mac(encrypted_mac_no_iv, key_e, iv, mac_key, concat_iv=False)
    assert decrypted_no_iv == data


def test_aes_cbc_decrypt_mac_errors():
    """Test error handling in aes_cbc_decrypt_mac."""
    key_e = b"0123456789abcdef0123456789abcdef"
    mac_key = b"fedcba9876543210fedcba9876543210"
    iv = b"0123456789abcdef"
    
    # Test with too short blob
    with pytest.raises(ValueError, match="ciphertext too short"):
        aes_cbc_decrypt_mac(b"short", key_e, None, mac_key, concat_iv=True)
    
    # Test with invalid MAC
    data = b"Test data"
    encrypted_mac = aes_cbc_encrypt_mac(data, key_e, iv, mac_key, concat_iv=True)
    # Tamper with MAC
    tampered = bytearray(encrypted_mac)
    tampered[-1] ^= 0xFF
    with pytest.raises(ValueError, match="HMAC verification failed"):
        aes_cbc_decrypt_mac(bytes(tampered), key_e, None, mac_key, concat_iv=True)
    
    # Test with missing IV when concat_iv=False
    encrypted_no_iv = aes_cbc_encrypt_mac(data, key_e, iv, mac_key, concat_iv=False)
    with pytest.raises(ValueError, match="IV must be provided"):
        aes_cbc_decrypt_mac(encrypted_no_iv, key_e, None, mac_key, concat_iv=False)


def test_aes_cbc_encrypt_decrypt_mac_round_trip():
    """Test complete round trip with various data sizes."""
    key_e = b"0123456789abcdef0123456789abcdef"
    mac_key = b"fedcba9876543210fedcba9876543210"
    iv = b"0123456789abcdef"
    
    # Test with various data sizes
    test_data_sets = [
        b"",
        b"a",
        b"short text",
        b"exactly16bytes!!",
        b"a" * 100,
        b"Long text " * 50,
    ]
    
    for data in test_data_sets:
        # With concat_iv=True
        encrypted_mac = aes_cbc_encrypt_mac(data, key_e, iv, mac_key, concat_iv=True)
        decrypted = aes_cbc_decrypt_mac(encrypted_mac, key_e, None, mac_key, concat_iv=True)
        assert decrypted == data, f"Round trip failed for data length {len(data)}"
        
        # With concat_iv=False
        encrypted_mac_no_iv = aes_cbc_encrypt_mac(data, key_e, iv, mac_key, concat_iv=False)
        decrypted_no_iv = aes_cbc_decrypt_mac(encrypted_mac_no_iv, key_e, iv, mac_key, concat_iv=False)
        assert decrypted_no_iv == data, f"Round trip (no concat_iv) failed for data length {len(data)}"


def test_aes_cbc_mac_with_random_data():
    """Test encrypt/decrypt with random keys and IVs."""
    key_e = get_random_bytes(32)
    mac_key = get_random_bytes(32)
    iv = get_random_bytes(16)
    data = b"Random test data" * 10
    
    encrypted_mac = aes_cbc_encrypt_mac(data, key_e, iv, mac_key)
    decrypted = aes_cbc_decrypt_mac(encrypted_mac, key_e, None, mac_key)
    assert decrypted == data
