import pytest
from binascii import unhexlify
from bsv.aes_gcm import aes_gcm_encrypt, aes_gcm_decrypt, ghash

def hex2bytes(s):
    return unhexlify(s.encode()) if s else b""

def test_aes_gcm_vectors():
    # 各テストケースは go-sdk/primitives/aesgcm/aesgcm_test.go に準拠
    test_cases = [
        # name, plaintext, aad, iv, key, expected_ciphertext, expected_tag
        ("Test Case 1", "", "", "000000000000000000000000", "00000000000000000000000000000000", "", "58e2fccefa7e3061367f1d57a4e7455a"),
        ("Test Case 2", "00000000000000000000000000000000", "", "000000000000000000000000", "00000000000000000000000000000000", "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf"),
        ("Test Case 3", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", "", "cafebabefacedbaddecaf888", "feffe9928665731c6d6a8f9467308308", "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985", "4d5c2af327cd64a62cf35abd2ba6fab4"),
        # ...（省略: goの全ベクトルをここに追加）...
    ]
    for name, pt, aad, iv, key, exp_ct, exp_tag in test_cases:
        pt_b = hex2bytes(pt)
        aad_b = hex2bytes(aad)
        iv_b = hex2bytes(iv)
        key_b = hex2bytes(key)
        exp_ct_b = hex2bytes(exp_ct)
        exp_tag_b = hex2bytes(exp_tag)
        ct, tag = aes_gcm_encrypt(pt_b, key_b, iv_b, aad_b)
        assert ct == exp_ct_b, f"{name}: ciphertext mismatch"
        assert tag == exp_tag_b, f"{name}: tag mismatch"
        # 復号も確認
        pt2 = aes_gcm_decrypt(ct, key_b, iv_b, tag, aad_b)
        assert pt2 == pt_b, f"{name}: decrypt mismatch"

def test_ghash():
    # go-sdk/primitives/aesgcm/aesgcm_test.go TestGhash 準拠
    input_data = unhexlify("000000000000000000000000000000000388dace60b6a392f328c2b971b2fe7800000000000000000000000000000080")  # NOSONAR - renamed to avoid shadowing builtin
    hash_subkey = unhexlify("66e94bd4ef8a2c3b884cfa59ca342b2e")
    expected = unhexlify("f38cbb1ad69223dcc3457ae5b6b0f885")
    actual = ghash(input_data, hash_subkey)
    assert actual == expected, f"ghash mismatch: got {actual.hex()} want {expected.hex()}"
