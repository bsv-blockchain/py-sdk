from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding

class AESGCMError(Exception):
    pass

def aes_gcm_encrypt(plaintext: bytes, key: bytes, iv: bytes, aad: bytes = b""):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag

def aes_gcm_decrypt(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes, aad: bytes = b""):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    cipher.update(aad)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError as e:
        raise AESGCMError(f"decryption failed: {e}")

# --- GHASH utilities (for test vector compatibility, optional) ---
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def right_shift(block: bytes) -> bytes:
    b = bytearray(block)
    carry = 0
    for i in range(len(b)):
        old_carry = carry
        carry = b[i] & 0x01
        b[i] >>= 1
        if old_carry:
            b[i] |= 0x80
    return bytes(b)

def check_bit(block: bytes, index: int, bit: int) -> bool:
    return ((block[index] >> bit) & 1) == 1

def multiply(block0: bytes, block1: bytes) -> bytes:
    v = bytearray(block1)
    z = bytearray(16)
    r = bytearray([0xe1] + [0x00]*15)
    for i in range(16):
        for j in range(7, -1, -1):
            if check_bit(block0, i, j):
                z = bytearray(x ^ y for x, y in zip(z, v))
            if check_bit(v, 15, 0):
                v = bytearray(x ^ y for x, y in zip(right_shift(v), r))
            else:
                v = bytearray(right_shift(v))
    return bytes(z)

def ghash(input_bytes: bytes, hash_subkey: bytes) -> bytes:
    result = bytes(16)
    for i in range(0, len(input_bytes), 16):
        block = input_bytes[i:i+16]
        if len(block) < 16:
            block = block + b"\x00" * (16 - len(block))
        result = multiply(xor_bytes(result, block), hash_subkey)
    return result
