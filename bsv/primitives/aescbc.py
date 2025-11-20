import hmac
from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC, SHA256

class InvalidPadding(Exception):
    pass

def PKCS7Padd(data: bytes, block_size: int) -> bytes:
    padding = block_size - (len(data) % block_size)
    return data + bytes([padding]) * padding

def PKCS7Unpad(data: bytes, block_size: int) -> bytes:
    length = len(data)
    if length % block_size != 0 or length == 0:
        raise InvalidPadding("invalid padding length")
    padding = data[-1]
    if padding > block_size:
        raise InvalidPadding("invalid padding byte (large)")
    if not all(x == padding for x in data[-padding:]):
        raise InvalidPadding("invalid padding byte (inconsistent)")
    return data[:-padding]

def AESCBCEncrypt(data: bytes, key: bytes, iv: bytes, concat_iv: bool) -> bytes:
    block_size = AES.block_size
    padded = PKCS7Padd(data, block_size)
    # AES-CBC is used with HMAC-SHA256 for authenticated encryption (see aes_cbc_encrypt_mac)
    cipher = AES.new(key, AES.MODE_CBC, iv)  # noqa: S305 - CBC mode with HMAC provides authenticated encryption
    ciphertext = cipher.encrypt(padded)
    if concat_iv:
        return iv + ciphertext
    return ciphertext

def AESCBCDecrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    block_size = AES.block_size
    # AES-CBC is used with HMAC-SHA256 for authenticated encryption (see aes_cbc_decrypt_mac)
    cipher = AES.new(key, AES.MODE_CBC, iv)  # noqa: S305 - CBC mode with HMAC provides authenticated encryption
    plaintext = cipher.decrypt(data)
    return PKCS7Unpad(plaintext, block_size)

def aes_encrypt_with_iv(key: bytes, iv: bytes, data: bytes) -> bytes:
    # 既存のAESCBCEncryptの引数順に合わせてラップ
    return AESCBCEncrypt(data, key, iv, concat_iv=False)

def aes_decrypt_with_iv(key: bytes, iv: bytes, data: bytes) -> bytes:
    # 既存のAESCBCDecryptの引数順に合わせてラップ
    return AESCBCDecrypt(data, key, iv)

# --- Encrypt-then-MAC helpers (Go ECIES compatible) ---

def aes_cbc_encrypt_mac(data: bytes, key_e: bytes, iv: bytes, mac_key: bytes, concat_iv: bool = True) -> bytes:
    """AES-CBC Encrypt then append HMAC-SHA256 (iv|cipher|mac).

    Parameters
    ----------
    data: Plaintext bytes to encrypt.
    key_e: 32-byte AES key.
    iv: 16-byte IV.
    mac_key: 32-byte key for HMAC-SHA256.
    concat_iv: If True (default) prepend iv to ciphertext as Go implementation does.

    Returns
    -------
    bytes
        iv|ciphertext|mac if concat_iv else ciphertext|mac
    """
    cipher_text = AESCBCEncrypt(data, key_e, iv, concat_iv)
    # data used for MAC (same as Go: iv concatenated if concat_iv True)
    # cipher_text already includes iv when concat_iv is True
    mac_input = cipher_text
    mac = HMAC.new(mac_key, mac_input, SHA256).digest()
    return mac_input + mac


def aes_cbc_decrypt_mac(blob: bytes, key_e: bytes, iv: bytes | None, mac_key: bytes, concat_iv: bool = True) -> bytes:
    """Verify HMAC then decrypt AES-CBC message produced by aes_cbc_encrypt_mac.

    Parameters
    ----------
    blob: iv|cipher|mac (or cipher|mac if concat_iv False).
    key_e: AES key.
    iv: If concat_iv is False the IV must be supplied here; otherwise extracted from blob.
    mac_key: HMAC-SHA256 key.
    concat_iv: Matches value used during encryption.

    Returns
    -------
    Plaintext bytes.
    """
    if len(blob) < 48:  # 16 iv + 16 min cipher + 16 mac -> 48 minimal
        raise ValueError("ciphertext too short")

    mac_len = 32  # SHA256 digest size
    mac_received = blob[-mac_len:]
    mac_input = blob[:-mac_len]

    # constant-time comparison
    mac_calculated = HMAC.new(mac_key, mac_input, SHA256).digest()
    if not hmac.compare_digest(mac_received, mac_calculated):
        raise ValueError("HMAC verification failed")

    if concat_iv:
        iv_extracted = mac_input[:16]
        cipher_text = mac_input[16:]
        iv_final = iv_extracted
    else:
        if iv is None:
            raise ValueError("IV must be provided when concat_iv is False")
        cipher_text = mac_input
        iv_final = iv

    return AESCBCDecrypt(cipher_text, key_e, iv_final)
