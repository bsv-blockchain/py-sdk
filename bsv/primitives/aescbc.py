from Cryptodome.Cipher import AES

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
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded)
    if concat_iv:
        return iv + ciphertext
    return ciphertext

def AESCBCDecrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    block_size = AES.block_size
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(data)
    return PKCS7Unpad(plaintext, block_size)

def aes_encrypt_with_iv(key: bytes, iv: bytes, data: bytes) -> bytes:
    # 既存のAESCBCEncryptの引数順に合わせてラップ
    return AESCBCEncrypt(data, key, iv, concat_iv=False)

def aes_decrypt_with_iv(key: bytes, iv: bytes, data: bytes) -> bytes:
    # 既存のAESCBCDecryptの引数順に合わせてラップ
    return AESCBCDecrypt(data, key, iv)
