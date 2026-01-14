from base64 import b64encode

from Cryptodome.Cipher import AES

from .keys import PrivateKey, PublicKey
from .utils import randbytes


class EncryptedMessage:
    VERSION = bytes.fromhex("42421033")

    @staticmethod
    def aes_gcm_encrypt(key: bytes, message: bytes) -> bytes:
        iv = randbytes(32)
        encrypted, auth_tag = AES.new(key, AES.MODE_GCM, iv).encrypt_and_digest(message)
        return iv + encrypted + auth_tag

    @staticmethod
    def aes_gcm_decrypt(key: bytes, message: bytes) -> bytes:
        iv, encrypted, auth_tag = message[:32], message[32:-16], message[-16:]
        return AES.new(key, AES.MODE_GCM, iv).decrypt_and_verify(encrypted, auth_tag)

    @classmethod
    def encrypt(cls, message: bytes, sender: PrivateKey, recipient: PublicKey) -> bytes:
        key_id = randbytes(32)
        key_id_base64 = b64encode(key_id).decode("ascii")
        invoice_number = f"2-message encryption-{key_id_base64}"
        sender_child = sender.derive_child(recipient, invoice_number)
        recipient_child = recipient.derive_child(sender, invoice_number)
        shared_secret = sender_child.derive_shared_secret(recipient_child)
        symmetric_key = shared_secret[1:]
        encrypted = cls.aes_gcm_encrypt(symmetric_key, message)
        return cls.VERSION + sender.public_key().serialize() + recipient.serialize() + key_id + encrypted

    @classmethod
    def decrypt(cls, message: bytes, recipient: PrivateKey) -> bytes:
        try:
            version = message[:4]
            sender_pubkey, recipient_pubkey = message[4:37], message[37:70]
            key_id = message[70:102]
            encrypted = message[102:]
            if version != cls.VERSION:
                raise ValueError(f"message version mismatch, expected {cls.VERSION.hex()} but got {version.hex()}")
            if recipient_pubkey != recipient.public_key().serialize():
                _expected = recipient.public_key().hex()
                _actual = recipient_pubkey.hex()
                raise ValueError(f"recipient public key mismatch, expected {_expected} but got {_actual}")
            key_id_base64 = b64encode(key_id).decode("ascii")
            invoice_number = f"2-message encryption-{key_id_base64}"
            sender = PublicKey(sender_pubkey)
            sender_child = sender.derive_child(recipient, invoice_number)
            recipient_child = recipient.derive_child(sender, invoice_number)
            shared_secret = sender_child.derive_shared_secret(recipient_child)
            symmetric_key = shared_secret[1:]
            return cls.aes_gcm_decrypt(symmetric_key, encrypted)
        except Exception as e:
            raise ValueError(f"failed to decrypt message: {e}") from e
