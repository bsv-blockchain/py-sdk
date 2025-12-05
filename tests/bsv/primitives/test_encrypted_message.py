import pytest

from bsv.encrypted_message import EncryptedMessage
from bsv.keys import PrivateKey
from bsv.utils import randbytes


def test_aes_gcm():
    key = randbytes(32)
    message = 'hello world'.encode('utf-8')
    encrypted = EncryptedMessage.aes_gcm_encrypt(key, message)
    decrypted = EncryptedMessage.aes_gcm_decrypt(key, encrypted)
    assert decrypted == message


def test_brc78():
    message = 'hello world'.encode('utf-8')
    sender_priv, recipient_priv = PrivateKey(), PrivateKey()
    encrypted = EncryptedMessage.encrypt(message, sender_priv, recipient_priv.public_key())
    decrypted = EncryptedMessage.decrypt(encrypted, recipient_priv)
    assert decrypted == message

    with pytest.raises(ValueError, match=r'message version mismatch'):
        EncryptedMessage.decrypt(encrypted[1:], PrivateKey())
    with pytest.raises(ValueError, match=r'recipient public key mismatch'):
        EncryptedMessage.decrypt(encrypted, PrivateKey())
    with pytest.raises(ValueError, match=r'failed to decrypt message'):
        EncryptedMessage.decrypt(encrypted[:-1], recipient_priv)
