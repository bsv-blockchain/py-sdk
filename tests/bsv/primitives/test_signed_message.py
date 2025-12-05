import pytest

from bsv.signed_message import SignedMessage
from bsv.keys import PrivateKey


def test_signs_message_for_recipient():
    sender = PrivateKey(15)
    recipient = PrivateKey(21)
    recipient_pub = recipient.public_key()
    message = bytes([1, 2, 4, 8, 16, 32])
    signature = SignedMessage.sign(message, sender, verifier=recipient_pub)
    verified = SignedMessage.verify(message, signature, recipient=recipient)
    assert verified is True

def test_signs_message_for_anyone():
    sender = PrivateKey(15)
    message = bytes([1, 2, 4, 8, 16, 32])
    signature = SignedMessage.sign(message, sender)
    verified = SignedMessage.verify(message, signature)
    assert verified is True

def test_fails_to_verify_message_with_wrong_version():
    sender = PrivateKey(15)
    recipient = PrivateKey(21)
    recipient_pub = recipient.public_key()
    message = bytes([1, 2, 4, 8, 16, 32])
    signature = bytearray(SignedMessage.sign(message, sender, verifier=recipient_pub))
    signature[0] = 1  # Altering the version byte
    with pytest.raises(ValueError, match=r'Message version mismatch: Expected 42423301, received 01423301'):
        SignedMessage.verify(message, signature, recipient=recipient)

def test_fails_to_verify_message_with_no_verifier_when_required():
    sender = PrivateKey(15)
    recipient = PrivateKey(21)
    recipient_pub = recipient.public_key()
    message = bytes([1, 2, 4, 8, 16, 32])
    signature = SignedMessage.sign(message, sender, verifier=recipient_pub)
    with pytest.raises(ValueError, match=r'This signature can only be verified with knowledge of a specific private key\. The associated public key is: .*'):
        SignedMessage.verify(message, signature)

def test_fails_to_verify_message_with_wrong_verifier():
    sender = PrivateKey(15)
    recipient = PrivateKey(21)
    wrong_recipient = PrivateKey(22)
    recipient_pub = recipient.public_key()
    message = bytes([1, 2, 4, 8, 16, 32])
    signature = SignedMessage.sign(message, sender, verifier=recipient_pub)
    with pytest.raises(ValueError, match=r'The recipient public key is .* but the signature requires the recipient to have public key .*'):
        SignedMessage.verify(message, signature, recipient=wrong_recipient)
