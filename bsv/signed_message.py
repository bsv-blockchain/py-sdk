from base64 import b64encode

from .curve import curve, curve_multiply
from .keys import PrivateKey, PublicKey
from .utils import Reader, randbytes


class SignedMessage:
    VERSION = bytes.fromhex("42423301")

    @staticmethod
    def sign(message: bytes, signer: PrivateKey, verifier: PublicKey = None) -> bytes:
        """
        Signs a message from one party to be verified by another, or for verification by anyone, using the BRC-77 message signing protocol.
        :param message: The message to sign
        :param signer: The private key of the message signer
        :param verifier: The public key of the person who can verify the message. If not provided, anyone will be able to verify the message signature.
        :return: The message signature.
        """
        recipient_anyone = verifier is None
        if recipient_anyone:
            anyone_point = curve_multiply(1, curve.g)
            verifier = PublicKey(anyone_point)

        # key_id = randbytes(32)
        key_id = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
        key_id_base64 = b64encode(key_id).decode("ascii")
        invoice_number = f"2-message signing-{key_id_base64}"
        signing_key = signer.derive_child(verifier, invoice_number)
        signature = signing_key.sign(message)
        signer_public_key = signer.public_key().serialize()
        version = SignedMessage.VERSION
        return (
            version + signer_public_key + (b"\x00" if recipient_anyone else verifier.serialize()) + key_id + signature
        )

    @staticmethod
    def verify(message: bytes, sig: bytes, recipient: PrivateKey = None) -> bool:
        """
        Verifies a message using the BRC-77 message signing protocol.
        :param message: The message to verify.
        :param sig: The message signature to be verified.
        :param recipient: The private key of the message verifier. This can be omitted if the message is verifiable by anyone.
        :return: True if the message is verified.
        """
        reader = Reader(sig)
        message_version = reader.read(4)
        if message_version != SignedMessage.VERSION:
            raise ValueError(
                f"Message version mismatch: Expected {SignedMessage.VERSION.hex()}, received {message_version.hex()}"
            )

        signer = PublicKey(reader.read(33))
        verifier_first = reader.read(1)[0]

        if verifier_first == 0:
            recipient = PrivateKey(1)
        else:
            verifier_rest = reader.read(32)
            verifier_der = bytes([verifier_first]) + verifier_rest
            if recipient is None:
                raise ValueError(
                    f"This signature can only be verified with knowledge of a specific private key. The associated public key is: {verifier_der.hex()}"
                )

            recipient_der = recipient.public_key().serialize()
            if verifier_der != recipient_der:
                raise ValueError(
                    f"The recipient public key is {recipient_der.hex()} but the signature requires the recipient to have public key {verifier_der.hex()}"
                )

        key_id = b64encode(reader.read(32)).decode("ascii")
        signature_der = reader.read(len(sig) - reader.tell())
        invoice_number = f"2-message signing-{key_id}"
        signing_key = signer.derive_child(recipient, invoice_number)
        print(signing_key.serialize().hex())
        return signing_key.verify(signature_der, message)
