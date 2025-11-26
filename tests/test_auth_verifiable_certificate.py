import base64
import pytest

from bsv.auth.certificate import Certificate, Outpoint
from bsv.auth.verifiable_certificate import VerifiableCertificate
from bsv.encrypted_message import EncryptedMessage
from bsv.keys import PrivateKey


class MockWallet:
    def __init__(self, expected_ciphertexts_to_plaintexts: dict[bytes, bytes]):
        self._map = expected_ciphertexts_to_plaintexts

    def decrypt(self, ctx, decrypt_args: dict):
        ciphertext = decrypt_args.get("ciphertext", b"")
        # Return the mapped plaintext if known; otherwise a default value
        if ciphertext in self._map:
            return {"plaintext": self._map[ciphertext]}
        # Default for tests
        return {"plaintext": b""}


def make_certificate_with_encrypted_field(field_name: str, field_value: str):
    # Symmetric key for the field
    field_key = b"K" * 32
    encrypted_field_bytes = EncryptedMessage.aes_gcm_encrypt(field_key, field_value.encode("utf-8"))
    encrypted_field_b64 = base64.b64encode(encrypted_field_bytes).decode("utf-8")

    cert_type = base64.b64encode(b"A" * 32).decode()
    serial = base64.b64encode(b"B" * 32).decode()
    subject = PrivateKey(100).public_key()
    certifier = PrivateKey(101).public_key()
    outpoint = Outpoint(txid=("00" * 32), index=0)
    fields = {field_name: encrypted_field_b64}
    cert = Certificate(cert_type, serial, subject, certifier, outpoint, fields)

    # Prepare keyring entry for verifier: encrypted symmetric key bytes (wallet.decrypt ignores content mapping)
    encrypted_key_bytes = b"EK" * 8
    keyring = {field_name: base64.b64encode(encrypted_key_bytes).decode("utf-8")}

    # Wallet will return plaintext symmetric key when given the encrypted_key_bytes
    wallet = MockWallet({encrypted_key_bytes: field_key})
    return cert, keyring, wallet


class TestVerifiableCertificate:
    def test_decrypt_fields_success(self):
        cert, keyring, wallet = make_certificate_with_encrypted_field("name", "Alice")
        vc = VerifiableCertificate(cert, keyring)
        decrypted = vc.decrypt_fields(None, wallet)
        assert decrypted["name"] == "Alice"

    def test_decrypt_fields_requires_keyring(self):
        cert, _, wallet = make_certificate_with_encrypted_field("name", "Alice")
        vc = VerifiableCertificate(cert, {})
        with pytest.raises(ValueError):
            vc.decrypt_fields(None, wallet)

    def test_missing_field_in_certificate_raises(self):
        cert, keyring, wallet = make_certificate_with_encrypted_field("name", "Alice")
        # Change field name in keyring to one not present in cert.fields
        wrong_keyring = {"unknown": keyring["name"]}
        vc = VerifiableCertificate(cert, wrong_keyring)
        with pytest.raises(ValueError):
            vc.decrypt_fields(None, wallet)



