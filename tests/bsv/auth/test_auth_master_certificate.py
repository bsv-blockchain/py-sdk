import base64
import pytest

from bsv.auth.master_certificate import MasterCertificate
from bsv.auth.certificate import Outpoint
from bsv.keys import PrivateKey


class EchoWallet:
    """
    Simple mock wallet that encrypts by prefixing b'ENC:' and decrypts by stripping it.
    """

    def encrypt(self, args=None, originator=None):
        plaintext = args.get("plaintext", b"")
        return {"ciphertext": b"ENC:" + plaintext}

    def decrypt(self, args=None, originator=None):
        ciphertext = args.get("ciphertext", b"")
        if isinstance(ciphertext, str):
            ciphertext = base64.b64decode(ciphertext)
        if ciphertext.startswith(b"ENC:"):
            return {"plaintext": ciphertext[4:]}
        return {"plaintext": b""}


def test_create_certificate_fields_and_decrypt_roundtrip_single_field():
    wallet = EchoWallet()
    certifier_or_subject = PrivateKey(5).public_key()
    fields = {"name": "Alice"}

    result = MasterCertificate.create_certificate_fields(wallet, certifier_or_subject, fields)
    assert set(result.keys()) == {"certificateFields", "masterKeyring"}
    cert_fields = result["certificateFields"]
    keyring = result["masterKeyring"]

    # Base64-encoded field ciphertext exists
    assert "name" in cert_fields and isinstance(cert_fields["name"], str)
    # Base64-encoded key ciphertext exists
    assert "name" in keyring and isinstance(keyring["name"], str)

    # Decrypt field via MasterCertificate.decrypt_field
    subject_wallet = wallet
    counterparty = certifier_or_subject
    out = MasterCertificate.decrypt_field(subject_wallet, keyring, "name", cert_fields["name"], counterparty)
    assert out["decryptedFieldValue"] == "Alice"
    assert isinstance(out["fieldRevelationKey"], (bytes, bytearray))


def test_decrypt_fields_multiple():
    wallet = EchoWallet()
    certifier_or_subject = PrivateKey(6).public_key()
    fields = {"name": "Alice", "email": "alice@example.com"}

    result = MasterCertificate.create_certificate_fields(wallet, certifier_or_subject, fields)
    cert_fields = result["certificateFields"]
    keyring = result["masterKeyring"]

    subject_wallet = wallet
    counterparty = certifier_or_subject
    decrypted = MasterCertificate.decrypt_fields(subject_wallet, keyring, cert_fields, counterparty)
    assert decrypted == fields


def test_create_keyring_for_verifier_reencrypts_with_serial_number_in_key_id():
    wallet = EchoWallet()
    certifier = PrivateKey(7).public_key()
    verifier = PrivateKey(8).public_key()
    subject_wallet = wallet

    # Prepare fields/ciphertexts using create_certificate_fields
    fields = {"memberId": "A123"}
    serial_number = base64.b64encode(b"S" * 32).decode("utf-8")
    res = MasterCertificate.create_certificate_fields(subject_wallet, certifier, fields)
    cert_fields = res["certificateFields"]
    master_keyring = res["masterKeyring"]

    # Create keyring for verifier and ensure re-encryption produces non-empty ciphertext
    out_keyring = MasterCertificate.create_keyring_for_verifier(
        subject_wallet,
        certifier,
        verifier,
        cert_fields,
        ["memberId"],
        master_keyring,
        serial_number,
    )
    assert "memberId" in out_keyring
    # Our EchoWallet returns ENC: + plaintext; base64-encoded string should decode to a value starting with b'ENC:'
    decoded = base64.b64decode(out_keyring["memberId"])
    assert decoded.startswith(b"ENC:") and len(decoded) > 4



class WalletWithWireOK:
    def __init__(self, priv: PrivateKey):
        self._priv = priv
        self._pub = priv.public_key()
        # Intentionally different public_key attr to detect fallback non-use
        self.public_key = PrivateKey(999999).public_key()

    def encrypt(self, args=None, originator=None):
        plaintext = args.get("plaintext", b"")
        return {"ciphertext": b"ENC:" + plaintext}

    def get_public_key(self, args=None, originator=None):
        assert args.get("identityKey") is True
        return {"publicKey": self._pub.hex()}

    def create_signature(self, args=None, originator=None):
        # Return a deterministic placeholder signature to ensure priority path
        return {"signature": b"WALLET_SIG"}


def test_issue_uses_get_public_key_identity_true_and_wallet_signature_priority():
    certifier_priv = PrivateKey(12345)
    wallet = WalletWithWireOK(certifier_priv)
    subject = PrivateKey(55555).public_key()
    fields = {"name": "Alice"}
    cert_type_b64 = base64.b64encode(b"T" * 32).decode()

    cert = MasterCertificate.issue_certificate_for_subject(
        wallet,
        subject,
        fields,
        cert_type_b64,
        get_revocation_outpoint=lambda s: Outpoint(txid=("00" * 32), index=0),
        serial_number=base64.b64encode(b"S" * 32).decode(),
    )

    assert cert.certifier.hex() == certifier_priv.public_key().hex()
    assert cert.signature == b"WALLET_SIG"


class WalletWithGetPkErrorAndAttrFallback:
    def __init__(self, priv: PrivateKey):
        self._priv = priv
        self.public_key = priv.public_key()

    def encrypt(self, args=None, originator=None):
        plaintext = args.get("plaintext", b"")
        return {"ciphertext": b"ENC:" + plaintext}

    def get_public_key(self, args=None, originator=None):
        raise RuntimeError("wire error")

    def create_signature(self, args=None, originator=None):
        return {"signature": b"WALLET_SIG"}


def test_issue_get_public_key_exception_then_fallback_to_public_key_attribute():
    certifier_priv = PrivateKey(23456)
    wallet = WalletWithGetPkErrorAndAttrFallback(certifier_priv)
    subject = PrivateKey(77777).public_key()
    cert_type_b64 = base64.b64encode(b"U" * 32).decode()

    cert = MasterCertificate.issue_certificate_for_subject(
        wallet,
        subject,
        {"x": "y"},
        cert_type_b64,
        get_revocation_outpoint=lambda s: Outpoint(txid=("11" * 32), index=1),
    )

    assert cert.certifier.hex() == certifier_priv.public_key().hex()
    assert cert.signature == b"WALLET_SIG"


class WalletGetPkAndAttrMissing:
    def encrypt(self, args=None, originator=None):
        plaintext = args.get("plaintext", b"")
        return {"ciphertext": b"ENC:" + plaintext}

    def get_public_key(self, args=None, originator=None):
        raise RuntimeError("no key")


def test_issue_get_public_key_failure_raises_value_error():
    wallet = WalletGetPkAndAttrMissing()
    subject = PrivateKey(1).public_key()
    cert_type_b64 = base64.b64encode(b"V" * 32).decode()

    with pytest.raises(ValueError):
        MasterCertificate.issue_certificate_for_subject(
            wallet,
            subject,
            {"f": "v"},
            cert_type_b64,
            get_revocation_outpoint=lambda s: Outpoint(txid=("22" * 32), index=2),
        )


class WalletWithFallbackSignOnly:
    def __init__(self, priv: PrivateKey):
        self.private_key = priv

    def encrypt(self, args=None, originator=None):
        plaintext = args.get("plaintext", b"")
        return {"ciphertext": b"ENC:" + plaintext}

    def get_public_key(self, args=None, originator=None):
        # Provide a different key to ensure it is overwritten by fallback signer
        return {"publicKey": PrivateKey(424242).public_key().hex()}

    def create_signature(self, args=None, originator=None):
        # Simulate wallet unable to sign
        return {}


def test_issue_wallet_signature_fallback_to_private_key_and_verify():
    priv = PrivateKey(34567)
    wallet = WalletWithFallbackSignOnly(priv)
    subject = PrivateKey(88888).public_key()
    cert_type_b64 = base64.b64encode(b"W" * 32).decode()

    cert = MasterCertificate.issue_certificate_for_subject(
        wallet,
        subject,
        {"k": "v"},
        cert_type_b64,
        get_revocation_outpoint=lambda s: Outpoint(txid=("33" * 32), index=3),
    )

    assert cert.signature is not None
    # Fallback signer sets certifier from private key used to sign
    assert cert.certifier.hex() == priv.public_key().hex()
    assert cert.verify() is True


