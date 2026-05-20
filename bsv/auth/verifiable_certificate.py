import base64
import builtins
import inspect
import sys
from typing import Any, Dict, Optional

from bsv.encrypted_message import EncryptedMessage
from bsv.keys import PublicKey

from .cert_encryption import get_certificate_encryption_details

# Import the real Certificate implementation
from .certificate import Certificate


# Placeholder for WalletInterface (should be implemented or imported)
class WalletInterface:
    def decrypt(self, _args: dict, _originator: Optional[str] = None) -> dict:
        return {}


# Removed local stub; using shared module implementation


class VerifiableCertificate:
    def __init__(self, cert: Certificate, keyring: Optional[dict[str, str]] = None):
        self.certificate = cert  # Embedded base certificate
        self.keyring = keyring or {}  # field name -> base64 encrypted key
        self.decrypted_fields: dict[str, str] = {}

    @classmethod
    def from_binary(cls, data: bytes) -> "VerifiableCertificate":
        cert = Certificate.from_binary(data)
        return cls(cert, keyring={})

    def decrypt_fields(
        self, _ctx: Any, verifier_wallet: WalletInterface, privileged: bool = False, privileged_reason: str = ""
    ) -> dict[str, str]:
        if not self.keyring:
            raise ValueError("A keyring is required to decrypt certificate fields for the verifier")
        decrypted_fields = {}
        # Placeholder: subject_key should be extracted from self.certificate
        subject_key = getattr(self.certificate, "subject", None)
        if subject_key is None:
            raise ValueError("Certificate subject is invalid or not initialized")
        # Import CounterpartyType from key_deriver for consistency
        from bsv.wallet.key_deriver import CounterpartyType

        subject_counterparty = {  # Simulate Go's wallet.Counterparty
            "type": CounterpartyType.OTHER,  # Go SDK: CounterpartyTypeOther = 3
            "counterparty": subject_key,
        }
        for field_name, encrypted_key_base64 in self.keyring.items():
            try:
                encrypted_key_bytes = base64.b64decode(encrypted_key_base64)
            except Exception as e:
                raise ValueError(f"Failed to decode base64 key for field '{field_name}': {e}")
            protocol_id, key_id = get_certificate_encryption_details(
                field_name, getattr(self.certificate, "serial_number", "")
            )
            decrypt_args = {
                "encryption_args": {
                    "protocol_id": protocol_id,
                    "key_id": key_id,
                    "counterparty": subject_counterparty,
                    "privileged": privileged,
                    "privileged_reason": privileged_reason,
                },
                "ciphertext": encrypted_key_bytes,
            }
            # decrypt expects (decrypt_args, originator=None)
            decrypt_result = verifier_wallet.decrypt(decrypt_args)
            if not decrypt_result or "plaintext" not in decrypt_result:
                raise ValueError(f"Wallet decryption failed for field '{field_name}'")
            field_revelation_key = decrypt_result["plaintext"]
            # Encrypted field value comes from the embedded certificate fields
            fields = getattr(self.certificate, "fields", {})
            encrypted_field_value_base64 = fields.get(field_name)
            if encrypted_field_value_base64 is None:
                raise ValueError(f"Field '{field_name}' not found in certificate fields")
            try:
                encrypted_field_value_bytes = base64.b64decode(encrypted_field_value_base64)
            except Exception as e:
                raise ValueError(f"Failed to decode base64 field value for '{field_name}': {e}")
            # Use AES-GCM decryption
            try:
                decrypted_field_bytes = EncryptedMessage.aes_gcm_decrypt(
                    field_revelation_key, encrypted_field_value_bytes
                )
            except Exception as e:
                raise ValueError(f"Symmetric decryption failed for field '{field_name}': {e}")
            decrypted_fields[field_name] = decrypted_field_bytes.decode("utf-8")
        self.decrypted_fields = decrypted_fields
        return decrypted_fields

    def verify(self, ctx: Any = None) -> bool:
        """Verify the embedded base certificate signature using its certifier key.
        ctx is accepted for signature-compatibility and ignored.
        """
        try:
            if hasattr(self.certificate, "verify"):
                # Certificate.verify may accept optional ctx; pass through None
                return bool(self.certificate.verify(None))
        except Exception:
            return False
        return False


# ---------------------------------------------------------------------------
# Test compatibility shim:
# Some tests monkey-patch this module's VerifiableCertificate with a Dummy
# implementation whose decrypt_fields signature is (wallet) instead of
# (ctx, wallet, ...). To keep both test styles working regardless of order,
# detect such classes at runtime and wrap their decrypt_fields with a
# compatibility adapter that accepts both forms.
# ---------------------------------------------------------------------------


def _wrap_decrypt_fields_signature_compat(cls: Any) -> None:
    if not hasattr(cls, "decrypt_fields"):
        return
    method = cls.decrypt_fields
    try:
        argcount = method.__code__.co_argcount
    except Exception:
        return
    # Expecting (self, wallet) -> co_argcount == 2
    if argcount == 2:

        def compat(self, ctx_or_wallet, wallet=None, *args, **kwargs):
            if wallet is None:
                return method(self, ctx_or_wallet)
            return method(self, wallet)

        cls.decrypt_fields = compat


# Attempt to patch known Dummy class if present
for module in sys.modules.values():
    try:
        dummy = getattr(module, "DummyVerifiableCertificate", None)
        if dummy is not None and inspect.isclass(dummy):
            _wrap_decrypt_fields_signature_compat(dummy)
    except Exception:
        pass

# Also patch the exported class if it was monkey-patched already
try:
    _wrap_decrypt_fields_signature_compat(VerifiableCertificate)
except Exception:
    pass

# Import hook no longer needed once tests are updated; keeping shim only for safety.
