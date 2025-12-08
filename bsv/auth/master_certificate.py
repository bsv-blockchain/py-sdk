from typing import Dict, Optional, Any, List, Callable
import base64
import os
from .certificate import Certificate
from bsv.encrypted_message import EncryptedMessage
from bsv.auth.cert_encryption import get_certificate_encryption_details

Base64String = str
CertificateFieldNameUnder50Bytes = str
class MasterCertificate(Certificate):
    def __init__(
        self,
        cert_type: str,
        serial_number: str,
        subject: Any,
        certifier: Any,
        revocation_outpoint: Optional[Any],
        fields: Dict[str, str],
        signature: Optional[bytes] = None,
        master_keyring: Optional[Dict[CertificateFieldNameUnder50Bytes, Base64String]] = None,
    ):
        super().__init__(
            cert_type,
            serial_number,
            subject,
            certifier,
            revocation_outpoint,
            fields,
            signature,
        )
        self.master_keyring: Dict[CertificateFieldNameUnder50Bytes, Base64String] = master_keyring or {}

    @staticmethod
    def create_certificate_fields(creator_wallet: Any, certifier_or_subject: Any, fields: Dict[CertificateFieldNameUnder50Bytes, str], privileged: bool = False, privileged_reason: Optional[str] = None) -> Dict[str, Any]:
        certificate_fields: Dict[CertificateFieldNameUnder50Bytes, Base64String] = {}
        master_keyring: Dict[CertificateFieldNameUnder50Bytes, Base64String] = {}
        for field_name, field_value in fields.items():
            symmetric_key = os.urandom(32)
            encrypted_field_bytes = EncryptedMessage.aes_gcm_encrypt(symmetric_key, field_value.encode('utf-8'))
            encrypted_field_b64 = base64.b64encode(encrypted_field_bytes).decode('utf-8')
            certificate_fields[field_name] = encrypted_field_b64
            protocol_id, key_id = get_certificate_encryption_details(field_name, None)
            # BRC-100 flat args structure (TypeScript/Go parity)
            encrypt_args = {
                "protocolID": protocol_id,
                "keyID": key_id,
                "counterparty": certifier_or_subject,
                "privileged": privileged,
                "privilegedReason": privileged_reason,
                "plaintext": symmetric_key,
            }
            # wallet.encrypt(args, originator) - originator is optional
            encrypt_result = creator_wallet.encrypt(encrypt_args)
            encrypted_key_bytes = encrypt_result["ciphertext"]
            encrypted_key_b64 = base64.b64encode(encrypted_key_bytes).decode('utf-8')
            master_keyring[field_name] = encrypted_key_b64
        return {'certificateFields': certificate_fields, 'masterKeyring': master_keyring}

    @staticmethod
    def _resolve_public_key(wallet: Any, fallback: Any = None) -> Any:
        """
        Resolve the public key from the wallet. If it fails, return the fallback.
        """
        from bsv.keys import PublicKey
        pubkey = None
        try:
            # BRC-100 args structure: wallet.get_public_key(args, originator)
            get_pk_args = {"identityKey": True}
            res = wallet.get_public_key(get_pk_args)
            if isinstance(res, dict):
                pk_bytes_or_hex = res.get("publicKey")
                if pk_bytes_or_hex:
                    pubkey = PublicKey(pk_bytes_or_hex)
        except Exception:
            pubkey = None
        if pubkey is None:
            try:
                pubkey = getattr(wallet, "public_key", None)
            except Exception:
                pubkey = None
        if pubkey is None and fallback is not None:
            pubkey = fallback
        return pubkey

    @staticmethod
    def _resolve_subject_public_key(subject: Any, certifier_pubkey: Any) -> Any:
        from bsv.keys import PublicKey

        # If already a PublicKey instance
        if isinstance(subject, PublicKey):
            return subject

        # If provided as bytes/bytearray/hex string
        if isinstance(subject, (bytes, bytearray, str)):
            try:
                return PublicKey(subject)
            except Exception:
                return certifier_pubkey

        # If provided as a dict descriptor
        if isinstance(subject, dict):
            stype = subject.get("type")
            if stype in (0, 2):  # self / anyone
                return certifier_pubkey
            cp = subject.get("counterparty")
            if cp is not None:
                try:
                    return PublicKey(cp)
                except Exception:
                    pass
            return certifier_pubkey

        # Fallback
        return certifier_pubkey

    @staticmethod
    def _sign_certificate(cert: 'MasterCertificate', certifier_wallet: Any, certificate_type: str, final_serial_number: str) -> Optional[bytes]:
        """
        Attach a signature to the certificate. Prefer the wallet interface; otherwise use the private_key attribute.
        """
        try:
            data_to_sign = cert.to_binary(include_signature=False)
            # BRC-100 compliant flat structure (camelCase for API consistency)
            sig_args = {
                'protocolID': [2, 'certificate signature'],
                'keyID': f"{certificate_type} {final_serial_number}",
                'counterparty': {'type': 2},  # CounterpartyType.ANYONE
                'data': data_to_sign,
            }
            sig_res = None
            try:
                # wallet.create_signature(args, originator)
                sig_res = certifier_wallet.create_signature(sig_args)
            except Exception:
                sig_res = None
            if isinstance(sig_res, dict) and sig_res.get('signature'):
                return sig_res['signature']
            else:
                priv = getattr(certifier_wallet, "private_key", None)
                if priv is not None:
                    # sign mutates the certificate; ensure we return bytes for callers
                    cert.sign(priv)
                    return cert.signature
        except Exception:
            pass
        return None

    @staticmethod
    def issue_certificate_for_subject(
        certifier_wallet: Any,
        subject: Any,
        fields: Dict[CertificateFieldNameUnder50Bytes, str],
        certificate_type: str,
        get_revocation_outpoint: Optional[Callable[[str], Any]] = None,
        serial_number: Optional[str] = None
    ) -> 'MasterCertificate':
        final_serial_number = serial_number or base64.b64encode(os.urandom(32)).decode('utf-8')
        field_result = MasterCertificate.create_certificate_fields(certifier_wallet, subject, fields)
        certificate_fields = field_result['certificateFields']
        master_keyring = field_result['masterKeyring']
        revocation_outpoint = get_revocation_outpoint(final_serial_number) if get_revocation_outpoint else None

        certifier_pubkey = MasterCertificate._resolve_public_key(certifier_wallet)
        if certifier_pubkey is None:
            raise ValueError("Unable to resolve certifier public key from wallet")
        subject_pubkey = MasterCertificate._resolve_subject_public_key(subject, certifier_pubkey)

        cert = MasterCertificate(
            certificate_type,
            final_serial_number,
            subject_pubkey,
            certifier_pubkey,
            revocation_outpoint,
            certificate_fields,
            signature=None,
            master_keyring=master_keyring,
        )

        cert.signature = MasterCertificate._sign_certificate(cert, certifier_wallet, certificate_type, final_serial_number)
        return cert

    @staticmethod
    def decrypt_field(
        subject_or_certifier_wallet: Any,
        master_keyring: Dict[CertificateFieldNameUnder50Bytes, Base64String],
        field_name: CertificateFieldNameUnder50Bytes,
        encrypted_field_value: Base64String,
        counterparty: Any,
        privileged: bool = False,
        privileged_reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Base64-decode the symmetric key for the given field_name from the master_keyring, decrypt it via wallet.decrypt,
        base64-decode the encrypted_field_value, then decrypt it with the symmetric key using AES-GCM.
        Returns: { 'fieldRevelationKey': bytes, 'decryptedFieldValue': str }
        """
        if field_name not in master_keyring:
            raise ValueError(f"Field '{field_name}' not found in master_keyring.")
        encrypted_key_b64 = master_keyring[field_name]
        encrypted_key_bytes = base64.b64decode(encrypted_key_b64)
        protocol_id, key_id = get_certificate_encryption_details(field_name, None)
        # BRC-100 flat args structure (TypeScript/Go parity)
        decrypt_args = {
            "protocolID": protocol_id,
            "keyID": key_id,
            "counterparty": counterparty,
            "privileged": privileged,
            "privilegedReason": privileged_reason,
            "ciphertext": encrypted_key_bytes,
        }
        # wallet.decrypt(args, originator) - originator is optional
        decrypt_result = subject_or_certifier_wallet.decrypt(decrypt_args)
        if not decrypt_result or 'plaintext' not in decrypt_result:
            raise NotImplementedError("wallet.decrypt implementation is required")
        field_revelation_key = decrypt_result['plaintext']
        encrypted_field_bytes = base64.b64decode(encrypted_field_value)
        decrypted_field_bytes = EncryptedMessage.aes_gcm_decrypt(field_revelation_key, encrypted_field_bytes)
        return {
            'fieldRevelationKey': field_revelation_key,
            'decryptedFieldValue': decrypted_field_bytes.decode('utf-8')
        }

    @staticmethod
    def decrypt_fields(
        subject_or_certifier_wallet: Any,
        master_keyring: Dict[CertificateFieldNameUnder50Bytes, Base64String],
        fields: Dict[CertificateFieldNameUnder50Bytes, Base64String],
        counterparty: Any,
        privileged: bool = False,
        privileged_reason: Optional[str] = None
    ) -> Dict[CertificateFieldNameUnder50Bytes, str]:
        """
        Invoke decrypt_field for each entry in fields and aggregate the results.
        Returns: { field_name: decrypted_value }
        """
        decrypted_fields: Dict[CertificateFieldNameUnder50Bytes, str] = {}
        for field_name, encrypted_field_value in fields.items():
            result = MasterCertificate.decrypt_field(
                subject_or_certifier_wallet,
                master_keyring,
                field_name,
                encrypted_field_value,
                counterparty,
                privileged,
                privileged_reason
            )
            decrypted_fields[field_name] = result['decryptedFieldValue']
        return decrypted_fields

    @staticmethod
    def create_keyring_for_verifier(
        subject_wallet: Any,
        certifier: Any,
        verifier: Any,
        fields: Dict[CertificateFieldNameUnder50Bytes, Base64String],
        fields_to_reveal: List[CertificateFieldNameUnder50Bytes],
        master_keyring: Dict[CertificateFieldNameUnder50Bytes, Base64String],
        serial_number: str,
        privileged: bool = False,
        privileged_reason: Optional[str] = None
    ) -> Dict[CertificateFieldNameUnder50Bytes, Base64String]:
        """
        For each field specified in fields_to_reveal:
        1. Decrypt the symmetric key from the master_keyring (using decrypt_field)
        2. Re-encrypt it with subject_wallet.encrypt for the verifier (include serial_number in key_id)
        3. Store the result in the keyring as Base64
        Returns: { field_name: encrypted_key_for_verifier }
        """
        keyring_for_verifier: Dict[CertificateFieldNameUnder50Bytes, Base64String] = {}
        for field_name in fields_to_reveal:
            if field_name not in fields:
                raise ValueError(f"Field '{field_name}' not found in certificate fields.")
            # 1. Decrypt the symmetric key from the master_keyring
            decrypt_result = MasterCertificate.decrypt_field(
                subject_wallet,
                master_keyring,
                field_name,
                fields[field_name],
                certifier,
                privileged,
                privileged_reason
            )
            field_revelation_key = decrypt_result['fieldRevelationKey']
            # 2. Re-encrypt for the verifier with subject_wallet.encrypt
            protocol_id, key_id = get_certificate_encryption_details(field_name, serial_number)
            # BRC-100 flat args structure (TypeScript/Go parity)
            encrypt_args = {
                "protocolID": protocol_id,
                "keyID": key_id,
                "counterparty": verifier,
                "privileged": privileged,
                "privilegedReason": privileged_reason,
                "plaintext": field_revelation_key,
            }
            # wallet.encrypt(args, originator) - originator is optional
            encrypt_result = subject_wallet.encrypt(encrypt_args)
            encrypted_key_bytes = encrypt_result["ciphertext"]
            encrypted_key_b64 = base64.b64encode(encrypted_key_bytes).decode('utf-8')
            keyring_for_verifier[field_name] = encrypted_key_b64
        return keyring_for_verifier
