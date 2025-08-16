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
            encrypt_args = {
                "encryption_args": {
                    "protocol_id": protocol_id,
                    "key_id": key_id,
                    "counterparty": certifier_or_subject,
                    "privileged": privileged,
                    "privileged_reason": privileged_reason,
                },
                "plaintext": symmetric_key,
            }
            encrypt_result = creator_wallet.encrypt(None, encrypt_args)
            encrypted_key_bytes = encrypt_result["ciphertext"]
            encrypted_key_b64 = base64.b64encode(encrypted_key_bytes).decode('utf-8')
            master_keyring[field_name] = encrypted_key_b64
        return {'certificateFields': certificate_fields, 'masterKeyring': master_keyring}

    @staticmethod
    def issue_certificate_for_subject(
        certifier_wallet: Any,
        subject: Any,
        fields: Dict[CertificateFieldNameUnder50Bytes, str],
        certificate_type: str,
        get_revocation_outpoint: Optional[Callable[[str], Any]] = None,
        serial_number: Optional[str] = None
    ) -> 'MasterCertificate':
        if serial_number is not None:
            final_serial_number = serial_number
        else:
            final_serial_number = base64.b64encode(os.urandom(32)).decode('utf-8')
        field_result = MasterCertificate.create_certificate_fields(certifier_wallet, subject, fields)
        certificate_fields = field_result['certificateFields']
        master_keyring = field_result['masterKeyring']
        if get_revocation_outpoint is not None:
            revocation_outpoint = get_revocation_outpoint(final_serial_number)
        else:
            revocation_outpoint = None
        # 1) Certifier public key resolution via wallet interface if available
        certifier_pubkey = None
        try:
            # Prefer WalletInterface.get_public_key with identityKey=True
            get_pk_args = {"identityKey": True}
            # Some wallet interfaces accept seekPermission; keep it False by default
            res = certifier_wallet.get_public_key(None, get_pk_args, "auth-master-cert")
            if isinstance(res, dict):
                pk_bytes_or_hex = res.get("publicKey")
                if pk_bytes_or_hex:
                    from bsv.keys import PublicKey
                    certifier_pubkey = PublicKey(pk_bytes_or_hex)
        except Exception:
            certifier_pubkey = None

        # Fallbacks: try common attributes exposed by simple wallets
        if certifier_pubkey is None:
            try:
                # e.g. WalletImpl exposes .public_key
                certifier_pubkey = getattr(certifier_wallet, "public_key", None)
            except Exception:
                certifier_pubkey = None
        if certifier_pubkey is None:
            raise ValueError("Unable to resolve certifier public key from wallet")

        # 1b) Resolve subject public key
        from bsv.keys import PublicKey
        subject_pubkey = None
        # Dict-like counterparty: {"type": <int>, "counterparty": <hex/bytes>}
        if isinstance(subject, dict):
            try:
                stype = subject.get("type")
                if stype in (0, 2):  # self / anyone
                    subject_pubkey = certifier_pubkey
                else:
                    cp = subject.get("counterparty")
                    if cp is not None:
                        subject_pubkey = PublicKey(cp)
            except Exception:
                subject_pubkey = None
        # Already a PublicKey
        if subject_pubkey is None and isinstance(subject, PublicKey):
            subject_pubkey = subject
        # Bytes/hex string
        if subject_pubkey is None and isinstance(subject, (bytes, bytearray, str)):
            try:
                subject_pubkey = PublicKey(subject)
            except Exception:
                subject_pubkey = None
        # Fallbacks: treat as self if still unresolved
        if subject_pubkey is None:
            subject_pubkey = certifier_pubkey

        # 2) Construct unsigned MasterCertificate
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

        # 3) Sign using wallet interface if available; fallback to direct private key
        try:
            # Use wallet wire compatible signing first
            data_to_sign = cert.to_binary(include_signature=False)
            sig_args = {
                'encryption_args': {
                    'protocol_id': {
                        'securityLevel': 2,
                        'protocol': 'certificate signature',
                    },
                    'key_id': f"{certificate_type} {final_serial_number}",
                    # Anyone
                    'counterparty': {'type': 2},
                },
                'data': data_to_sign,
            }
            sig_res = None
            try:
                sig_res = certifier_wallet.create_signature(None, sig_args, "auth-master-cert")
            except Exception:
                sig_res = None
            if isinstance(sig_res, dict) and sig_res.get('signature'):
                cert.signature = sig_res['signature']
            else:
                # Fallback: direct private key if exposed
                priv = getattr(certifier_wallet, "private_key", None)
                if priv is not None:
                    cert.sign(priv)
        except Exception:
            # Leave unsigned; caller may sign later using their own mechanism
            pass

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
        master_keyringからfield_nameの対称鍵をbase64デコード→wallet.decryptで復号→encrypted_field_valueをbase64デコード→対称鍵でAES-GCM復号
        戻り値: { 'fieldRevelationKey': bytes, 'decryptedFieldValue': str }
        """
        if field_name not in master_keyring:
            raise ValueError(f"Field '{field_name}' not found in master_keyring.")
        encrypted_key_b64 = master_keyring[field_name]
        encrypted_key_bytes = base64.b64decode(encrypted_key_b64)
        protocol_id, key_id = get_certificate_encryption_details(field_name, None)
        decrypt_args = {
            "encryption_args": {
                "protocol_id": protocol_id,
                "key_id": key_id,
                "counterparty": counterparty,
                "privileged": privileged,
                "privileged_reason": privileged_reason,
            },
            "ciphertext": encrypted_key_bytes,
        }
        # 対称鍵の復号（wallet.decrypt）
        decrypt_result = subject_or_certifier_wallet.decrypt(None, decrypt_args)
        if not decrypt_result or 'plaintext' not in decrypt_result:
            raise NotImplementedError("wallet.decryptの実装が必要です")
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
        fieldsの各フィールドに対してdecrypt_fieldを呼び出し、結果を集約
        戻り値: { field_name: decrypted_value }
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
        fields_to_revealで指定された各フィールドについて：
        1. master_keyringから対称鍵を復号（decrypt_fieldを利用）
        2. subject_wallet.encryptでverifier用に再暗号化（serial_numberをkey_idに含める）
        3. 結果をBase64でkeyringに格納
        返り値: { field_name: encrypted_key_for_verifier }
        """
        keyring_for_verifier: Dict[CertificateFieldNameUnder50Bytes, Base64String] = {}
        for field_name in fields_to_reveal:
            if field_name not in fields:
                raise ValueError(f"Field '{field_name}' not found in certificate fields.")
            # 1. master_keyringから対称鍵を復号
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
            # 2. subject_wallet.encryptでverifier用に再暗号化
            protocol_id, key_id = get_certificate_encryption_details(field_name, serial_number)
            encrypt_args = {
                "encryption_args": {
                    "protocol_id": protocol_id,
                    "key_id": key_id,
                    "counterparty": verifier,
                    "privileged": privileged,
                    "privileged_reason": privileged_reason,
                },
                "plaintext": field_revelation_key,
            }
            encrypt_result = subject_wallet.encrypt(None, encrypt_args)
            encrypted_key_bytes = encrypt_result["ciphertext"]
            encrypted_key_b64 = base64.b64encode(encrypted_key_bytes).decode('utf-8')
            keyring_for_verifier[field_name] = encrypted_key_b64
        return keyring_for_verifier
