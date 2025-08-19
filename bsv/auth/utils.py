import base64
import os
from typing import Any

def verify_nonce(nonce: str, wallet: Any, counterparty: Any = None, ctx: Any = None) -> bool:
    """
    Verifies that a nonce was derived from the given wallet.
    Ported from Go/TypeScript verifyNonce.
    """
    try:
        nonce_bytes = base64.b64decode(nonce)
    except Exception:
        return False
    if len(nonce_bytes) <= 16:
        return False
    data = nonce_bytes[:16]
    hmac = nonce_bytes[16:]
    # Prepare encryption_args for wallet.verify_hmac
    encryption_args = {
        'protocol_id': {
            'securityLevel': 1,  # Go版: SecurityLevelEveryApp = 1
            'protocol': 'server hmac'
        },
        'key_id': data.decode('latin1'),  # Go版: string(randomBytes)
        'counterparty': counterparty
    }
    args = {
        'encryption_args': encryption_args,
        'data': data,
        'hmac': hmac
    }
    try:
        result = wallet.verify_hmac(ctx, args, "")
        print(f"[verify_nonce] result={result}")
        if isinstance(result, dict):
            return bool(result.get('valid', False))
        else:
            return bool(getattr(result, 'valid', False))
    except Exception:
        return False

def create_nonce(wallet: Any, counterparty: Any = None, ctx: Any = None) -> str:
    """
    Creates a nonce derived from a wallet (ported from TypeScript createNonce).
    """
    # Generate 16 random bytes for the first half of the data
    first_half = os.urandom(16)
    # Create an sha256 HMAC
    encryption_args = {
        'protocol_id': {
            'securityLevel': 1,  # Go版: SecurityLevelEveryApp = 1
            'protocol': 'server hmac'
        },
        'key_id': first_half.decode('latin1'),  # Go版: string(randomBytes)
        'counterparty': counterparty
    }
    args = {
        'encryption_args': encryption_args,
        'data': first_half
    }
    result = wallet.create_hmac(ctx, args, "")
    print(f"[create_nonce] result={result}")
    hmac = result.get('hmac') if isinstance(result, dict) else getattr(result, 'hmac', None)
    if hmac is None:
        raise Exception('Failed to create HMAC for nonce')
    nonce_bytes = first_half + hmac
    return base64.b64encode(nonce_bytes).decode('ascii')


def get_verifiable_certificates(wallet, requested_certificates, verifier_identity_key):
    """
    Retrieves an array of verifiable certificates based on the request (ported from TypeScript getVerifiableCertificates).
    """
    # Find matching certificates we have
    matching = wallet.list_certificates({
        'certifiers': requested_certificates.get('certifiers', []),
        'types': list(requested_certificates.get('types', {}).keys())
    })
    certificates = matching.get('certificates', [])
    result = []
    for certificate in certificates:
        proof = wallet.prove_certificate({
            'certificate': certificate,
            'fields_to_reveal': requested_certificates['types'].get(certificate['type'], []),
            'verifier': verifier_identity_key
        })
        # Construct VerifiableCertificate (assume similar constructor as TS)
        from bsv.auth.verifiable_certificate import VerifiableCertificate
        verifiable = VerifiableCertificate(
            certificate['type'],
            certificate['serialNumber'],
            certificate['subject'],
            certificate['certifier'],
            certificate['revocationOutpoint'],
            certificate['fields'],
            proof.get('keyring_for_verifier', {}),
            certificate['signature']
        )
        result.append(verifiable)
    return result


def validate_certificates(verifier_wallet, message, certificates_requested=None):
    """
    Validates and processes certificates received from a peer.
    - Ensures each certificate's subject equals message.identityKey
    - Verifies signature
    - If certificates_requested is provided, enforces certifier/type/required fields
    - Attempts to decrypt fields using the verifier wallet
    Raises Exception on validation failure.
    """
    from bsv.auth.verifiable_certificate import VerifiableCertificate

    certificates = getattr(message, 'certificates', None) or (message.get('certificates', None) if isinstance(message, dict) else None)
    identity_key = getattr(message, 'identityKey', None) or (message.get('identityKey', None) if isinstance(message, dict) else None)
    if not certificates:
        raise Exception('No certificates were provided in the AuthMessage.')
    if identity_key is None:
        raise Exception('identityKey must be provided in the AuthMessage.')

    # Normalize certificates_requested into (allowed_certifiers, requested_types_map)
    def _normalize_requested(req):
        allowed_certifiers = []
        requested_types = {}
        if req is None:
            return allowed_certifiers, requested_types
        try:
            # RequestedCertificateSet
            from bsv.auth.requested_certificate_set import RequestedCertificateSet
            if isinstance(req, RequestedCertificateSet):
                allowed_certifiers = list(getattr(req, 'certifiers', []) or [])
                # For utils we expect plain string type keys; convert bytes keys to base64 strings
                mapping = getattr(getattr(req, 'certificate_types', None), 'mapping', {}) or {}
                requested_types = {base64.b64encode(k).decode('ascii'): list(v or []) for k, v in mapping.items()}
                return allowed_certifiers, requested_types
        except Exception:
            pass
        # dict-like
        if isinstance(req, dict):
            allowed_certifiers = req.get('certifiers') or req.get('Certifiers') or []
            types_dict = req.get('certificate_types') or req.get('certificateTypes') or req.get('types') or {}
            # In utils tests, type keys are simple strings. Keep as-is.
            for k, v in types_dict.items():
                requested_types[str(k)] = list(v or [])
        return allowed_certifiers, requested_types

    allowed_certifiers, requested_types = _normalize_requested(certificates_requested)

    for incoming in certificates:
        # Extract fields as-is (tests expect plain strings, not decoded keys)
        cert_type = incoming.get('type')
        serial_number = incoming.get('serialNumber') or incoming.get('serial_number')
        subject = incoming.get('subject')
        certifier = incoming.get('certifier')
        fields = incoming.get('fields') or {}
        signature = incoming.get('signature')
        keyring = incoming.get('keyring') or {}

        if subject != identity_key:
            raise Exception(f'The subject of one of your certificates ("{subject}") is not the same as the request sender ("{identity_key}").')

        # Instantiate VerifiableCertificate with backwards-compatible signature used in tests
        try:
            vc = VerifiableCertificate(cert_type, serial_number, subject, certifier, incoming.get('revocationOutpoint'), fields, keyring, signature)
        except Exception:
            # Fallback: if real class is present, try wrapping via real constructor
            try:
                from bsv.auth.certificate import Certificate as _Cert, Outpoint as _Out
                from bsv.keys import PublicKey as _PK
                subj_pk = _PK(subject)
                cert_pk = _PK(certifier) if certifier else None
                rev = incoming.get('revocationOutpoint')
                rev_out = None
                if isinstance(rev, dict):
                    txid = rev.get('txid') or rev.get('txID') or rev.get('txId')
                    index = rev.get('index') or rev.get('vout')
                    if txid is not None and index is not None:
                        rev_out = _Out(txid, int(index))
                base = _Cert(cert_type, serial_number, subj_pk, cert_pk, rev_out, fields, signature)
                vc = VerifiableCertificate(base, keyring)
            except Exception as e:
                raise e

        # Signature verification
        if not vc.verify():
            raise Exception(f'The signature for the certificate with serial number {serial_number} is invalid!')

        # Requested constraints
        if allowed_certifiers or requested_types:
            if allowed_certifiers and certifier not in allowed_certifiers:
                raise Exception(f'Certificate with serial number {serial_number} has an unrequested certifier')
            if requested_types and cert_type not in requested_types:
                raise Exception(f'Certificate with type {cert_type} was not requested')
            required_fields = requested_types.get(cert_type, [])
            for field in required_fields:
                if field not in (fields or {}):
                    raise Exception(f'Certificate missing required field: {field}')

        # Try to decrypt fields for the verifier
        # Let decryption errors bubble up to the caller (as tests expect)
        vc.decrypt_fields(None, verifier_wallet)