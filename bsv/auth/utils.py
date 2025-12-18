import base64
import os
from typing import Any

def verify_nonce(nonce: str, wallet: Any, counterparty: Any = None) -> bool:
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
        'protocolID': {
            'securityLevel': 1,  # Go version: SecurityLevelEveryApp = 1
            'protocol': 'server hmac'
        },
        'keyID': data.decode('latin1'),  # Go version: string(randomBytes)
        'counterparty': counterparty
    }
    args = {
        'encryption_args': encryption_args,
        'data': data,
        'hmac': hmac
    }
    try:
        result = wallet.verify_hmac(args, "")
        print(f"[verify_nonce] result={result}")
        if isinstance(result, dict):
            return bool(result.get('valid', False))
        else:
            return bool(getattr(result, 'valid', False))
    except Exception:
        return False

def create_nonce(wallet: Any, counterparty: Any = None) -> str:
    """
    Creates a nonce derived from a wallet (ported from TypeScript createNonce).
    """
    # Generate 16 random bytes for the first half of the data
    first_half = os.urandom(16)
    # Create an sha256 HMAC
    encryption_args = {
        'protocolID': {
            'securityLevel': 1,  # Go version: SecurityLevelEveryApp = 1
            'protocol': 'server hmac'
        },
        'keyID': first_half.decode('latin1'),  # Go version: string(randomBytes)
        'counterparty': counterparty
    }
    args = {
        'encryption_args': encryption_args,
        'data': first_half
    }
    result = wallet.create_hmac(args, "")
    print(f"[create_nonce] result={result}")
    hmac = result.get('hmac') if isinstance(result, dict) else getattr(result, 'hmac', None)
    if hmac is None:
        raise RuntimeError('Failed to create HMAC for nonce')
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
    Validate and process certificates received from a peer.
    - Ensures each certificate's subject equals message.identityKey
    - Verifies signature
    - If certificates_requested is provided, enforces certifier/type/required fields
    - Attempts to decrypt fields using the verifier wallet
    Raises Exception on validation failure.
    """
    certificates = _extract_message_certificates(message)
    identity_key = _extract_message_identity_key(message)
    if not certificates:
        raise ValueError('No certificates were provided in the AuthMessage.')
    if identity_key is None:
        raise ValueError('identityKey must be provided in the AuthMessage.')

    allowed_certifiers, requested_types = _normalize_requested_for_utils(certificates_requested)

    for incoming in certificates:
        cert_type, serial_number, subject, certifier, fields, signature, keyring = _extract_incoming_fields(incoming)

        _ensure_subject_matches(subject, identity_key)

        vc = _build_verifiable_certificate(incoming, cert_type, serial_number, subject, certifier, fields, signature, keyring)

        if not vc.verify():
            raise ValueError(f'The signature for the certificate with serial number {serial_number} is invalid!')

        _enforce_requested_constraints(allowed_certifiers, requested_types, cert_type, certifier, fields, serial_number)

        # Try to decrypt fields for the verifier (errors bubble up to caller)
        vc.decrypt_fields(None, verifier_wallet)


# ------- Helpers below keep validate_certificates simple and testable -------
def _extract_message_certificates(message):
    return getattr(message, 'certificates', None) or (message.get('certificates', None) if isinstance(message, dict) else None)


def _extract_message_identity_key(message):
    return getattr(message, 'identityKey', None) or (message.get('identityKey', None) if isinstance(message, dict) else None)


def _normalize_requested_for_utils(req):  # NOSONAR - Complexity (17), requires refactoring
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
        # Check for forbidden snake_case keys
        forbidden_keys = {
            'certificate_types': 'certificateTypes'
        }
        for snake_key, camel_key in forbidden_keys.items():
            if snake_key in req:
                raise ValueError(f"RequestedCertificateSet key '{snake_key}' is not supported. Use '{camel_key}' instead.")

        allowed_certifiers = req.get('certifiers') or req.get('Certifiers') or []
        types_dict = req.get('certificateTypes') or req.get('types') or {}
        # In utils tests, type keys are simple strings. Keep as-is.
        for k, v in types_dict.items():
            requested_types[str(k)] = list(v or [])
    return allowed_certifiers, requested_types


def _extract_incoming_fields(incoming):
    # Check for forbidden snake_case keys
    if 'serial_number' in incoming:
        raise ValueError("Certificate key 'serial_number' is not supported. Use 'serialNumber' instead.")

    cert_type = incoming.get('type')
    serial_number = incoming.get('serialNumber')
    subject = incoming.get('subject')
    certifier = incoming.get('certifier')
    fields = incoming.get('fields') or {}
    signature = incoming.get('signature')
    keyring = incoming.get('keyring') or {}
    return cert_type, serial_number, subject, certifier, fields, signature, keyring


def _ensure_subject_matches(subject, identity_key):
    if subject != identity_key:
        raise ValueError(f'The subject of one of your certificates ("{subject}") is not the same as the request sender ("{identity_key}").')


def _build_verifiable_certificate(incoming, cert_type, serial_number, subject, certifier, fields, signature, keyring):
    from bsv.auth.verifiable_certificate import VerifiableCertificate
    try:
        return VerifiableCertificate(cert_type, serial_number, subject, certifier, incoming.get('revocationOutpoint'), fields, keyring, signature)
    except Exception:
        # Fallback: attempt to wrap a base Certificate if available
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
        return VerifiableCertificate(base, keyring)


def _enforce_requested_constraints(allowed_certifiers, requested_types, cert_type, certifier, fields, serial_number):
    if not (allowed_certifiers or requested_types):
        return
    if allowed_certifiers and certifier not in allowed_certifiers:
        raise ValueError(f'Certificate with serial number {serial_number} has an unrequested certifier')
    if requested_types and cert_type not in requested_types:
        raise ValueError(f'Certificate with type {cert_type} was not requested')
    required_fields = requested_types.get(cert_type, [])
    for field in required_fields:
        if field not in (fields or {}):
            raise ValueError(f'Certificate missing required field: {field}')