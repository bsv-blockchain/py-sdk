# auth_message.py - Ported from AuthMessage.py for PEP8 compliance
from typing import List, Optional, Any
from bsv.keys import PublicKey


class AuthMessage:
    """Represents a message exchanged during the auth protocol."""

    def __init__(
        self,
        version: str = "",
        message_type: str = "",
        identity_key: Optional[PublicKey] = None,
        nonce: str = "",
        initial_nonce: str = "",
        your_nonce: str = "",
        certificates: Optional[List[Any]] = None,  # Should be List[VerifiableCertificate]
        requested_certificates: Optional[Any] = None,  # Should be RequestedCertificateSet
        payload: Optional[bytes] = None,
        signature: Optional[bytes] = None,
    ):
        self.version = version
        self.message_type = message_type
        self.identity_key = identity_key
        self.nonce = nonce
        self.initial_nonce = initial_nonce
        self.your_nonce = your_nonce
        self.certificates = certificates if certificates is not None else []
        self.requested_certificates = requested_certificates
        self.payload = payload
        self.signature = signature
