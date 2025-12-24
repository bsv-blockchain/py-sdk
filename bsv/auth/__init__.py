"""
BSV Authentication Module

This module provides BSV authentication protocol implementation including:
- Peer: Central authentication protocol implementation
- SessionManager: Session management
- Certificate: Certificate handling
- Transport: Communication layer
"""

# Export main authentication classes
from .peer import Peer, PeerOptions, PeerSession
from .session_manager import SessionManager

# Certificate imports with fallbacks
try:
    from .certificate import Certificate
except (ImportError, AttributeError):
    Certificate = None  # type: ignore

try:
    from .verifiable_certificate import VerifiableCertificate
except (ImportError, AttributeError):
    # VerifiableCertificate might have different structure
    VerifiableCertificate = None  # type: ignore

from .requested_certificate_set import RequestedCertificateSet
from .auth_message import AuthMessage
from .transports.transport import Transport

__all__ = [
    'Peer',
    'PeerOptions',
    'PeerSession',
    'SessionManager',
    'Certificate',
    'VerifiableCertificate',
    'RequestedCertificateSet',
    'AuthMessage',
    'Transport',
]

