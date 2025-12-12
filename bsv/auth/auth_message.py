# auth_message.py - Ported from AuthMessage.py for PEP8 compliance
from typing import List, Optional, Any
from bsv.keys import PublicKey


class AuthMessage:
    """
    Represents a message exchanged during the auth protocol (BRC-103).
    
    Required Fields (always):
        version: Protocol version (e.g., "1.0")
        message_type: Message type ('initialRequest', 'initialResponse', 'general', etc.)
        identity_key: Sender's public key for identity verification
    
    Conditional Fields (depends on message_type):
        nonce: Required for 'initialRequest' and 'initialResponse'
        initial_nonce: Required for 'initialResponse'
        your_nonce: Required for 'general' messages
    
    Optional Fields:
        certificates: List of verifiable certificates
        requested_certificates: Set of requested certificate types
        payload: Message payload data
        signature: Digital signature of the message
    
    Example:
        >>> # Initial request
        >>> msg = AuthMessage(
        ...     version="1.0",
        ...     message_type="initialRequest",
        ...     identity_key=public_key,
        ...     nonce="abc123..."
        ... )
        
        >>> # General message
        >>> msg = AuthMessage(
        ...     version="1.0",
        ...     message_type="general",
        ...     identity_key=public_key,
        ...     your_nonce="def456...",
        ...     payload=b"Hello"
        ... )
    """

    def __init__(
        self,
        version: str,
        message_type: str,
        identity_key: PublicKey,
        nonce: str = "",
        initial_nonce: str = "",
        your_nonce: str = "",
        certificates: Optional[List[Any]] = None,  # Should be List[VerifiableCertificate]
        requested_certificates: Optional[Any] = None,  # Should be RequestedCertificateSet
        payload: Optional[bytes] = None,
        signature: Optional[bytes] = None,
    ):
        """
        Initialize an AuthMessage.
        
        Args:
            version: Protocol version (e.g., "1.0") - REQUIRED
            message_type: Message type - REQUIRED
                ('initialRequest', 'initialResponse', 'certificateRequest', 
                 'certificateResponse', 'general')
            identity_key: Sender's public key - REQUIRED
            nonce: Sender's nonce (required for initial messages)
            initial_nonce: Original nonce from initial request (required for response)
            your_nonce: Recipient's nonce from previous message (required for general)
            certificates: List of verifiable certificates
            requested_certificates: Set of requested certificates
            payload: Message payload data
            signature: Digital signature of the message
            
        Raises:
            ValueError: If required fields are empty or None
            
        Note:
            This constructor now enforces required fields at instantiation time.
            If upgrading from previous versions, ensure all required parameters
            are provided when creating AuthMessage instances.
        """
        # Validate required fields
        if not version:
            raise ValueError("version is required and cannot be empty")
        if not message_type:
            raise ValueError("message_type is required and cannot be empty")
        if identity_key is None:
            raise ValueError("identity_key is required and cannot be None")
        
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