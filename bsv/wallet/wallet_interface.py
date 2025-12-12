"""
WalletInterface Protocol - Python implementation of ts-sdk WalletInterface

This module defines the Protocol (similar to TypeScript interface) for wallet implementations.
It ensures type safety and compatibility with ts-sdk.

References:
- ts-sdk: src/wallet/Wallet.interfaces.ts (WalletInterface)
- BRC Standards: BRC-1, BRC-2, BRC-3, etc.
"""

from typing import Protocol, Optional, Dict, List, Any, Union, runtime_checkable
from typing_extensions import TypedDict


# ============================================================================
# Type Aliases (matching ts-sdk)
# ============================================================================

HexString = str
"""A string containing only hexadecimal characters (0-9, a-f)."""

PubKeyHex = str
"""Represents a compressed DER secp256k1 public key, exactly 66 hex characters (33 bytes)."""

TXIDHexString = str
"""Represents a transaction ID, 64 characters in hexadecimal format."""

Base64String = str
"""A standard base64 encoded string."""

AtomicBEEF = List[int]
"""Array of integers (0-255) indicating transaction data in Atomic BEEF (BRC-95) format."""

OriginatorDomainNameStringUnder250Bytes = str
"""Fully qualified domain name (FQDN) of the application that originates the request."""


# ============================================================================
# SecurityLevel (matching go-sdk/ts-sdk)
# ============================================================================

SecurityLevel = int
"""
Security level for wallet operations.

Values:
    0 = Silently grants the request with no user interaction.
    1 = Requires user approval for every application.
    2 = Requires user approval per counterparty per application.

Reference: go-sdk/wallet/wallet.go (SecurityLevel)
"""

SECURITY_LEVEL_SILENT = 0
"""Silently grants the request with no user interaction."""

SECURITY_LEVEL_EVERY_APP = 1
"""Requires user approval for every application."""

SECURITY_LEVEL_EVERY_APP_AND_COUNTERPARTY = 2
"""Requires user approval per counterparty per application."""


# ============================================================================
# WalletProtocol (matching go-sdk Protocol struct)
# ============================================================================

class WalletProtocol(TypedDict):
    """Protocol definition with security level and protocol name.

    This matches go-sdk's Protocol struct:
        type Protocol struct {
            SecurityLevel SecurityLevel
            Protocol      string
        }

    Attributes:
        securityLevel: Access control level (0, 1, or 2).
        protocol: Protocol identifier string (5-400 bytes).

    Example:
        >>> protocol: WalletProtocol = {
        ...     "securityLevel": 2,
        ...     "protocol": "my protocol"
        ... }
    """

    securityLevel: SecurityLevel
    protocol: str


# Legacy type alias for backwards compatibility with list format
WalletProtocolLegacy = List[Union[int, str]]
"""Legacy format: [SecurityLevel, ProtocolID]. Use WalletProtocol dict instead."""


# ============================================================================
# CounterpartyType (matching go-sdk)
# ============================================================================

CounterpartyType = int
"""
Type of counterparty in a cryptographic operation.

Values:
    0 = Uninitialized (default/unknown state)
    1 = Anyone (special constant for 'anyone' counterparty)
    2 = Self (derive vs self)
    3 = Other (explicit public key provided)

Reference: go-sdk/wallet/wallet.go (CounterpartyType)
"""

COUNTERPARTY_UNINITIALIZED = 0
"""Uninitialized/default state."""

COUNTERPARTY_TYPE_ANYONE = 1
"""Special constant for 'anyone' counterparty."""

COUNTERPARTY_TYPE_SELF = 2
"""Derive vs self."""

COUNTERPARTY_TYPE_OTHER = 3
"""Explicit public key provided."""


class WalletCounterparty(TypedDict, total=False):
    """Counterparty in a cryptographic operation.

    This matches go-sdk's Counterparty struct:
        type Counterparty struct {
            Type         CounterpartyType
            Counterparty *ec.PublicKey
        }

    Attributes:
        type: Counterparty type (0=uninitialized, 1=anyone, 2=self, 3=other).
        counterparty: Public key hex string (required when type=3/other).

    Example:
        >>> # Self counterparty
        >>> cp: WalletCounterparty = {"type": 2}
        >>>
        >>> # Anyone counterparty
        >>> cp: WalletCounterparty = {"type": 1}
        >>>
        >>> # Specific counterparty with public key
        >>> cp: WalletCounterparty = {
        ...     "type": 3,
        ...     "counterparty": "02abc123..."
        ... }
    """

    type: CounterpartyType
    counterparty: PubKeyHex


# Legacy type alias for backwards compatibility with string format
WalletCounterpartyLegacy = Union[PubKeyHex, str]
"""Legacy format: PubKeyHex | 'self' | 'anyone'. Use WalletCounterparty dict instead."""


# ============================================================================
# Result Types (matching ts-sdk)
# ============================================================================

class GetPublicKeyResult(TypedDict):
    """Result from getPublicKey method."""
    publicKey: PubKeyHex


class CreateSignatureResult(TypedDict):
    """Result from createSignature method."""
    signature: List[int]  # DER-encoded ECDSA signature as byte array


class CreateActionResult(TypedDict, total=False):
    """Result from createAction method."""
    txid: Optional[TXIDHexString]
    tx: Optional[AtomicBEEF]
    noSendChange: Optional[List[str]]  # OutpointString[]
    sendWithResults: Optional[List[Dict[str, Any]]]
    signableTransaction: Optional[Dict[str, Any]]


class InternalizeActionResult(TypedDict):
    """Result from internalizeAction method."""
    accepted: bool
    satoshisPaid: Optional[int]
    transactionId: Optional[TXIDHexString]


class VerifySignatureResult(TypedDict):
    """Result from verifySignature method."""
    valid: bool


class VerifyHmacResult(TypedDict):
    """Result from verifyHmac method."""
    valid: bool


class EncryptResult(TypedDict):
    """Result from encrypt method."""
    ciphertext: bytes


class DecryptResult(TypedDict):
    """Result from decrypt method."""
    plaintext: bytes


class CreateHmacResult(TypedDict):
    """Result from createHmac method."""
    hmac: bytes


class SignActionResult(TypedDict, total=False):
    """Result from signAction method."""
    txid: Optional[TXIDHexString]
    tx: Optional[AtomicBEEF]
    sendWithResults: Optional[List[Dict[str, Any]]]


class AbortActionResult(TypedDict):
    """Result from abortAction method."""
    aborted: bool


class ListActionsResult(TypedDict):
    """Result from listActions method."""
    totalActions: int
    actions: List[Dict[str, Any]]


class ListOutputsResult(TypedDict):
    """Result from listOutputs method."""
    totalOutputs: int
    outputs: List[Dict[str, Any]]
    BEEF: Optional[bytes]


class ListCertificatesResult(TypedDict):
    """Result from listCertificates method."""
    totalCertificates: int
    certificates: List[Dict[str, Any]]


class DiscoverCertificatesResult(TypedDict):
    """Result from discoverByIdentityKey and discoverByAttributes methods."""
    totalCertificates: int
    certificates: List[Dict[str, Any]]


class ProveCertificateResult(TypedDict):
    """Result from proveCertificate method."""
    keyringForVerifier: Dict[str, str]


class RelinquishCertificateResult(TypedDict):
    """Result from relinquishCertificate method."""
    relinquished: bool


class RelinquishOutputResult(TypedDict):
    """Result from relinquishOutput method."""
    relinquished: bool


class AuthenticatedResult(TypedDict):
    """Result from isAuthenticated and waitForAuthentication methods."""
    authenticated: bool


class GetHeightResult(TypedDict):
    """Result from getHeight method."""
    height: int


class GetHeaderResult(TypedDict):
    """Result from getHeaderForHeight method."""
    header: bytes


class GetNetworkResult(TypedDict):
    """Result from getNetwork method."""
    network: str


class GetVersionResult(TypedDict):
    """Result from getVersion method."""
    version: str


class RevealCounterpartyKeyLinkageResult(TypedDict):
    """Result from revealCounterpartyKeyLinkage method."""
    encryptedLinkage: bytes
    encryptedLinkageProof: bytes
    prover: PubKeyHex
    verifier: PubKeyHex
    counterparty: PubKeyHex
    revelationTime: str


class RevealSpecificKeyLinkageResult(TypedDict):
    """Result from revealSpecificKeyLinkage method."""
    encryptedLinkage: bytes
    encryptedLinkageProof: bytes
    prover: PubKeyHex
    verifier: PubKeyHex
    counterparty: PubKeyHex
    protocolID: WalletProtocol
    keyID: str
    proofType: int


# ============================================================================
# Args Types (matching ts-sdk)
# ============================================================================


class WalletEncryptionArgs(TypedDict, total=False):
    """Base arguments for encryption-related operations.

    Reference: ts-sdk/src/wallet/Wallet.interfaces.ts (WalletEncryptionArgs)

    Attributes:
        protocolID: Security level and protocol string [SecurityLevel, ProtocolString].
        keyID: Key identifier string (max 800 bytes).
        counterparty: Counterparty identifier ('self', 'anyone', or PubKeyHex).
        privileged: Whether this is a privileged operation. Default False.
        privilegedReason: Reason for privileged access (5-50 bytes).
        seekPermission: Whether to seek user permission. Default True.
    """

    protocolID: WalletProtocol
    keyID: str
    counterparty: WalletCounterparty
    privileged: bool
    privilegedReason: str
    seekPermission: bool


class GetPublicKeyArgs(TypedDict, total=False):
    """Arguments for getPublicKey method.

    When identityKey is True, WalletEncryptionArgs fields are not required.

    Reference: ts-sdk/src/wallet/Wallet.interfaces.ts (GetPublicKeyArgs)

    Attributes:
        identityKey: If True, returns the wallet's identity key.
        protocolID: Security level and protocol string [SecurityLevel, ProtocolString].
        keyID: Key identifier string.
        counterparty: Counterparty identifier.
        forSelf: Whether to derive key for self. Default False.
        privileged: Whether this is a privileged operation.
        privilegedReason: Reason for privileged access.
        seekPermission: Whether to seek user permission.
    """

    identityKey: bool
    protocolID: WalletProtocol
    keyID: str
    counterparty: WalletCounterparty
    forSelf: bool
    privileged: bool
    privilegedReason: str
    seekPermission: bool


class CreateSignatureArgs(TypedDict, total=False):
    """Arguments for createSignature method.

    Reference: ts-sdk/src/wallet/Wallet.interfaces.ts (CreateSignatureArgs)

    Attributes:
        data: Data to sign (bytes or List[int]).
        hashToDirectlySign: Pre-hashed data to sign directly.
        protocolID: Security level and protocol string.
        keyID: Key identifier string.
        counterparty: Counterparty identifier.
        forSelf: Whether to sign for self.
        privileged: Whether this is a privileged operation.
        privilegedReason: Reason for privileged access.
        seekPermission: Whether to seek user permission.
    """

    data: bytes
    hashToDirectlySign: bytes
    protocolID: WalletProtocol
    keyID: str
    counterparty: WalletCounterparty
    forSelf: bool
    privileged: bool
    privilegedReason: str
    seekPermission: bool


class VerifySignatureArgs(TypedDict, total=False):
    """Arguments for verifySignature method.

    Reference: ts-sdk/src/wallet/Wallet.interfaces.ts (VerifySignatureArgs)

    Attributes:
        data: Original data that was signed.
        hashToDirectlyVerify: Pre-hashed data to verify against.
        signature: The DER-encoded ECDSA signature to verify.
        protocolID: Security level and protocol string.
        keyID: Key identifier string.
        counterparty: Counterparty identifier.
        forSelf: Whether the signature was created for self.
        privileged: Whether this is a privileged operation.
        privilegedReason: Reason for privileged access.
        seekPermission: Whether to seek user permission.
    """

    data: bytes
    hashToDirectlyVerify: bytes
    signature: bytes
    protocolID: WalletProtocol
    keyID: str
    counterparty: WalletCounterparty
    forSelf: bool
    privileged: bool
    privilegedReason: str
    seekPermission: bool


class EncryptArgs(TypedDict, total=False):
    """Arguments for encrypt method.

    Reference: ts-sdk/src/wallet/Wallet.interfaces.ts (WalletEncryptArgs)

    Attributes:
        plaintext: Data to encrypt.
        protocolID: Security level and protocol string.
        keyID: Key identifier string.
        counterparty: Counterparty identifier.
        privileged: Whether this is a privileged operation.
        privilegedReason: Reason for privileged access.
        seekPermission: Whether to seek user permission.
    """

    plaintext: bytes
    protocolID: WalletProtocol
    keyID: str
    counterparty: WalletCounterparty
    privileged: bool
    privilegedReason: str
    seekPermission: bool


class DecryptArgs(TypedDict, total=False):
    """Arguments for decrypt method.

    Reference: ts-sdk/src/wallet/Wallet.interfaces.ts (WalletDecryptArgs)

    Attributes:
        ciphertext: Data to decrypt.
        protocolID: Security level and protocol string.
        keyID: Key identifier string.
        counterparty: Counterparty identifier.
        privileged: Whether this is a privileged operation.
        privilegedReason: Reason for privileged access.
        seekPermission: Whether to seek user permission.
    """

    ciphertext: bytes
    protocolID: WalletProtocol
    keyID: str
    counterparty: WalletCounterparty
    privileged: bool
    privilegedReason: str
    seekPermission: bool


class CreateHmacArgs(TypedDict, total=False):
    """Arguments for createHmac method.

    Reference: ts-sdk/src/wallet/Wallet.interfaces.ts (CreateHmacArgs)

    Attributes:
        data: Data to create HMAC for.
        protocolID: Security level and protocol string.
        keyID: Key identifier string.
        counterparty: Counterparty identifier.
        privileged: Whether this is a privileged operation.
        privilegedReason: Reason for privileged access.
        seekPermission: Whether to seek user permission.
    """

    data: bytes
    protocolID: WalletProtocol
    keyID: str
    counterparty: WalletCounterparty
    privileged: bool
    privilegedReason: str
    seekPermission: bool


class VerifyHmacArgs(TypedDict, total=False):
    """Arguments for verifyHmac method.

    Reference: ts-sdk/src/wallet/Wallet.interfaces.ts (VerifyHmacArgs)

    Attributes:
        data: Original data.
        hmac: HMAC to verify.
        protocolID: Security level and protocol string.
        keyID: Key identifier string.
        counterparty: Counterparty identifier.
        privileged: Whether this is a privileged operation.
        privilegedReason: Reason for privileged access.
        seekPermission: Whether to seek user permission.
    """

    data: bytes
    hmac: bytes
    protocolID: WalletProtocol
    keyID: str
    counterparty: WalletCounterparty
    privileged: bool
    privilegedReason: str
    seekPermission: bool


class RevealCounterpartyKeyLinkageArgs(TypedDict, total=False):
    """Arguments for revealCounterpartyKeyLinkage method.

    Reference: ts-sdk/src/wallet/Wallet.interfaces.ts

    Attributes:
        counterparty: Public key of the counterparty.
        verifier: Public key of the verifier.
        privileged: Whether this is a privileged operation.
        privilegedReason: Reason for privileged access.
    """

    counterparty: PubKeyHex
    verifier: PubKeyHex
    privileged: bool
    privilegedReason: str


class RevealSpecificKeyLinkageArgs(TypedDict, total=False):
    """Arguments for revealSpecificKeyLinkage method.

    Reference: ts-sdk/src/wallet/Wallet.interfaces.ts

    Attributes:
        counterparty: Counterparty identifier.
        verifier: Public key of the verifier.
        protocolID: Security level and protocol string.
        keyID: Key identifier string.
        privileged: Whether this is a privileged operation.
        privilegedReason: Reason for privileged access.
    """

    counterparty: WalletCounterparty
    verifier: PubKeyHex
    protocolID: WalletProtocol
    keyID: str
    privileged: bool
    privilegedReason: str


# ============================================================================
# WalletInterface Protocol
# ============================================================================

@runtime_checkable
class WalletInterface(Protocol):
    """
    Protocol defining the interface that all wallet implementations must follow.
    
    This is the Python equivalent of ts-sdk's WalletInterface.
    It uses Protocol (PEP 544) to define structural subtyping (duck typing with type checking).
    
    Core Methods:
    - get_public_key: Retrieve derived or identity public keys
    - create_signature: Create digital signatures
    - verify_signature: Verify digital signatures
    - create_action: Create new Bitcoin transactions
    - sign_action: Sign previously created transactions
    - abort_action: Abort transactions in progress
    - internalize_action: Internalize transactions into wallet
    - list_actions: Query transaction history
    - list_outputs: Query wallet UTXOs
    - relinquish_output: Remove outputs from tracking
    
    Cryptographic Methods:
    - encrypt: Encrypt data using derived keys
    - decrypt: Decrypt data using derived keys
    - create_hmac: Create HMAC for data authentication
    - verify_hmac: Verify HMAC values
    
    Certificate Methods:
    - acquire_certificate: Acquire identity certificates
    - list_certificates: List owned certificates
    - prove_certificate: Prove certificate fields to verifiers
    - relinquish_certificate: Remove certificates from wallet
    - discover_by_identity_key: Find certificates by identity key
    - discover_by_attributes: Find certificates by attributes
    
    Key Linkage Methods:
    - reveal_counterparty_key_linkage: Reveal all key linkage with counterparty
    - reveal_specific_key_linkage: Reveal specific protocol key linkage
    
    Network/Authentication Methods:
    - is_authenticated: Check authentication status
    - wait_for_authentication: Wait for authentication
    - get_height: Get current blockchain height
    - get_header_for_height: Get block header at height
    - get_network: Get network (mainnet/testnet)
    - get_version: Get wallet version
    
    All methods follow the pattern:
        method(args: Dict, originator: Optional[str]) -> TypedDict
    
    Where:
    - args: Dictionary containing method-specific parameters
    - originator: Optional FQDN of the application originating the request
    - Returns: TypedDict with method-specific results
    
    Error Handling:
    Methods should raise exceptions that include:
    - 'code': Machine-readable error code
    - 'description': Human-readable error description
    """
    
    def get_public_key(
        self,
        args: GetPublicKeyArgs,
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> GetPublicKeyResult:
        """
        Retrieve a derived or identity public key.
        
        Args:
            args: Dictionary containing:
                - identityKey (bool, optional): If true, returns identity key
                - protocolID (WalletProtocol, optional): Protocol for key derivation
                - keyID (str, optional): Key identifier
                - counterparty (WalletCounterparty, optional): Counterparty identifier
                - forSelf (bool, optional): Whether key is for self
                - privileged (bool, optional): Whether operation is privileged
            originator: Optional FQDN of requesting application
        
        Returns:
            GetPublicKeyResult with 'publicKey' field (66 hex characters)
        
        Raises:
            Exception: Dictionary with 'code' and 'description' fields:
                {
                    'code': str,        # Machine-readable error code
                    'description': str  # Human-readable error message
                }
                
                Common error codes:
                - 'ERR_INVALID_ARGS': Missing or invalid arguments
                - 'ERR_KEY_NOT_FOUND': Requested key does not exist
                - 'ERR_UNAUTHORIZED': Operation not authorized for originator
                - 'ERR_DERIVATION_FAILED': Key derivation computation failed
                - 'ERR_WALLET_LOCKED': Wallet is locked, user authentication required
        
        Example:
            >>> # Success case
            >>> result = wallet.get_public_key({'identityKey': True})
            >>> print(result['publicKey'])
            '033f5aed5f6cfbafaf94570c8cde0c0a6e2b5fb0e07ca40ce1d6f6bdfde1e5b9b8'
            
            >>> # Error case
            >>> try:
            ...     result = wallet.get_public_key({})  # Missing identityKey
            ... except Exception as e:
            ...     print(e['code'])  # 'ERR_INVALID_ARGS'
            ...     print(e['description'])  # 'identityKey or protocolID required'
        """
        ...
    
    def create_signature(
        self,
        args: CreateSignatureArgs,
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> CreateSignatureResult:
        """
        Create a digital signature for provided data.
        
        Args:
            args: Dictionary containing:
                - data (bytes or List[int]): Data to sign
                - protocolID (WalletProtocol): Protocol for signature
                - keyID (str, optional): Key identifier
                - counterparty (WalletCounterparty, optional): Counterparty
                - privileged (bool, optional): Whether operation is privileged
                - hashToDirectlySign (bytes, optional): Pre-hashed data
            originator: Optional FQDN of requesting application
        
        Returns:
            CreateSignatureResult with 'signature' field (DER-encoded ECDSA signature)
        
        Raises:
            Exception: Dictionary with 'code' and 'description' fields:
                
                Common error codes:
                - 'ERR_INVALID_ARGS': Missing required arguments (data or protocolID)
                - 'ERR_INVALID_DATA': Data format is invalid
                - 'ERR_KEY_NOT_FOUND': Signing key not found
                - 'ERR_UNAUTHORIZED': Operation not authorized
                - 'ERR_SIGNING_FAILED': Signature generation failed
                - 'ERR_WALLET_LOCKED': Wallet locked, authentication required
        
        Example:
            >>> # Success case
            >>> result = wallet.create_signature({
            ...     'data': b'message to sign',
            ...     'protocolID': [2, 'auth message signature']
            ... })
            >>> print(len(result['signature']))  # ~70-72 bytes (DER format)
            71
            
            >>> # Error case
            >>> try:
            ...     result = wallet.create_signature({'data': b'test'})  # Missing protocolID
            ... except Exception as e:
            ...     print(e['code'])  # 'ERR_INVALID_ARGS'
        """
        ...
    
    def create_action(
        self,
        args: Dict[str, Any],
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> CreateActionResult:
        """
        Create a new Bitcoin transaction.
        
        Args:
            args: Dictionary containing:
                - description (str): Human-readable action description
                - inputs (List[Dict], optional): Transaction inputs
                - outputs (List[Dict], optional): Transaction outputs
                - lockTime (int, optional): Transaction lock time
                - version (int, optional): Transaction version
                - labels (List[str], optional): Labels for the transaction
                - options (Dict, optional): Transaction options
            originator: Optional FQDN of requesting application
        
        Returns:
            CreateActionResult with txid, tx, or signableTransaction
        
        Raises:
            Exception: Dictionary with 'code' and 'description' fields:
                
                Common error codes:
                - 'ERR_INVALID_ARGS': Missing required arguments (description)
                - 'ERR_INVALID_OUTPUTS': Invalid output specification
                - 'ERR_INVALID_INPUTS': Invalid input specification
                - 'ERR_INSUFFICIENT_FUNDS': Not enough funds for transaction
                - 'ERR_TX_BUILD_FAILED': Transaction construction failed
                - 'ERR_BROADCAST_FAILED': Transaction broadcast failed
                - 'ERR_UNAUTHORIZED': Operation not authorized
                - 'ERR_USER_REJECTED': User rejected the transaction
        
        Example:
            >>> # Success case
            >>> result = wallet.create_action({
            ...     'description': 'Payment transaction',
            ...     'outputs': [{
            ...         'satoshis': 1000,
            ...         'lockingScript': '76a914...',
            ...         'outputDescription': 'Payment to merchant'
            ...     }]
            ... })
            >>> print(result['txid'])
            'a1b2c3d4...'
            
            >>> # Error case
            >>> try:
            ...     result = wallet.create_action({'outputs': [...]})  # Missing description
            ... except Exception as e:
            ...     print(e['code'])  # 'ERR_INVALID_ARGS'
        """
        ...
    
    def internalize_action(
        self,
        args: Dict[str, Any],
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> InternalizeActionResult:
        """
        Internalize a transaction into the wallet.
        
        This method processes incoming transactions, adding outputs to the wallet's
        balance and optionally organizing them into baskets and tags.
        
        Args:
            args: Dictionary containing:
                - tx (AtomicBEEF or bytes): Transaction data in BEEF format
                - outputs (List[Dict], optional): Outputs to track
                - labels (List[str], optional): Labels for the transaction
                - seekPermission (bool, optional): Whether to seek user permission
            originator: Optional FQDN of requesting application
        
        Returns:
            InternalizeActionResult with:
                - accepted (bool): Whether transaction was accepted
                - satoshisPaid (int, optional): Amount paid
                - transactionId (str, optional): Transaction ID
        
        Raises:
            Exception: Dictionary with 'code' and 'description' fields:
                
                Common error codes:
                - 'ERR_INVALID_ARGS': Missing required arguments (tx)
                - 'ERR_INVALID_TX': Transaction data is malformed or invalid
                - 'ERR_TX_VERIFICATION_FAILED': Transaction verification failed
                - 'ERR_DOUBLE_SPEND': Transaction contains double-spend
                - 'ERR_UNAUTHORIZED': Operation not authorized
                - 'ERR_USER_REJECTED': User rejected the internalization
                - 'ERR_INSUFFICIENT_PROOF': Insufficient BEEF proof data
        
        Example:
            >>> # Success case
            >>> result = wallet.internalize_action({
            ...     'tx': beef_data,
            ...     'outputs': [{'outputIndex': 0, 'basket': 'payments'}]
            ... })
            >>> print(f"Accepted: {result['accepted']}")
            True
            >>> print(f"Satoshis: {result['satoshisPaid']}")
            1000
            
            >>> # Error case
            >>> try:
            ...     result = wallet.internalize_action({})  # Missing tx
            ... except Exception as e:
            ...     print(e['code'])  # 'ERR_INVALID_ARGS'
            ...     print(e['description'])  # 'tx is required'
        """
        ...
    
    def encrypt(
        self,
        args: EncryptArgs,
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> EncryptResult:
        """Encrypt data using derived keys."""
        ...

    def decrypt(
        self,
        args: DecryptArgs,
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> DecryptResult:
        """Decrypt data using derived keys."""
        ...

    def create_hmac(
        self,
        args: CreateHmacArgs,
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> CreateHmacResult:
        """Create HMAC for data authentication."""
        ...

    def verify_signature(
        self,
        args: VerifySignatureArgs,
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> VerifySignatureResult:
        """Verify a digital signature."""
        ...

    def verify_hmac(
        self,
        args: VerifyHmacArgs,
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> VerifyHmacResult:
        """Verify an HMAC."""
        ...
    
    def sign_action(
        self,
        args: Dict[str, Any],
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> SignActionResult:
        """Sign a previously created transaction."""
        ...
    
    def abort_action(
        self,
        args: Dict[str, Any],
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> AbortActionResult:
        """Abort a transaction that is in progress."""
        ...
    
    def list_actions(
        self,
        args: Dict[str, Any],
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> ListActionsResult:
        """List all transactions matching the specified labels."""
        ...
    
    def list_outputs(
        self,
        args: Dict[str, Any],
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> ListOutputsResult:
        """List spendable outputs kept within a specific basket."""
        ...
    
    def relinquish_output(
        self,
        args: Dict[str, Any],
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> RelinquishOutputResult:
        """Relinquish an output out of a basket."""
        ...
    
    def acquire_certificate(
        self,
        args: Dict[str, Any],
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> Dict[str, Any]:
        """Acquire an identity certificate."""
        ...
    
    def list_certificates(
        self,
        args: Dict[str, Any],
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> ListCertificatesResult:
        """List identity certificates belonging to the user."""
        ...
    
    def prove_certificate(
        self,
        args: Dict[str, Any],
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> ProveCertificateResult:
        """Prove select fields of an identity certificate."""
        ...
    
    def relinquish_certificate(
        self,
        args: Dict[str, Any],
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> RelinquishCertificateResult:
        """Relinquish an identity certificate."""
        ...
    
    def discover_by_identity_key(
        self,
        args: Dict[str, Any],
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> DiscoverCertificatesResult:
        """Discover identity certificates by identity key."""
        ...
    
    def discover_by_attributes(
        self,
        args: Dict[str, Any],
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> DiscoverCertificatesResult:
        """Discover identity certificates by attributes."""
        ...
    
    def reveal_counterparty_key_linkage(
        self,
        args: RevealCounterpartyKeyLinkageArgs,
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> RevealCounterpartyKeyLinkageResult:
        """Reveal key linkage between ourselves and a counterparty."""
        ...

    def reveal_specific_key_linkage(
        self,
        args: RevealSpecificKeyLinkageArgs,
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> RevealSpecificKeyLinkageResult:
        """Reveal specific key linkage for a protocol and key combination."""
        ...
    
    def is_authenticated(
        self,
        args: Dict[str, Any],
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> AuthenticatedResult:
        """Check the authentication status of the user."""
        ...
    
    def wait_for_authentication(
        self,
        args: Dict[str, Any],
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> AuthenticatedResult:
        """Wait until the user is authenticated."""
        ...
    
    def get_height(
        self,
        args: Dict[str, Any],
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> GetHeightResult:
        """Retrieve the current height of the blockchain."""
        ...
    
    def get_header_for_height(
        self,
        args: Dict[str, Any],
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> GetHeaderResult:
        """Retrieve the block header at a specified height."""
        ...
    
    def get_network(
        self,
        args: Dict[str, Any],
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> GetNetworkResult:
        """Retrieve the Bitcoin network the client is using."""
        ...
    
    def get_version(
        self,
        args: Dict[str, Any],
        originator: Optional[OriginatorDomainNameStringUnder250Bytes] = None
    ) -> GetVersionResult:
        """Retrieve the current version of the wallet."""
        ...


# ============================================================================
# Helper Functions
# ============================================================================

def is_wallet_interface(obj: Any) -> bool:
    """
    Check if an object implements the WalletInterface protocol.
    
    Uses isinstance() with the @runtime_checkable WalletInterface Protocol.
    This automatically checks for all required methods defined in the Protocol,
    ensuring consistency even as the interface evolves.
    
    Args:
        obj: Object to check
    
    Returns:
        True if object implements all required WalletInterface methods
    
    Example:
        >>> if is_wallet_interface(my_wallet):
        ...     print("Valid wallet implementation")
        
        >>> class MyWallet:
        ...     def get_public_key(self, args, originator=None): ...
        ...     def create_signature(self, args, originator=None): ...
        ...     def create_action(self, args, originator=None): ...
        ...     def internalize_action(self, args, originator=None): ...
        >>> 
        >>> wallet = MyWallet()
        >>> is_wallet_interface(wallet)  # True
    
    Note:
        Because WalletInterface is decorated with @runtime_checkable,
        isinstance() will verify that the object has all required methods.
        This is more maintainable than a hardcoded list of method names.
    """
    return isinstance(obj, WalletInterface)


__all__ = [
    # Protocol
    'WalletInterface',

    # Type Aliases
    'HexString',
    'PubKeyHex',
    'TXIDHexString',
    'Base64String',
    'AtomicBEEF',
    'OriginatorDomainNameStringUnder250Bytes',
    'SecurityLevel',
    'SECURITY_LEVEL_SILENT',
    'SECURITY_LEVEL_EVERY_APP',
    'SECURITY_LEVEL_EVERY_APP_AND_COUNTERPARTY',
    'WalletProtocol',
    'WalletProtocolLegacy',
    'CounterpartyType',
    'COUNTERPARTY_UNINITIALIZED',
    'COUNTERPARTY_TYPE_ANYONE',
    'COUNTERPARTY_TYPE_SELF',
    'COUNTERPARTY_TYPE_OTHER',
    'WalletCounterparty',
    'WalletCounterpartyLegacy',

    # Args Types
    'WalletEncryptionArgs',
    'GetPublicKeyArgs',
    'CreateSignatureArgs',
    'VerifySignatureArgs',
    'EncryptArgs',
    'DecryptArgs',
    'CreateHmacArgs',
    'VerifyHmacArgs',
    'RevealCounterpartyKeyLinkageArgs',
    'RevealSpecificKeyLinkageArgs',

    # Result Types
    'GetPublicKeyResult',
    'CreateSignatureResult',
    'CreateActionResult',
    'InternalizeActionResult',
    'VerifySignatureResult',
    'VerifyHmacResult',
    'EncryptResult',
    'DecryptResult',
    'CreateHmacResult',
    'SignActionResult',
    'AbortActionResult',
    'ListActionsResult',
    'ListOutputsResult',
    'ListCertificatesResult',
    'DiscoverCertificatesResult',
    'ProveCertificateResult',
    'RelinquishCertificateResult',
    'RelinquishOutputResult',
    'AuthenticatedResult',
    'GetHeightResult',
    'GetHeaderResult',
    'GetNetworkResult',
    'GetVersionResult',
    'RevealCounterpartyKeyLinkageResult',
    'RevealSpecificKeyLinkageResult',

    # Helpers
    'is_wallet_interface',
]
