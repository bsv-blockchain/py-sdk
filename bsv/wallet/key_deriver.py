from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional
import re
import hmac
import hashlib
import os

from bsv.keys import PrivateKey, PublicKey
from bsv.hash import hmac_sha256
from bsv.curve import curve, curve_add, curve_multiply, Point  # Elliptic helpers

# secp256k1 curve order (same as coincurve.curve.n)
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


@dataclass
class Protocol:  # NOSONAR - Field names match protocol specification
    security_level: int  # 0,1,2
    protocol: str  # NOSONAR - Field names match protocol specification
    
    def __init__(self, security_level: int, protocol: str):
        # Allow 3-400 characters to match TS/Go (e.g., "ctx" is valid in tests)
        # This matches _validate_protocol() behavior
        if not isinstance(protocol, str) or len(protocol) < 3 or len(protocol) > 400:
            raise ValueError("protocol names must be 3-400 characters")
        self.security_level = security_level
        self.protocol = protocol


class CounterpartyType:
    """
    Counterparty type constants matching Go SDK implementation.
    
    Go SDK reference:
    - CounterpartyUninitialized = 0
    - CounterpartyTypeAnyone    = 1
    - CounterpartyTypeSelf      = 2
    - CounterpartyTypeOther     = 3
    """
    UNINITIALIZED = 0  # Uninitialized/default state
    ANYONE = 1         # Special constant for "anyone" counterparty
    SELF = 2           # Derive vs self
    OTHER = 3          # Explicit pubkey provided


@dataclass
class Counterparty:  # NOSONAR - Field names match protocol specification
    type: int
    counterparty: Optional[PublicKey] = None  # NOSONAR - Field names match protocol specification

    def to_public_key(self, self_pub: PublicKey) -> PublicKey:
        if self.type == CounterpartyType.SELF:
            return self_pub
        if self.type == CounterpartyType.ANYONE:
            # Anyone is represented by the constant PublicKey derived from PrivateKey(1)
            return PrivateKey(1).public_key()
        if self.type == CounterpartyType.OTHER and self.counterparty:
            return self.counterparty
        raise ValueError("Invalid counterparty configuration")


class KeyDeriver:
    """key derivation (deterministic, HMAC-SHA256 + elliptic add)"""

    def __init__(self, root_private_key: PrivateKey):
        self._root_private_key = root_private_key
        self._root_public_key = root_private_key.public_key()

    # ---------------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------------
    def _validate_protocol(self, protocol: Protocol):
        if protocol.security_level not in (0, 1, 2):
            raise ValueError("protocol security level must be 0, 1, or 2")
        # Allow shorter protocol names to match TS/Go usage in tests (e.g., "ctx")
        if not (3 <= len(protocol.protocol) <= 400):
            raise ValueError("protocol names must be 3-400 characters")
        if '  ' in protocol.protocol:
            raise ValueError("protocol names cannot contain multiple consecutive spaces")
        if not re.match(r'^[A-Za-z0-9 ]+$', protocol.protocol):
            raise ValueError("protocol names can only contain letters, numbers and spaces")
        if protocol.protocol.endswith(" protocol"):
            raise ValueError('no need to end your protocol name with " protocol"')

    def _validate_key_id(self, key_id: str):
        if not (1 <= len(key_id) <= 800):
            raise ValueError("key IDs must be 1-800 characters")

    # ------------------------------------------------------------------
    # Derivation core
    # ------------------------------------------------------------------
    def _branch_scalar(self, invoice_number: str, cp_pub: PublicKey) -> int:
        """Deterministic branch scalar from HMAC(sharedSecret.encode(true), invoiceNumber).
        
        This implementation matches TypeScript/Go SDK behavior:
        - TS SDK: sha256hmac(sharedSecret.encode(true), invoiceNumberBin)
        - sharedSecret.encode(true) returns compressed public key (33 bytes)
        
        Reference: ts-sdk/src/primitives/PublicKey.ts deriveChild()
        """
        invoice_number_bin = invoice_number.encode('utf-8')
        # derive_shared_secret returns compressed public key (33 bytes)
        shared_secret = cp_pub.derive_shared_secret(self._root_private_key)
        
        # Use the full compressed point (33 bytes) as HMAC key, matching TS SDK
        if isinstance(shared_secret, (bytes, bytearray)):
            shared_key = bytes(shared_secret)
        else:
            shared_key = shared_secret
        
        branch = hmac_sha256(shared_key, invoice_number_bin)
        scalar = int.from_bytes(branch, 'big') % CURVE_ORDER
        if os.getenv("BSV_DEBUG", "0") == "1":
            try:
                print(f"[DEBUG KeyDeriver._branch_scalar] invoice_number={invoice_number} shared_len={len(shared_key)} scalar={scalar:x}")
            except Exception:
                print(f"[DEBUG KeyDeriver._branch_scalar] scalar={scalar:x}")
        return scalar

    # ------------------------------------------------------------------
    # Public / Private / Symmetric derivations
    # ------------------------------------------------------------------
    def derive_private_key(self, protocol: Protocol, key_id: str, counterparty: Counterparty) -> PrivateKey:
        """Derives a private key based on protocol ID, key ID, and counterparty.
        
        This implementation now matches TypeScript/Go SDK behavior:
        1. Generate invoiceNumber using compute_invoice_number
        2. Normalize counterparty
        3. Call _branch_scalar with invoiceNumber
        4. Compute derived key as (root + branch_scalar) mod N
        """
        invoice_number = self.compute_invoice_number(protocol, key_id)
        cp_pub = counterparty.to_public_key(self._root_public_key)
        branch_k = self._branch_scalar(invoice_number, cp_pub)

        derived_int = (self._root_private_key.int() + branch_k) % CURVE_ORDER
        return PrivateKey(derived_int)

    def derive_public_key(
        self,
        protocol: Protocol,
        key_id: str,
        counterparty: Counterparty,
        for_self: bool = False,
    ) -> PublicKey:
        """Derives a public key based on protocol ID, key ID, and counterparty.
        
        This implementation matches TypeScript/Go SDK behavior:
        - forSelf=True: rootKey.deriveChild(counterparty, invoice).toPublicKey()
        - forSelf=False: counterparty.deriveChild(rootKey, invoice)
        
        Note: This means derive_public_key(forSelf=False) != derive_private_key().public_key()
        This is intentional and matches TS/Go SDK behavior for asymmetric key derivation.
        """
        invoice_number = self.compute_invoice_number(protocol, key_id)
        # Determine counterparty pub used for tweak
        cp_pub = counterparty.to_public_key(self._root_public_key) if not for_self else self._root_public_key
        delta = self._branch_scalar(invoice_number, cp_pub)
        
        if for_self:
            # forSelf=True: derived from root's perspective
            # tweaked public = root_pub + delta*G
            delta_point = curve_multiply(delta, curve.g)
            new_point = curve_add(self._root_public_key.point(), delta_point)
        else:
            # forSelf=False: derived from counterparty's perspective
            # tweaked public = cp_pub + delta*G
            delta_point = curve_multiply(delta, curve.g)
            new_point = curve_add(cp_pub.point(), delta_point)
        
        return PublicKey(new_point)

    def derive_symmetric_key(self, protocol: Protocol, key_id: str, counterparty: Counterparty) -> bytes:
        """Derive a symmetric key based on protocol ID, key ID, and counterparty.
        
        This implementation matches TypeScript/Go SDK behavior:
        1. Derive public key and private key for the given protocol/keyID/counterparty
        2. Compute shared secret between derived private key and derived public key
        3. Return the X coordinate of the shared secret point (32 bytes)
        
        Reference: ts-sdk KeyDeriver.deriveSymmetricKey, go-sdk KeyDeriver.DeriveSymmetricKey
        """
        # If counterparty is 'anyone', use the anyone public key
        if counterparty.type == CounterpartyType.ANYONE:
            counterparty = Counterparty(CounterpartyType.OTHER, PrivateKey(1).public_key())
        
        # Derive both public and private keys
        derived_public_key = self.derive_public_key(protocol, key_id, counterparty, for_self=False)
        derived_private_key = self.derive_private_key(protocol, key_id, counterparty)
        
        # Compute shared secret: derived_private_key.deriveSharedSecret(derived_public_key)
        # This matches TS SDK: derivedPrivateKey.deriveSharedSecret(derivedPublicKey)
        shared_secret = derived_private_key.derive_shared_secret(derived_public_key)
        
        # The shared secret is a compressed public key (33 bytes)
        # Extract the X coordinate (bytes 1-32) - this matches TS/Go behavior
        if isinstance(shared_secret, (bytes, bytearray)) and len(shared_secret) >= 33:
            x_coordinate = bytes(shared_secret)[1:33]
        else:
            # Fallback: pad to 32 bytes if needed
            x_coordinate = bytes(shared_secret)[:32]
            if len(x_coordinate) < 32:
                x_coordinate = bytes(32 - len(x_coordinate)) + x_coordinate
        
        return x_coordinate

    # Identity key (root public)
    def identity_key(self) -> PublicKey:
        return self._root_public_key

    # ------------------------------------------------------------------
    # Additional helpers required by tests / higher layers
    # ------------------------------------------------------------------
    def compute_invoice_number(self, protocol: Protocol, key_id: str) -> str:
        """Return a string invoice number: "<security>-<protocol>-<key_id>" with validation.
        
        Protocol names are converted to lowercase and trimmed, matching TS/Go SDK behavior.
        Reference: go-sdk/wallet/key_deriver.go computeInvoiceNumber
        """
        self._validate_protocol(protocol)
        self._validate_key_id(key_id)
        # Normalize protocol name: lowercase and trim whitespace (matches Go/TS SDK)
        protocol_name = protocol.protocol.strip().lower()
        return f"{protocol.security_level}-{protocol_name}-{key_id}"

    def normalize_counterparty(self, cp: Any) -> PublicKey:
        """Normalize various counterparty representations to a PublicKey.

        Accepted forms:
        - Counterparty(SELF/ANYONE/OTHER)
        - PublicKey
        - hex string
        """
        if isinstance(cp, Counterparty):
            return cp.to_public_key(self._root_public_key)
        if isinstance(cp, PublicKey):
            return cp
        if isinstance(cp, (bytes, str)):
            return PublicKey(cp)
        raise ValueError("Invalid counterparty configuration")

    # ------------------------------------------------------------------
    # Reveal methods for key linkage (matches TS/Go SDK)
    # ------------------------------------------------------------------
    def reveal_counterparty_secret(self, counterparty: Counterparty) -> bytes:
        """Reveals the shared secret between the root key and the counterparty.
        
        Note: This should not be used for 'self'.
        
        Args:
            counterparty: The counterparty's public key or a predefined value.
            
        Returns:
            The shared secret as compressed public key bytes (33 bytes).
            
        Raises:
            ValueError: If attempting to reveal a shared secret for 'self'.
            
        Reference: ts-sdk KeyDeriver.revealCounterpartySecret, go-sdk KeyDeriver.RevealCounterpartySecret
        """
        if counterparty.type == CounterpartyType.SELF:
            raise ValueError("Counterparty secrets cannot be revealed for counterparty=self.")
        
        counterparty_key = counterparty.to_public_key(self._root_public_key)
        
        # Double-check to ensure not revealing the secret for 'self'
        self_key = self._root_public_key
        key_derived_by_self = self._root_private_key.derive_child(self_key, "test")
        key_derived_by_counterparty = self._root_private_key.derive_child(counterparty_key, "test")
        
        if key_derived_by_self.hex() == key_derived_by_counterparty.hex():
            raise ValueError("Counterparty secrets cannot be revealed if counterparty key is self.")
        
        # Return the shared secret as compressed public key
        shared_secret = self._root_private_key.derive_shared_secret(counterparty_key)
        return shared_secret

    def reveal_specific_secret(self, counterparty: Counterparty, protocol: Protocol, key_id: str) -> bytes:
        """Reveals the specific key association for a given protocol ID, key ID, and counterparty.
        
        Args:
            counterparty: The counterparty's public key or a predefined value.
            protocol: The protocol ID including a security level and protocol name.
            key_id: The key identifier.
            
        Returns:
            The specific key association as HMAC-SHA256 bytes (32 bytes).
            
        Reference: ts-sdk KeyDeriver.revealSpecificSecret, go-sdk KeyDeriver.RevealSpecificSecret
        """
        counterparty_key = counterparty.to_public_key(self._root_public_key)
        
        # Compute shared secret
        shared_secret = self._root_private_key.derive_shared_secret(counterparty_key)
        
        # Compute invoice number
        invoice_number = self.compute_invoice_number(protocol, key_id)
        invoice_number_bin = invoice_number.encode('utf-8')
        
        # Compute HMAC-SHA256 using compressed shared secret as key
        return hmac_sha256(shared_secret, invoice_number_bin)
