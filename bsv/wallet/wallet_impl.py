from typing import Any, Dict, Optional, List
from types import SimpleNamespace
import os
from .wallet_interface import (
    WalletInterface,
    GetPublicKeyArgs,
    CreateSignatureArgs,
    VerifySignatureArgs,
    EncryptArgs,
    DecryptArgs,
    CreateHmacArgs,
    VerifyHmacArgs,
    RevealCounterpartyKeyLinkageArgs,
    RevealSpecificKeyLinkageArgs,
)
from .key_deriver import KeyDeriver, Protocol, Counterparty, CounterpartyType
from bsv.keys import PrivateKey, PublicKey
import hashlib
import hmac
import time
from bsv.script.type import P2PKH
from bsv.utils.address import validate_address
from bsv.fee_models.satoshis_per_kilobyte import SatoshisPerKilobyte
from bsv.chaintrackers import WhatsOnChainTracker

class ProtoWallet(WalletInterface):
    """Core wallet implementation providing cryptographic operations.
    
    ProtoWallet provides the fundamental cryptographic operations that higher-level
    wallet implementations delegate to. This matches the TS/Go SDK architecture
    where ProtoWallet handles key derivation, signing, encryption, and HMAC operations.
    
    Reference: ts-sdk ProtoWallet, go-sdk wallet.ProtoWallet
    """
    _dotenv_loaded: bool = False

    def __init__(self, private_key: PrivateKey, permission_callback=None, woc_api_key: Optional[str] = None, load_env: bool = False):
        self.private_key = private_key
        self.key_deriver = KeyDeriver(private_key)
        self.public_key = private_key.public_key()
        self.permission_callback = permission_callback  # Optional[Callable[[str], bool]]
        # in-memory stores
        self._actions: List[Dict[str, Any]] = []
        self._certificates: List[Dict[str, Any]] = []
        # Optionally load .env once at initialization time
        if load_env and not ProtoWallet._dotenv_loaded:
            try:
                from dotenv import load_dotenv  # type: ignore
                load_dotenv()
            except Exception:
                pass
            ProtoWallet._dotenv_loaded = True
        # WhatsOnChain API key (TS parity: WhatsOnChainConfig.apiKey)
        self._woc_api_key: str = (woc_api_key or os.environ.get("WOC_API_KEY") or "")

    def _check_permission(self, action: str) -> None:
        if self.permission_callback:
            allowed = self.permission_callback(action)
        else:
            # Default for CLI: Ask the user for permission
            resp = input(f"[Wallet] Allow {action}? [y/N]: ")
            allowed = resp.strip().lower() in ("y", "yes")
        if not allowed:
            raise PermissionError(f"Operation '{action}' was not permitted by the user.")

    # -----------------------------
    # Normalization helpers
    # -----------------------------
    def _parse_counterparty_type(self, t: Any) -> int:
        """Parse counterparty type from various input formats.
        
        Matches Go SDK CounterpartyType values:
        - UNINITIALIZED = 0
        - ANYONE = 1
        - SELF = 2
        - OTHER = 3
        """
        if isinstance(t, int):
            return t
        if isinstance(t, str):
            tl = t.lower()
            if tl in ("self", "me"):
                return CounterpartyType.SELF  # 2
            if tl in ("other", "counterparty"):
                return CounterpartyType.OTHER  # 3
            if tl in ("anyone", "any"):
                return CounterpartyType.ANYONE  # 1
        return CounterpartyType.SELF

    def _normalize_counterparty(self, counterparty: Any) -> Counterparty:
        if isinstance(counterparty, dict):
            inner = counterparty.get("counterparty")
            if inner is not None and not isinstance(inner, PublicKey):
                inner = PublicKey(inner)
            ctype = self._parse_counterparty_type(counterparty.get("type", CounterpartyType.SELF))
            return Counterparty(ctype, inner)
        if isinstance(counterparty, str):
            # Handle special string values (TS/Go parity)
            if counterparty == "self":
                return Counterparty(CounterpartyType.SELF)
            if counterparty == "anyone":
                return Counterparty(CounterpartyType.ANYONE)
            # Otherwise treat as hex public key
            return Counterparty(CounterpartyType.OTHER, PublicKey(counterparty))
        if isinstance(counterparty, bytes):
            return Counterparty(CounterpartyType.OTHER, PublicKey(counterparty))
        if isinstance(counterparty, PublicKey):
            return Counterparty(CounterpartyType.OTHER, counterparty)
        # None or unknown -> self
        return Counterparty(CounterpartyType.SELF)

    def get_public_key(self, args: GetPublicKeyArgs = None, originator: str = None) -> Dict:
        try:
            # Check for forbidden snake_case keys
            forbidden_keys = {
                'seek_permission': 'seekPermission',
                'protocol_id': 'protocolID',
                'key_id': 'keyID'
            }
            for snake_key, camel_key in forbidden_keys.items():
                if snake_key in args:
                    raise ValueError(f"Wallet API key '{snake_key}' is not supported. Use '{camel_key}' instead.")

            seek_permission = args.get("seekPermission")
            if seek_permission:
                self._check_permission("Get public key")
            if args.get("identityKey", False):
                return {"publicKey": self.public_key.hex()}
            # camelCase only
            protocol_id = args.get("protocolID")
            key_id = args.get("keyID")
            counterparty = args.get("counterparty")
            for_self = args.get("forSelf", False)
            if protocol_id is None or key_id is None:
                # For PushDrop/self usage, allow identity key when forSelf is True
                if for_self:
                    return {"publicKey": self.public_key.hex()}
                return {"error": "get_public_key: protocolID and keyID are required for derived key"}
            if isinstance(protocol_id, dict):
                protocol = SimpleNamespace(security_level=int(protocol_id.get("securityLevel", 0)), protocol=str(protocol_id.get("protocol", "")))
            elif isinstance(protocol_id, (list, tuple)):
                # Handle list/tuple format: [security_level, protocol_name]
                protocol = SimpleNamespace(security_level=int(protocol_id[0]), protocol=str(protocol_id[1]))
            else:
                protocol = protocol_id
            cp = self._normalize_counterparty(counterparty)
            derived_pub = self.key_deriver.derive_public_key(protocol, key_id, cp, for_self)
            return {"publicKey": derived_pub.hex()}
        except Exception as e:
            return {"error": f"get_public_key: {e}"}

    def encrypt(self, args: EncryptArgs = None, originator: str = None) -> Dict:
        """Encrypt data using AES-GCM with a derived symmetric key.
        
        This implementation matches TS/Go SDK ProtoWallet.encrypt:
        1. Derive symmetric key from protocol_id, key_id, counterparty
        2. Encrypt using AES-GCM (SymmetricKey.encrypt)
        3. Return ciphertext in format: IV (32 bytes) || ciphertext || authTag (16 bytes)
        
        Args format (matches TS SDK WalletEncryptArgs):
            - plaintext: The data to encrypt (bytes or list of ints)
            - protocol_id / protocolID: The protocol ID [security_level, protocol_name]
            - key_id / keyID: The key identifier string
            - counterparty: The counterparty (optional, defaults to 'self')
        """
        try:
            from bsv.primitives.symmetric_key import SymmetricKey
            
            # Support both flat args (TS style) and nested encryption_args (legacy)
            encryption_args = args.get("encryption_args", args)
            
            
            self._maybe_seek_permission("Encrypt", encryption_args)
            
            # Get plaintext
            plaintext = args.get("plaintext")
            if plaintext is None:
                return {"error": "encrypt: plaintext is required"}
            
            # Normalize plaintext to bytes
            if isinstance(plaintext, list):
                plaintext = bytes(plaintext)
            elif isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')

            # Check for forbidden snake_case keys
            forbidden_keys = {
                'protocol_id': 'protocolID',
                'key_id': 'keyID'
            }
            for snake_key, camel_key in forbidden_keys.items():
                if snake_key in encryption_args:
                    raise ValueError(f"Wallet API key '{snake_key}' is not supported. Use '{camel_key}' instead.")

            # Get protocol parameters (camelCase only)
            protocol_id = encryption_args.get("protocolID")
            key_id = encryption_args.get("keyID")
            counterparty = encryption_args.get("counterparty")
            
            if protocol_id is None or key_id is None:
                return {"error": "encrypt: protocol_id and key_id are required"}
            
            # Normalize protocol and counterparty
            protocol = self._normalize_protocol(protocol_id)
            cp = self._normalize_counterparty(counterparty)
            
            # Derive symmetric key (TS/Go compatible)
            symmetric_key_bytes = self.key_deriver.derive_symmetric_key(protocol, key_id, cp)
            symmetric_key = SymmetricKey(symmetric_key_bytes)
            
            # Encrypt using AES-GCM
            ciphertext = symmetric_key.encrypt(plaintext)
            
            # Return as list of ints (matching TS SDK)
            return {"ciphertext": list(ciphertext)}
        except Exception as e:
            return {"error": f"encrypt: {e}"}

    def decrypt(self, args: DecryptArgs = None, originator: str = None) -> Dict:
        """Decrypt data using AES-GCM with a derived symmetric key.
        
        This implementation matches TS/Go SDK ProtoWallet.decrypt:
        1. Derive symmetric key from protocol_id, key_id, counterparty
        2. Decrypt using AES-GCM (SymmetricKey.decrypt)
        3. Expects ciphertext format: IV (32 bytes) || ciphertext || authTag (16 bytes)
        
        Args format (matches TS SDK WalletDecryptArgs):
            - ciphertext: The encrypted data (bytes or list of ints)
            - protocol_id / protocolID: The protocol ID [security_level, protocol_name]
            - key_id / keyID: The key identifier string
            - counterparty: The counterparty (optional, defaults to 'self')
        """
        try:
            from bsv.primitives.symmetric_key import SymmetricKey
            
            # Support both flat args (TS style) and nested encryption_args (legacy)
            encryption_args = args.get("encryption_args", args)
            
            
            self._maybe_seek_permission("Decrypt", encryption_args)
            
            # Get ciphertext
            ciphertext = args.get("ciphertext")
            if ciphertext is None:
                return {"error": "decrypt: ciphertext is required"}
            
            # Normalize ciphertext to bytes
            if isinstance(ciphertext, list):
                ciphertext = bytes(ciphertext)
            elif isinstance(ciphertext, str):
                # Assume hex encoding for strings
                ciphertext = bytes.fromhex(ciphertext)

            # Check for forbidden snake_case keys
            forbidden_keys = {
                'protocol_id': 'protocolID',
                'key_id': 'keyID'
            }
            for snake_key, camel_key in forbidden_keys.items():
                if snake_key in encryption_args:
                    raise ValueError(f"Wallet API key '{snake_key}' is not supported. Use '{camel_key}' instead.")

            # Get protocol parameters (camelCase only)
            protocol_id = encryption_args.get("protocolID")
            key_id = encryption_args.get("keyID")
            counterparty = encryption_args.get("counterparty")
            
            if protocol_id is None or key_id is None:
                return {"error": "decrypt: protocol_id and key_id are required"}
            
            # Normalize protocol and counterparty
            protocol = self._normalize_protocol(protocol_id)
            cp = self._normalize_counterparty(counterparty)
            
            # Derive symmetric key (TS/Go compatible)
            symmetric_key_bytes = self.key_deriver.derive_symmetric_key(protocol, key_id, cp)
            symmetric_key = SymmetricKey(symmetric_key_bytes)
            
            # Decrypt using AES-GCM
            plaintext = symmetric_key.decrypt(ciphertext)
            
            # Return as list of ints (matching TS SDK)
            return {"plaintext": list(plaintext)}
        except Exception as e:
            return {"error": f"decrypt: {e}"}

    def create_signature(self, args: CreateSignatureArgs = None, originator: str = None) -> Dict:
        try:
            # Check for forbidden snake_case keys
            forbidden_keys = {
                'protocol_id': 'protocolID',
                'key_id': 'keyID'
            }
            for snake_key, camel_key in forbidden_keys.items():
                if snake_key in args:
                    raise ValueError(f"Wallet API key '{snake_key}' is not supported. Use '{camel_key}' instead.")

            # camelCase only
            protocol_id = args.get("protocolID")
            key_id = args.get("keyID")
            counterparty = args.get("counterparty")
            
            
            if protocol_id is None or key_id is None:
                return {"error": "create_signature: protocol_id and key_id are required"}
            
            # Normalize protocol_id (supports both camelCase and snake_case)
            protocol = self._normalize_protocol(protocol_id)
            
            # Default counterparty to 'anyone' for signatures (TS parity)
            if counterparty is None:
                counterparty = "anyone"
            cp = self._normalize_counterparty(counterparty)
            priv = self.key_deriver.derive_private_key(protocol, key_id, cp)
            
            # Get data or hash to sign
            data = args.get("data", b"")
            if isinstance(data, list):
                data = bytes(data)
            hash_to_sign = args.get("hash_to_directly_sign") or args.get("hashToDirectlySign")
            
            if hash_to_sign:
                if isinstance(hash_to_sign, list):
                    hash_to_sign = bytes(hash_to_sign)
                to_sign = hash_to_sign
            else:
                to_sign = hashlib.sha256(data).digest()
            
            # Sign the SHA-256 digest directly (no extra hashing in signer)
            signature = priv.sign(to_sign, hasher=lambda m: m)
            return {"signature": signature}
        except Exception as e:
            return {"error": f"create_signature: {e}"}

    def _normalize_protocol(self, protocol_id):
        """Normalize protocol_id to SimpleNamespace (supports both camelCase and snake_case)."""
        if isinstance(protocol_id, (list, tuple)) and len(protocol_id) == 2:
            return SimpleNamespace(security_level=int(protocol_id[0]), protocol=str(protocol_id[1]))
        elif isinstance(protocol_id, dict):
            # Support both camelCase (API standard) and snake_case (Python standard)
            security_level = protocol_id.get("security_level") or protocol_id.get("securityLevel", 0)
            protocol_str = protocol_id.get("protocol", "")
            return SimpleNamespace(
                security_level=int(security_level),
                protocol=str(protocol_str)
            )
        else:
            return protocol_id

    def _to_public_key(self, arg) -> PublicKey:
        """Convert various representations to a PublicKey."""
        if isinstance(arg, PublicKey):
            return arg
        elif isinstance(arg, bytes):
            return PublicKey(arg)
        elif isinstance(arg, str):
            # Handle special string values
            if arg == "anyone":
                return PrivateKey(1).public_key()
            if arg == "self":
                return self.public_key
            return PublicKey(arg)
        elif isinstance(arg, dict):
            # Handle counterparty dict format
            cp = arg.get("counterparty")
            if cp is not None:
                return self._to_public_key(cp)
            # Handle type-only dict (e.g., {'type': 1} for 'anyone')
            cp_type = arg.get("type")
            if cp_type == CounterpartyType.ANYONE or cp_type == 1:
                return PrivateKey(1).public_key()
            if cp_type == CounterpartyType.SELF or cp_type == 2:
                return self.public_key
            raise ValueError(f"Cannot convert dict to PublicKey: {arg}")
        else:
            raise ValueError(f"Cannot convert {type(arg)} to PublicKey")

    def _encode_point(self, point) -> bytes:
        """Encode a curve point as a compressed public key (33 bytes)."""
        if point is None:
            return b'\x00' * 33
        x, y = point
        # Compressed format: 0x02 or 0x03 prefix + 32-byte x coordinate
        prefix = 0x02 if (y % 2 == 0) else 0x03
        x_bytes = x.to_bytes(32, 'big')
        return bytes([prefix]) + x_bytes


    def _compute_hash_to_verify(self, args: Dict) -> tuple[bytes, bytes]:
        """Compute hash to verify and return (to_verify, data)."""
        data = args.get("data", b"")
        hash_to_verify = args.get("hash_to_directly_verify")
        
        if hash_to_verify:
            return hash_to_verify, data
        else:
            return hashlib.sha256(data).digest(), data


    def verify_signature(self, args: VerifySignatureArgs = None, originator: str = None) -> Dict:
        try:
            # Check for forbidden snake_case keys
            forbidden_keys = {
                'protocol_id': 'protocolID',
                'key_id': 'keyID',
                'for_self': 'forSelf'
            }
            for snake_key, camel_key in forbidden_keys.items():
                if snake_key in args:
                    raise ValueError(f"Wallet API key '{snake_key}' is not supported. Use '{camel_key}' instead.")

            # Extract and validate parameters (camelCase only)
            protocol_id = args.get("protocolID")
            key_id = args.get("keyID")
            counterparty = args.get("counterparty")
            for_self = args.get("forSelf", False)
            
            if protocol_id is None or key_id is None:
                return {"error": "verify_signature: protocol_id and key_id are required"}
            
            # Normalize protocol and derive public key
            protocol = self._normalize_protocol(protocol_id)
            # Default counterparty to 'self' for verify_signature (TS parity)
            # TS ProtoWallet.verifySignature: args.counterparty ?? 'self'
            if counterparty is None:
                counterparty = "self"
            
            cp = self._normalize_counterparty(counterparty)

            pub = self.key_deriver.derive_public_key(protocol, key_id, cp, for_self)
            
            # Always log derived key
            
            # Get data and signature
            signature = args.get("signature")
            if signature is None:
                return {"error": "verify_signature: signature is required"}
            
            to_verify, data = self._compute_hash_to_verify(args)
            
            # Perform verification
            valid = pub.verify(signature, to_verify, hasher=lambda m: m)
            
            
            return {"valid": valid}
        except Exception as e:
            return {"error": f"verify_signature: {e}"}

    def create_hmac(self, args: CreateHmacArgs = None, originator: str = None) -> Dict:
        """Create HMAC using a derived symmetric key.
        
        This implementation matches TS/Go SDK ProtoWallet.CreateHMAC:
        1. Derive symmetric key from protocol_id, key_id, counterparty
        2. Use the derived key to compute HMAC-SHA256 of the data
        
        Args format (supports both flat and nested):
            - data: The data to HMAC (bytes)
            - protocol_id / protocolID: The protocol ID
            - key_id / keyID: The key identifier
            - counterparty: The counterparty (optional, defaults to 'self')
            - encryption_args: Alternative nested format (legacy)
            
        Reference: go-sdk/wallet/proto_wallet.go CreateHMAC
        """
        try:
            # Support both flat args (TS/Go style) and nested encryption_args (legacy)
            encryption_args = args.get("encryption_args", args)
            
            # Get protocol parameters (support both camelCase and snake_case)
            protocol_id = encryption_args.get("protocol_id") or encryption_args.get("protocolID")
            key_id = encryption_args.get("key_id") or encryption_args.get("keyID")
            counterparty = encryption_args.get("counterparty")
            
            
            if protocol_id is None or key_id is None:
                return {"error": "create_hmac: protocol_id and key_id are required"}
            
            # Normalize protocol (supports both camelCase and snake_case)
            protocol = self._normalize_protocol(protocol_id)
            
            # Normalize counterparty (default to 'self' for HMAC, matching Go SDK)
            cp = self._normalize_counterparty(counterparty)
            
            # Derive symmetric key (TS/Go compatible)
            symmetric_key = self.key_deriver.derive_symmetric_key(protocol, key_id, cp)
            
            # Get data
            data = args.get("data", b"")
            if isinstance(data, list):
                data = bytes(data)
            
            # Create HMAC using the derived key
            hmac_value = hmac.new(symmetric_key, data, hashlib.sha256).digest()
            
            return {"hmac": hmac_value}
        except Exception as e:
            return {"error": f"create_hmac: {e}"}

    def _extract_hmac_params(self, args: Dict) -> tuple:
        """Extract HMAC verification parameters from args.
        
        Supports both flat args (TS/Go style) and nested encryption_args (legacy).
        """
        # Support both flat args and nested encryption_args
        encryption_args = args.get("encryption_args", args)

        # Check for forbidden snake_case keys
        forbidden_keys = {
            'protocol_id': 'protocolID',
            'key_id': 'keyID'
        }
        for snake_key, camel_key in forbidden_keys.items():
            if snake_key in encryption_args:
                raise ValueError(f"Wallet API key '{snake_key}' is not supported. Use '{camel_key}' instead.")

        # Get protocol parameters (camelCase only)
        protocol_id = encryption_args.get("protocolID")
        key_id = encryption_args.get("keyID")
        counterparty = encryption_args.get("counterparty")
        
        data = args.get("data", b"")
        if isinstance(data, list):
            data = bytes(data)
            
        hmac_value = args.get("hmac")
        if isinstance(hmac_value, list):
            hmac_value = bytes(hmac_value)
            
        return encryption_args, protocol_id, key_id, counterparty, data, hmac_value


    def verify_hmac(self, args: VerifyHmacArgs = None, originator: str = None) -> Dict:
        print(f"[ProtoWallet.verify_hmac] Starting verification")
        print(f"[ProtoWallet.verify_hmac] Args: {args}")
        try:
            # Extract parameters
            encryption_args, protocol_id, key_id, counterparty, data, hmac_value = self._extract_hmac_params(args)
            
            print(f"[ProtoWallet.verify_hmac] Extracted params:")
            print(f"  - protocol_id: {protocol_id}")
            print(f"  - key_id: {key_id} (type: {type(key_id)}, length: {len(key_id) if isinstance(key_id, str) else 'N/A'})")
            print(f"  - counterparty: {counterparty} (type: {type(counterparty)})")
            print(f"  - data: {data.hex() if isinstance(data, bytes) else data} (length: {len(data) if isinstance(data, bytes) else 'N/A'})")
            print(f"  - hmac_value: {hmac_value.hex() if isinstance(hmac_value, bytes) else hmac_value} (length: {len(hmac_value) if isinstance(hmac_value, bytes) else 'N/A'})")
            
            # Validate required fields
            if protocol_id is None or key_id is None:
                error_msg = "verify_hmac: protocol_id and key_id are required"
                print(f"[ProtoWallet.verify_hmac] ERROR: {error_msg}")
                return {"error": error_msg}
            if hmac_value is None:
                error_msg = "verify_hmac: hmac is required"
                print(f"[ProtoWallet.verify_hmac] ERROR: {error_msg}")
                return {"error": error_msg}
            
            # Normalize protocol and counterparty
            protocol = self._normalize_protocol(protocol_id)
            cp = self._normalize_counterparty(counterparty)
            
            print(f"[ProtoWallet.verify_hmac] Normalized:")
            print(f"  - protocol: {protocol}")
            print(f"  - counterparty normalized: {cp}")
            
            
            # Derive shared secret and verify HMAC
            print(f"[ProtoWallet.verify_hmac] Deriving symmetric key...")
            shared_secret = self.key_deriver.derive_symmetric_key(protocol, key_id, cp)
            print(f"[ProtoWallet.verify_hmac] Shared secret length: {len(shared_secret)}")
            print(f"[ProtoWallet.verify_hmac] Computing expected HMAC...")
            expected = hmac.new(shared_secret, data, hashlib.sha256).digest()
            print(f"[ProtoWallet.verify_hmac] Expected HMAC: {expected.hex()}")
            print(f"[ProtoWallet.verify_hmac] Received HMAC: {hmac_value.hex() if isinstance(hmac_value, bytes) else hmac_value}")
            valid = hmac.compare_digest(expected, hmac_value)
            print(f"[ProtoWallet.verify_hmac] HMAC comparison result: {valid}")
            
            return {"valid": valid}
        except Exception as e:
            error_msg = f"verify_hmac: {e}"
            print(f"[ProtoWallet.verify_hmac] EXCEPTION: {error_msg}")
            import traceback
            print(f"[ProtoWallet.verify_hmac] Traceback: {traceback.format_exc()}")
            return {"error": error_msg}

    def abort_action(self, *a, **k):
        # NOTE: This mock wallet does not manage long-running actions, so there is
        # nothing to abort. The method is intentionally left empty to satisfy the
        # interface and to document that abort semantics are a no-op in tests.
        pass
    def acquire_certificate(self, args: Dict = None, originator: str = None) -> Dict:
        # store minimal certificate record for listing/discovery
        record = {
            "certificateBytes": args.get("type", b"") + args.get("serialNumber", b""),
            "keyring": args.get("keyringForSubject"),
            "verifier": b"",
            "match": (args.get("type"), args.get("serialNumber"), args.get("certifier")),
            "attributes": args.get("fields", {}),
        }
        self._certificates.append(record)
        return {}

    def _process_pushdrop_args(self, pushdrop_args: Dict, originator: str, outputs: List[Dict]) -> None:
        """Process PushDrop arguments and append the output if needed."""
        from bsv.transaction.pushdrop import build_lock_before_pushdrop, PushDrop
        
        fields = pushdrop_args.get("fields", [])
        pubkey = pushdrop_args.get("public_key")
        include_signature = pushdrop_args.get("include_signature", False)
        signature = pushdrop_args.get("signature")
        lock_position = pushdrop_args.get("lock_position", "before")
        basket = pushdrop_args.get("basket")
        retention = pushdrop_args.get("retentionSeconds")
        protocol_id = pushdrop_args.get("protocolID")
        key_id = pushdrop_args.get("keyID")
        counterparty = pushdrop_args.get("counterparty")
        
        if pubkey:
            locking_script = build_lock_before_pushdrop(
                fields, pubkey, include_signature=include_signature,
                signature=signature, lock_position=lock_position
            )
        else:
            pd = PushDrop(self, originator)
            locking_script = pd.lock(
                fields, protocol_id, key_id, counterparty,
                for_self=True, include_signature=include_signature,
                lock_position=lock_position
            )
        
        pushdrop_satoshis = pushdrop_args.get("satoshis", 1)
        output = {"lockingScript": locking_script, "satoshis": pushdrop_satoshis}
        if basket:
            output["basket"] = basket
        if retention:
            output["outputDescription"] = {"retentionSeconds": retention}
        
        if not outputs:
            outputs.append(output)

    def _calculate_existing_unlock_lens(self, inputs_meta: List[Dict]) -> List[int]:
        """Calculate existing inputs' estimated unlocking lengths."""
        return [int(meta.get("unlockingScriptLength", 73)) for meta in inputs_meta]

    def _calculate_change_amount(
        self, inputs_meta: List[Dict], outputs: List[Dict], fee_rate: int, fee_model
    ) -> tuple[Optional[int], int]:
        """Calculate change amount and fee. Returns (change_sats, fee)."""
        input_sum = 0
        for meta in inputs_meta:
            outpoint = meta.get("outpoint") or meta.get("Outpoint")
            if outpoint and isinstance(outpoint, dict):
                for o in outputs:
                    if self._outpoint_matches_output(outpoint, o):
                        input_sum += int(o.get("satoshis", 0))
                        break
        
        keyvalue_satoshis = self._find_keyvalue_satoshis(outputs)
        fee = self._calculate_fee(fee_rate, fee_model, len(outputs), len(inputs_meta))
        
        if input_sum > 0:
            change_sats = input_sum - keyvalue_satoshis - fee
            return change_sats if change_sats > 0 else None, fee
        return None, fee

    def _outpoint_matches_output(self, outpoint: Dict, output: Dict) -> bool:
        """Check if an outpoint matches an output."""
        txid_match = (
            (isinstance(output.get("txid"), str) and bytes.fromhex(output.get("txid")) == outpoint.get("txid")) or
            (isinstance(output.get("txid"), (bytes, bytearray)) and output.get("txid") == outpoint.get("txid"))
        )
        index_match = int(output.get("outputIndex", 0)) == int(outpoint.get("index", 0))
        return txid_match and index_match

    def _find_keyvalue_satoshis(self, outputs: List[Dict]) -> int:
        """Find satoshis amount for key-value output."""
        for o in outputs:
            desc = o.get("outputDescription", "")
            if (isinstance(desc, str) and "kv.set" in desc) or (isinstance(desc, dict) and desc.get("type") == "kv.set"):
                return int(o.get("satoshis", 0))
        return 0

    def _calculate_fee(self, fee_rate: int, fee_model, output_count: int, input_count: int) -> int:
        """Calculate transaction fee."""
        if fee_rate and fee_rate > 0:
            estimated_size = input_count * 148 + output_count * 34 + 10
            return int(estimated_size * fee_rate / 1000)
        try:
            return fee_model.estimate(output_count, input_count)
        except Exception:
            return 0

    def _normalize_outputs_to_hex(self, outputs: List[Dict]) -> None:
        """Normalize lockingScript in outputs to hex string."""
        for o in outputs:
            ls = o.get("lockingScript")
            if isinstance(ls, bytes):
                o["lockingScript"] = ls.hex()

    def _add_change_output_if_needed(self, change_output: Optional[Dict], inputs_meta: List[Dict], outputs: List[Dict], fee_rate: int, fee_model) -> None:
        """Add change output to outputs if it has positive satoshis."""
        if not change_output:
            return
        
        change_sats, fee = self._calculate_change_amount(inputs_meta, outputs, fee_rate, fee_model)
        print(f"[TRACE] [create_action] Change calculation: change_sats={change_sats}, fee={fee}")
        
        if change_sats is not None and change_sats > 0:
            change_output["satoshis"] = change_sats
            outputs.append(change_output)
            print(f"[TRACE] [create_action] Added change output: {change_sats} satoshis")
        elif int(change_output.get("satoshis", 0)) > 0:
            outputs.append(change_output)
            print(f"[TRACE] [create_action] Added change output: {change_output.get('satoshis')} satoshis")

    def _normalize_action_txid(self, action: Dict) -> None:
        """Ensure txid is bytes for wallet serialization."""
        try:
            txid = action.get("txid")
            if isinstance(txid, str) and len(txid) == 64:
                action["txid"] = bytes.fromhex(txid)
        except Exception:
            pass

    def _build_result_dict(self, signable_tx, inputs_meta: List[Dict], outputs: List[Dict], fee_rate: int, change_output: Optional[Dict], action: Dict) -> Dict:
        """Build the final result dictionary."""
        import binascii
        
        # Return lockingScript as hex for test vectors
        for out in outputs:
            ls = out.get("lockingScript")
            if ls is not None and not isinstance(ls, str):
                out["lockingScriptHex"] = binascii.hexlify(ls).decode()
        
        return {
            "signableTransaction": {"tx": signable_tx.serialize()},
            "inputs": inputs_meta,
            "outputs": outputs,
            "feeRate": fee_rate,
            "changeOutput": change_output,
            "action": action,
        }

    def create_action(self, args: Dict = None, originator: str = None) -> Dict:
        """
        Build a Transaction from inputs/outputs; auto-fund with wallet UTXOs (Go-style).
        - Always calls .serialize() on Transaction object returned by _build_signable_transaction.
        """
        import binascii
        print(f"[TRACE] [create_action] called with labels={args.get('labels')} outputs_count={len(args.get('outputs') or [])}")
        
        labels = args.get("labels") or []
        description = args.get("description", "")
        outputs = list(args.get("outputs") or [])
        inputs_meta = list(args.get("inputs") or [])
        
        print("[TRACE] [create_action] initial inputs_meta:", inputs_meta)
        print("[TRACE] [create_action] initial outputs:", outputs)
        
        # Process PushDrop extension if provided
        pushdrop_args = args.get("pushdrop")
        if pushdrop_args:
            print("[TRACE] [create_action] found pushdrop_args")
            self._process_pushdrop_args(pushdrop_args, originator, outputs)
        
        print("[TRACE] [create_action] after pushdrop outputs:", outputs)
        
        # Setup fee model and existing unlock lengths
        fee_rate = int(args.get("feeRate") or 500)
        fee_model = SatoshisPerKilobyte(fee_rate)
        _ = self._sum_outputs(outputs)
        existing_unlock_lens = self._calculate_existing_unlock_lens(inputs_meta)
        
        # Auto-fund if needed
        funding_ctx, change_output = self._select_funding_and_change(
            args, originator, outputs, inputs_meta, existing_unlock_lens, fee_model
        )
        
        if funding_ctx:
            print(f"[TRACE] [create_action] funding_ctx returned: {len(funding_ctx)} UTXOs")
        
        # Trace fee estimation if needed
        if pushdrop_args and funding_ctx:
            fee = self._calculate_fee(fee_rate, fee_model, len(outputs), len(inputs_meta))
            print(f"[TRACE] [create_action] Calculated fee: {fee} satoshis")
        
        # Add change output if generated
        self._add_change_output_if_needed(change_output, inputs_meta, outputs, fee_rate, fee_model)
        
        total_out = self._sum_outputs(outputs)
        self._normalize_outputs_to_hex(outputs)
        
        print("[TRACE] [create_action] before _build_action_dict inputs_meta:", inputs_meta)
        action = self._build_action_dict(args, total_out, description, labels, inputs_meta, outputs)
        
        self._normalize_action_txid(action)
        self._actions.append(action)
        
        # Build signable transaction
        funding_start_index = len(inputs_meta) - len(funding_ctx) if funding_ctx else None
        signable_tx = self._build_signable_transaction(
            outputs, inputs_meta, prefill_funding=True,
            funding_start_index=funding_start_index, funding_context=funding_ctx
        )
        
        return self._build_result_dict(signable_tx, inputs_meta, outputs, fee_rate, change_output, action)

    def _normalize_locking_script_to_bytes(self, ls_val) -> bytes:
        """Normalize lockingScript value to bytes."""
        if isinstance(ls_val, str):
            try:
                return bytes.fromhex(ls_val)
            except Exception:
                return b""
        return ls_val or b""

    def _normalize_output_description(self, output_desc) -> str:
        """Normalize outputDescription (serialize dict to JSON if needed)."""
        if isinstance(output_desc, dict):
            import json
            return json.dumps(output_desc)
        return output_desc or ""

    def _normalize_output_for_action(self, output: dict, index: int, created_at: int) -> dict:
        """Normalize a single output for action dictionary."""
        ls_bytes = self._normalize_locking_script_to_bytes(output.get("lockingScript", b""))
        output_desc = self._normalize_output_description(output.get("outputDescription", ""))
        
        return {
            "outputIndex": int(index),
            "satoshis": int(output.get("satoshis", 0)),
            "lockingScript": ls_bytes,
            "spendable": True,
            "outputDescription": output_desc,
            "basket": output.get("basket", ""),
            "tags": output.get("tags") or [],
            "customInstructions": output.get("customInstructions"),
            "createdAt": created_at,
        }

    def _build_action_dict(self, args, total_out, description, labels, inputs_meta, outputs):
        created_at = int(time.time())
        txid = (b"\x00" * 32).hex()
        
        # Normalize all outputs
        norm_outputs = [self._normalize_output_for_action(o, i, created_at) 
                       for i, o in enumerate(outputs)]
        
        return {
            "txid": txid,
            "satoshis": total_out,
            "status": "unprocessed",
            "isOutgoing": True,
            "description": description,
            "labels": labels,
            "version": int(args.get("version") or 0),
            "lockTime": int(args.get("lockTime") or 0),
            "inputs": inputs_meta,
            "outputs": norm_outputs,
        }

    def _normalize_lockingscripts_to_hex(self, outputs: List[Dict]) -> None:
        """Convert all lockingScripts in outputs to hex strings."""
        for output in outputs:
            ls = output.get("lockingScript")
            if isinstance(ls, bytes):
                output["lockingScript"] = ls.hex()

    def _add_outputs_to_transaction(self, t, outputs: List[Dict], logger) -> None:
        """Add all outputs to the transaction."""
        from bsv.transaction_output import TransactionOutput
        from bsv.script.script import Script
        
        for o in outputs:
            ls = o.get("lockingScript", b"")
            ls_hex = ls.hex() if isinstance(ls, bytes) else ls
            satoshis = o.get("satoshis", 0)
            logger.debug(f"Output satoshis type: {type(satoshis)}, value: {satoshis}")
            logger.debug(f"Output lockingScript type: {type(ls_hex)}, value: {ls_hex}")
            assert isinstance(satoshis, int), f"satoshis must be int, got {type(satoshis)}"
            assert isinstance(ls_hex, str), f"lockingScript must be hex string, got {type(ls_hex)}"
            s = Script(ls_hex)
            to = TransactionOutput(s, int(satoshis))
            t.add_output(to)

    def _add_inputs_to_transaction(self, t, inputs_meta: List[Dict]) -> List[int]:
        """Add all inputs to the transaction and return funding indices."""
        from bsv.transaction_input import TransactionInput
        
        funding_indices: List[int] = []
        for i, meta in enumerate(inputs_meta):
            print(f"[TRACE] [_build_signable_transaction] input_meta[{i}]:", meta)
            outpoint = meta.get("outpoint") or meta.get("Outpoint")
            if outpoint and isinstance(outpoint, dict):
                txid = outpoint.get("txid")
                index = outpoint.get("index", 0)
                txid_str = self._convert_txid_to_hex(txid)
                ti = TransactionInput(source_txid=txid_str, source_output_index=int(index))
                t.add_input(ti)
                funding_indices.append(len(t.inputs) - 1)
        return funding_indices

    def _convert_txid_to_hex(self, txid) -> str:
        """Convert txid to hex string format."""
        if isinstance(txid, bytes):
            return txid.hex()
        elif isinstance(txid, str):
            return txid
        return "00" * 32

    def _set_funding_context_on_inputs(self, t, funding_start_index: int, funding_context: List[Dict]) -> None:
        """Set precise prevout data from funding context."""
        from bsv.script.script import Script
        
        for j, ctx_item in enumerate(funding_context):
            idx = funding_start_index + j
            if 0 <= idx < len(t.inputs):
                tin = t.inputs[idx]
                tin.satoshis = int(ctx_item.get("satoshis", 0))
                ls_b = ctx_item.get("lockingScript") or b""
                if isinstance(ls_b, str):
                    try:
                        ls_b = bytes.fromhex(ls_b)
                    except Exception:
                        ls_b = b""
                tin.locking_script = Script(ls_b)

    def _set_generic_funding_scripts(self, t, funding_indices: List[int]) -> None:
        """Set generic P2PKH lock for funding inputs."""
        addr = self.public_key.address()
        ls_fund = P2PKH().lock(addr)
        for idx in funding_indices:
            tin = t.inputs[idx]
            tin.satoshis = 0
            tin.locking_script = ls_fund

    def _derive_private_key_for_input(self, meta: Dict):
        """Derive the appropriate private key for an input."""
        protocol = meta.get("protocol")
        key_id = meta.get("key_id")
        counterparty = meta.get("counterparty")
        
        if protocol is not None and key_id is not None:
            if isinstance(protocol, dict):
                protocol_obj = SimpleNamespace(
                    security_level=int(protocol.get("securityLevel", 0)),
                    protocol=str(protocol.get("protocol", ""))
                )
            else:
                protocol_obj = protocol
            cp = self._normalize_counterparty(counterparty)
            return self.key_deriver.derive_private_key(protocol_obj, key_id, cp)
        return self.private_key

    def _sign_funding_inputs(self, t, funding_indices: List[int], inputs_meta: List[Dict]) -> None:
        """Sign all funding inputs."""
        for idx in funding_indices:
            meta = inputs_meta[idx] if idx < len(inputs_meta) else {}
            priv = self._derive_private_key_for_input(meta)
            print(f"[TRACE] [_build_signable_transaction] priv address: {priv.address()}")
            
            try:
                prevout_script_bytes = t.inputs[idx].locking_script.serialize()
                self._check_prevout_pubkey(priv, prevout_script_bytes)
            except Exception as _dbg_e:
                print(f"[TRACE] [sign_check] prevout/pubkey hash check skipped: {_dbg_e}")
            
            unlock_tpl = P2PKH().unlock(priv)
            t.inputs[idx].unlocking_script = unlock_tpl.sign(t, idx)
            
            try:
                us_b = t.inputs[idx].unlocking_script.serialize()
                self._check_unlocking_sig(us_b, priv)
            except Exception as _dbg_e2:
                print(f"[TRACE] [sign_check] scriptSig structure check skipped: {_dbg_e2}")

    def _build_signable_transaction(self, outputs, inputs_meta, prefill_funding: bool = False, funding_start_index: Optional[int] = None, funding_context: Optional[List[Dict[str, Any]]] = None):
        """
        Always return a Transaction object, even if outputs is empty (for remove flows).
        Ensure TransactionInput receives source_txid as hex string (str), not bytes.
        Ensure TransactionOutput receives int(satoshis) and Script in correct order.
        """
        self._normalize_lockingscripts_to_hex(outputs)
        print("[TRACE] [_build_signable_transaction] inputs_meta at entry:", inputs_meta)
        print("[TRACE] [_build_signable_transaction] outputs at entry:", outputs)
        
        try:
            from bsv.transaction import Transaction
            import logging
            logging.basicConfig(level=logging.DEBUG)
            logger = logging.getLogger(__name__)
            
            logger.debug(f"Building transaction with outputs: {outputs}")
            logger.debug(f"Building transaction with inputs_meta: {inputs_meta}")
            
            t = Transaction()
            self._normalize_lockingscripts_to_hex(outputs)
            self._add_outputs_to_transaction(t, outputs, logger)
            funding_indices = self._add_inputs_to_transaction(t, inputs_meta)
            
            print("[TRACE] [_build_signable_transaction] funding_indices:", funding_indices)
            
            if prefill_funding and funding_indices:
                try:
                    if funding_start_index is not None and funding_context:
                        self._set_funding_context_on_inputs(t, funding_start_index, funding_context)
                    else:
                        self._set_generic_funding_scripts(t, funding_indices)
                    
                    self._sign_funding_inputs(t, funding_indices, inputs_meta)
                except Exception:
                    pass
            
            return t
        except Exception as e:
            print(f"[ERROR] Exception in _build_signable_transaction: {e}")
            raise

    def discover_by_attributes(self, args: Dict = None, originator: str = None) -> Dict:
        attrs = args.get("attributes", {}) or {}
        matches = []
        for c in self._certificates:
            if all(c.get("attributes", {}).get(k) == v for k, v in attrs.items()):
                # Return identity certificate minimal (wrap stored bytes as base cert only)
                matches.append({
                    "certificateBytes": c.get("certificateBytes", b""),
                    "certifierInfo": {"name": "", "iconUrl": "", "description": "", "trust": 0},
                    "publiclyRevealedKeyring": {},
                    "decryptedFields": {},
                })
        return {"totalCertificates": len(matches), "certificates": matches}
    def discover_by_identity_key(self, args: Dict = None, originator: str = None) -> Dict:
        # naive: no identity index, return empty
        return {"totalCertificates": 0, "certificates": []}
    def get_header_for_height(self, args: Dict = None, originator: str = None) -> Dict:
        # minimal: return empty header bytes
        return {"header": b""}
    def get_height(self, args: Dict = None, originator: str = None) -> Dict:
        return {"height": 0}
    def get_network(self, args: Dict = None, originator: str = None) -> Dict:
        return {"network": "mocknet"}
    def get_version(self, args: Dict = None, originator: str = None) -> Dict:
        return {"version": "0.0.0"}
    def internalize_action(self, args: Dict = None, originator: str = None) -> Dict:
        """
        Broadcast the signed transaction to the network.
        - If outputs are empty, do not broadcast and return an error.
        """
        tx_bytes = args.get("tx")
        if not tx_bytes:
            return {"accepted": False, "error": "internalize_action: missing tx bytes"}
        
        # Parse and validate transaction
        tx_result = self._parse_transaction_for_broadcast(tx_bytes)
        if "error" in tx_result:
            return tx_result
        
        tx_hex = tx_result["tx_hex"]
        
        # Determine broadcaster configuration
        broadcaster_config = self._determine_broadcaster_config(args)
        
        # Route to appropriate broadcaster
        return self._execute_broadcast(tx_bytes, tx_hex, args, broadcaster_config)

    def _parse_transaction_for_broadcast(self, tx_bytes: bytes) -> Dict:
        """Parse and validate transaction before broadcasting."""
        import binascii
        try:
            from bsv.transaction import Transaction
            from bsv.utils import Reader
            tx = Transaction.from_reader(Reader(tx_bytes))
            
            # Guard: do not broadcast if outputs are empty
            if not getattr(tx, "outputs", None) or len(tx.outputs) == 0:
                return {
                    "error": "Cannot broadcast transaction with no outputs",
                    "tx_hex": binascii.hexlify(tx_bytes).decode()
                }
            
            tx_hex = tx.to_hex() if hasattr(tx, "to_hex") else binascii.hexlify(tx_bytes).decode()
            return {"tx_hex": tx_hex, "tx": tx}
        except Exception as e:
            return {"error": f"Failed to parse transaction: {e}"}

    def _determine_broadcaster_config(self, args: Dict) -> Dict:
        """Determine which broadcaster to use based on configuration."""
        import os

        # Check for forbidden snake_case keys
        forbidden_keys = {
            'disable_arc': 'disableArc',
            'use_woc': 'useWoc',
            'use_mapi': 'useMAPI',
            'use_custom_node': 'useCustomNode'
        }
        for snake_key, camel_key in forbidden_keys.items():
            if snake_key in args:
                raise ValueError(f"Broadcaster config key '{snake_key}' is not supported. Use '{camel_key}' instead.")

        disable_arc = os.getenv("DISABLE_ARC", "0") == "1" or args.get("disableArc")
        use_arc = not disable_arc  # ARC is enabled by default
        use_woc = os.getenv("USE_WOC", "0") == "1" or args.get("useWoc")
        use_mapi = args.get("useMAPI")
        use_custom_node = args.get("useCustomNode")
        ext_bc = args.get("broadcaster")
        
        return {
            "use_arc": use_arc,
            "use_woc": use_woc,
            "use_mapi": use_mapi,
            "use_custom_node": use_custom_node,
            "custom_broadcaster": ext_bc
        }

    def _execute_broadcast(self, tx_bytes: bytes, tx_hex: str, args: Dict, config: Dict) -> Dict:
        """Execute broadcast using the determined broadcaster."""
        # Priority: Custom > ARC > WOC > MAPI > Custom Node
        if config["custom_broadcaster"] and hasattr(config["custom_broadcaster"], "broadcast"):
            return self._broadcast_with_custom(config["custom_broadcaster"], tx_hex)
        elif config["use_arc"]:
            return self._broadcast_with_arc(tx_bytes, tx_hex, args, config["use_woc"])
        elif config["use_woc"]:
            return self._broadcast_with_woc(tx_hex, args)
        elif config["use_mapi"]:
            return self._broadcast_with_mapi(tx_hex, args)
        elif config["use_custom_node"]:
            return self._broadcast_with_custom_node(tx_hex, args)
        else:
            return self._broadcast_with_mock(tx_bytes, tx_hex)

    def _broadcast_with_custom(self, broadcaster, tx_hex: str) -> Dict:
        """Broadcast using custom broadcaster."""
        res = broadcaster.broadcast(tx_hex)
        if isinstance(res, dict) and (res.get("accepted") or res.get("txid")):
            return {"accepted": True, "txid": res.get("txid"), "tx_hex": tx_hex}
        return res

    def _broadcast_with_arc(self, tx_bytes: bytes, tx_hex: str, args: Dict, use_woc_fallback: bool) -> Dict:
        """Broadcast using ARC with optional WOC fallback."""
        import os
        from bsv.broadcasters.arc import ARC, ARCConfig
        
        arc_url = args.get("arc_url") or os.getenv("ARC_URL", "https://arc.taal.com")
        arc_api_key = args.get("arc_api_key") or os.getenv("ARC_API_KEY")
        timeout = int(args.get("timeoutSeconds", int(os.getenv("ARC_TIMEOUT", "30"))))
        
        # Create ARC config with required headers
        headers = {"X-WaitFor": "SEEN_ON_NETWORK", "X-MaxTimeout": "1"}
        arc_config = ARCConfig(api_key=arc_api_key, headers=headers) if arc_api_key else ARCConfig(headers=headers)
        bc = ARC(arc_url, arc_config)
        
        print(f"[INFO] Broadcasting to ARC (default). URL: {arc_url}, tx_hex: {tx_hex}")
        
        try:
            from bsv.transaction import Transaction
            from bsv.utils import Reader
            tx_obj = Transaction.from_reader(Reader(tx_bytes))
            arc_result = bc.sync_broadcast(tx_obj, timeout=timeout)
            
            if hasattr(arc_result, 'status') and arc_result.status == "success":
                return {
                    "accepted": True,
                    "txid": arc_result.txid,
                    "tx_hex": tx_hex,
                    "message": arc_result.message,
                    "broadcaster": "ARC"
                }
            else:
                error_msg = getattr(arc_result, 'description', 'ARC broadcast failed')
                print(f"[WARN] ARC broadcast failed: {error_msg}, falling back to WOC if enabled")
                
                if use_woc_fallback:
                    return self._broadcast_with_woc(tx_hex, args, is_fallback=True)
                return {"accepted": False, "error": error_msg, "tx_hex": tx_hex, "broadcaster": "ARC"}
                
        except Exception as arc_error:
            print(f"[WARN] ARC broadcast error: {arc_error}, falling back to WOC if enabled")
            
            if use_woc_fallback:
                return self._broadcast_with_woc(tx_hex, args, is_fallback=True)
            return {"accepted": False, "error": f"ARC error: {arc_error}", "tx_hex": tx_hex, "broadcaster": "ARC"}

    def _broadcast_with_woc(self, tx_hex: str, args: Dict, is_fallback: bool = False) -> Dict:
        """Broadcast using WhatsOnChain."""
        import os
        from bsv.broadcasters.whatsonchain import WhatsOnChainBroadcasterSync
        
        api_key = self._resolve_woc_api_key(args)
        timeout = int(args.get("timeoutSeconds", int(os.getenv("WOC_TIMEOUT", "10"))))
        network = self._get_network_for_broadcast()
        
        bc = WhatsOnChainBroadcasterSync(network=network, api_key=api_key)
        label = "Fallback broadcasting" if is_fallback else "Broadcasting"
        print(f"[INFO] {label} to WhatsOnChain. tx_hex: {tx_hex}")
        
        res = bc.broadcast(tx_hex, api_key=api_key, timeout=timeout)
        broadcaster_label = "WOC (fallback)" if is_fallback else "WOC"
        return {**res, "tx_hex": tx_hex, "broadcaster": broadcaster_label}

    def _broadcast_with_mapi(self, tx_hex: str, args: Dict) -> Dict:
        """Broadcast using MAPI."""
        import os
        from bsv.network.broadcaster import MAPIClientBroadcaster
        
        api_url = args.get("mapi_url") or os.getenv("MAPI_URL")
        api_key = args.get("mapi_api_key") or os.getenv("MAPI_API_KEY")
        
        if not api_url:
            return {"accepted": False, "error": "internalize_action: mAPI url missing", "tx_hex": tx_hex}
        
        bc = MAPIClientBroadcaster(api_url=api_url, api_key=api_key)
        res = bc.broadcast(tx_hex)
        return {**res, "tx_hex": tx_hex}

    def _broadcast_with_custom_node(self, tx_hex: str, args: Dict) -> Dict:
        """Broadcast using custom node."""
        import os
        from bsv.network.broadcaster import CustomNodeBroadcaster
        
        api_url = args.get("custom_node_url") or os.getenv("CUSTOM_NODE_URL")
        api_key = args.get("custom_node_api_key") or os.getenv("CUSTOM_NODE_API_KEY")
        
        if not api_url:
            return {"accepted": False, "error": "internalize_action: custom node url missing", "tx_hex": tx_hex}
        
        bc = CustomNodeBroadcaster(api_url=api_url, api_key=api_key)
        res = bc.broadcast(tx_hex)
        return {**res, "tx_hex": tx_hex}

    def _broadcast_with_mock(self, tx_bytes: bytes, tx_hex: str) -> Dict:
        """Broadcast using mock logic (for testing)."""
        from bsv.transaction import Transaction
        from bsv.utils import Reader
        tx = Transaction.from_reader(Reader(tx_bytes))
        txid = tx.txid() if hasattr(tx, "txid") else None
        return {"accepted": True, "txid": txid, "tx_hex": tx_hex, "mock": True}

    def _get_network_for_broadcast(self) -> str:
        """Determine network (main/test) from private key."""
        if hasattr(self, 'private_key') and hasattr(self.private_key, 'network'):
            from bsv.constants import Network
            if self.private_key.network == Network.TESTNET:
                return "test"
        return "main"

    # --- Optional: simple query helpers for mempool/confirm ---
    def query_tx_mempool(self, txid: str, *, network: str = "main", api_key: Optional[str] = None, timeout: int = 10) -> Dict[str, Any]:
        """Check if a tx is known via injected ChainTracker or WOC."""
        # Prefer injected tracker on the instance
        tracker = getattr(self, "_chain_tracker", None)
        if tracker and hasattr(tracker, "query_tx"):
            try:
                return tracker.query_tx(txid, api_key=api_key, network=network, timeout=timeout)
            except Exception as e:  # noqa: PERF203
                return {"known": False, "error": str(e)}
        # Fallback to WhatsOnChainTracker
        from bsv.chaintrackers import WhatsOnChainTracker
        try:
            key = api_key or self._resolve_woc_api_key({})
            ct = WhatsOnChainTracker(api_key=key, network=network)
            return ct.query_tx(txid, timeout=timeout)
        except Exception as e:  # noqa: PERF203
            return {"known": False, "error": str(e)}
    def is_authenticated(self, args: Dict = None, originator: str = None) -> Dict:
        return {"authenticated": True}
    def list_actions(self, args: Dict = None, originator: str = None) -> Dict:
        labels = args.get("labels") or []
        mode = args.get("labelQueryMode", "")
        def match(act):
            if not labels:
                return True
            act_labels = act.get("labels") or []
            if mode == "all":
                return all(l in act_labels for l in labels)
            # default any
            return any(l in act_labels for l in labels)
        actions = [a for a in self._actions if match(a)]
        return {"totalActions": len(actions), "actions": actions}
    def list_certificates(self, args: Dict = None, originator: str = None) -> Dict:
        # Minimal: return stored certificates
        return {"totalCertificates": len(self._certificates), "certificates": self._certificates}
    def list_outputs(self, args: Dict = None, originator: str = None) -> Dict:
        """
        Fetch UTXOs. Priority: WOC > Mock logic
        When both WOC and ARC are enabled, WOC is preferred for UTXO fetching.
        """
        # Allow cooperative cancel
        if args.get("cancel"):
            return {"outputs": []}
        
        include = (args.get("include") or "").lower()
        use_woc = self._should_use_woc(args, include)
        
        try:
            print(f"[TRACE] [list_outputs] include='{include}' use_woc={use_woc} basket={args.get('basket')} tags={args.get('tags')}")
        except Exception:
            pass
        
        if use_woc:
            return self._get_outputs_from_woc(args)
        
        return self._get_outputs_from_mock(args, include)

    def _should_use_woc(self, args: Dict, include: str) -> bool:
        """Determine if WOC should be used for UTXO fetching."""
        # WOC cannot return BEEF, so skip if entire transactions requested
        if "entire" in include or "transaction" in include:
            return False
        
        # Check explicit arg first, then environment variable
        if "use_woc" in args:
            return args.get("use_woc", False)
        
        return os.getenv("USE_WOC", "0") == "1"

    def _get_outputs_from_woc(self, args: Dict) -> Dict:
        """Fetch outputs from WOC service."""
        address = self._derive_query_address(args)
        
        if not address or not isinstance(address, str) or not validate_address(address):
            address = self._get_fallback_address()
            if isinstance(address, dict):  # Error response
                return address
        
        timeout = int(args.get("timeoutSeconds", int(os.getenv("WOC_TIMEOUT", "10"))))
        utxos = self._get_utxos_from_woc(address, timeout=timeout)
        return {"outputs": utxos}

    def _derive_query_address(self, args: Dict) -> Optional[str]:
        """Derive address for UTXO query from various sources."""
        try:
            # Try protocol/key derivation first
            protocol_id, key_id, counterparty = self._extract_protocol_params(args)
            
            if protocol_id and key_id is not None:
                protocol = self._normalize_protocol_id(protocol_id)
                cp = self._normalize_counterparty(counterparty)
                derived_pub = self.key_deriver.derive_public_key(protocol, key_id, cp, for_self=False)
                return derived_pub.address()
        except Exception:
            pass
        
        # Fallback to basket or tags
        return args.get("basket") or (args.get("tags") or [None])[0]

    def _extract_protocol_params(self, args: Dict) -> tuple:
        """Extract protocol parameters from args."""
        protocol_id = args.get("protocolID") or args.get("protocol_id")
        key_id = args.get("keyID") or args.get("key_id")
        counterparty = args.get("counterparty")
        
        # Fallback: read from nested pushdrop bag
        if protocol_id is None or key_id is None:
            pd = args.get("pushdrop") or {}
            protocol_id = protocol_id or pd.get("protocolID") or pd.get("protocol_id")
            key_id = key_id or pd.get("keyID") or pd.get("key_id")
            if counterparty is None:
                counterparty = pd.get("counterparty")
        
        return protocol_id, key_id, counterparty

    def _normalize_protocol_id(self, protocol_id):
        """Normalize protocol_id to SimpleNamespace."""
        if isinstance(protocol_id, dict):
            return SimpleNamespace(
                security_level=int(protocol_id.get("securityLevel", 0)),
                protocol=str(protocol_id.get("protocol", ""))
            )
        return protocol_id

    def _get_fallback_address(self):
        """Get fallback address from wallet's public key."""
        try:
            from bsv.keys import PublicKey
            pubkey = self.public_key if hasattr(self, "public_key") else None
            if pubkey and hasattr(pubkey, "to_address"):
                return pubkey.to_address("mainnet")
            return {"error": "No address available for WOC UTXO lookup"}
        except Exception as e:
            return {"error": f"Failed to derive address: {e}"}

    def _get_outputs_from_mock(self, args: Dict, include: str) -> Dict:
        """Get outputs from mock/local logic."""
        basket = args.get("basket", "")
        outputs_desc = self._find_outputs_for_basket(basket, args)
        
        try:
            print(f"[TRACE] [list_outputs] outputs_desc_len={len(outputs_desc)} sample={outputs_desc[0] if outputs_desc else None}")
        except Exception:
            pass
        
        # Filter expired outputs if requested
        if args.get("excludeExpired"):
            now_epoch = int(args.get("nowEpoch", time.time()))
            outputs_desc = [o for o in outputs_desc if not self._is_output_expired(o, now_epoch)]
        
        
        beef_bytes = self._build_beef_for_outputs(outputs_desc)
        res = {"outputs": self._format_outputs_result(outputs_desc, basket)}
        
        if "entire" in include or "transaction" in include:
            res["BEEF"] = beef_bytes
            try:
                print(f"[TRACE] [list_outputs] BEEF len={len(beef_bytes)}")
            except Exception:
                pass
        return res

    # ---- Helpers to reduce cognitive complexity in list_outputs ----
    def _find_outputs_for_basket(self, basket: str, args: Dict) -> List[Dict[str, Any]]:
        outputs_desc: List[Dict[str, Any]] = []
        for action in reversed(self._actions):
            outs = action.get("outputs") or []
            filtered = [o for o in outs if (not basket) or (o.get("basket") == basket)]
            if filtered:
                outputs_desc = filtered
                break
        if outputs_desc:
            return outputs_desc
        # Fallback to one mock output
        return [{
            "outputIndex": 0,
            "satoshis": 1000,
            "lockingScript": b"\x51",
            "spendable": True,
            "outputDescription": "mock",
            "basket": basket,
            "tags": args.get("tags", []) or [],
            "customInstructions": None,
        }]

    def _build_beef_for_outputs(self, outputs_desc: List[Dict[str, Any]]) -> bytes:
        try:
            from bsv.transaction import Transaction
            from bsv.transaction_output import TransactionOutput
            from bsv.script.script import Script
            tx = Transaction()
            try:
                print(f"[TRACE] [_build_beef_for_outputs] building for {len(outputs_desc)} outputs")
            except Exception:
                pass
            for o in outputs_desc:
                ls_hex = o.get("lockingScript")
                try:
                    print(f"[TRACE] [_build_beef_for_outputs] out sat={o.get('satoshis')} ls_hex={ls_hex if isinstance(ls_hex, str) else (ls_hex.hex() if isinstance(ls_hex, (bytes, bytearray)) else ls_hex)}")
                except Exception:
                    pass
                ls_script = Script(ls_hex) if isinstance(ls_hex, str) else Script(ls_hex or b"\x51")
                to = TransactionOutput(ls_script, int(o.get("satoshis", 0)))
                tx.add_output(to)
            beef = tx.to_beef()
            try:
                print(f"[TRACE] [_build_beef_for_outputs] produced BEEF len={len(beef)}")
            except Exception:
                pass
            return beef
        except Exception:
            return b""

    def _format_outputs_result(self, outputs_desc: List[Dict[str, Any]], basket: str) -> List[Dict[str, Any]]:
        result_outputs: List[Dict[str, Any]] = []
        for idx, o in enumerate(outputs_desc):
            ls_hex = o.get("lockingScript")
            if not isinstance(ls_hex, str):
                ls_hex = (ls_hex or b"\x51").hex()
            result_outputs.append({
                "outputIndex": int(o.get("outputIndex", idx)),
                "satoshis": int(o.get("satoshis", 0)),
                "lockingScript": ls_hex,
                "spendable": True,
                "outputDescription": o.get("outputDescription", ""),
                "basket": o.get("basket", basket),
                "tags": o.get("tags") or [],
                "customInstructions": o.get("customInstructions"),
                "txid": "00" * 32,
                "createdAt": int(o.get("createdAt", 0)),
            })
        return result_outputs

    def _is_output_expired(self, out_desc: Dict[str, Any], now_epoch: int) -> bool:
        try:
            meta = out_desc.get("outputDescription")
            if not meta:
                return False
            import json
            d = json.loads(meta) if isinstance(meta, str) else meta
            keep = int(d.get("retentionSeconds", 0))
            if keep <= 0:
                return False
            created = int(out_desc.get("createdAt", 0))
            return created > 0 and (created + keep) < now_epoch
        except Exception:
            return False

    # ---- Shared helpers for encrypt/decrypt ----
    def _maybe_seek_permission(self, action_label: str, enc_args: Dict) -> None:
        seek_permission = enc_args.get("seekPermission") or enc_args.get("seek_permission")
        if seek_permission:
            self._check_permission(action_label)

    def _resolve_encryption_public_key(self, enc_args: Dict) -> PublicKey:
        protocol_id = enc_args.get("protocol_id")
        key_id = enc_args.get("key_id")
        counterparty = enc_args.get("counterparty")
        for_self = enc_args.get("forSelf", False)
        if protocol_id and key_id:
            protocol = SimpleNamespace(security_level=int(protocol_id.get("securityLevel", 0)), protocol=str(protocol_id.get("protocol", ""))) if isinstance(protocol_id, dict) else protocol_id
            cp = self._normalize_counterparty(counterparty)
            return self.key_deriver.derive_public_key(protocol, key_id, cp, for_self)
        # Fallbacks
        if isinstance(counterparty, PublicKey):
            return counterparty
        if isinstance(counterparty, str):
            return PublicKey(counterparty)
        return self.public_key

    def _perform_decrypt_with_args(self, enc_args: Dict, ciphertext: bytes) -> bytes:
        protocol_id = enc_args.get("protocol_id")
        key_id = enc_args.get("key_id")
        counterparty = enc_args.get("counterparty")
        if protocol_id and key_id:
            protocol = SimpleNamespace(security_level=int(protocol_id.get("securityLevel", 0)), protocol=str(protocol_id.get("protocol", ""))) if isinstance(protocol_id, dict) else protocol_id
            cp = self._normalize_counterparty(counterparty)
            derived_priv = self.key_deriver.derive_private_key(protocol, key_id, cp)
            try:
                plaintext = derived_priv.decrypt(ciphertext)
            except Exception as dec_err:
                plaintext = b""
            return plaintext
        # Fallback path
        return self.private_key.decrypt(ciphertext)
    def prove_certificate(self, args: Dict = None, originator: str = None) -> Dict:
        return {"keyringForVerifier": {}, "verifier": args.get("verifier", b"")}
    def relinquish_certificate(self, args: Dict = None, originator: str = None) -> Dict:
        # Remove matching certificate if present
        typ = args.get("type")
        serial = args.get("serialNumber")
        certifier = args.get("certifier")
        self._certificates = [c for c in self._certificates if 
            c.get("match") != (typ, serial, certifier)
        ]
        return {}
    def relinquish_output(self, args: Dict = None, originator: str = None) -> Dict:
        return {}
    def reveal_counterparty_key_linkage(
        self, args: RevealCounterpartyKeyLinkageArgs = None, originator: str = None
    ) -> Dict:
        """Reveal linkage information between our keys and a counterparty's key.
        
        This creates a cryptographic proof that can be verified by a third party.
        
        Args format:
            - counterparty: The counterparty's public key (required)
            - verifier: The verifier's public key (required)
            - seekPermission/seek_permission: Whether to ask for permission
            
        Returns:
            - prover: Prover's public key
            - counterparty: Counterparty's public key
            - verifier: Verifier's public key
            - revelation_time: Timestamp of revelation
            - encrypted_linkage: Encrypted linkage (list of ints)
            - encrypted_linkage_proof: Encrypted Schnorr proof (list of ints)
            
        Reference: go-sdk/wallet/proto_wallet_reveal.go RevealCounterpartyKeyLinkage
        """
        try:
            from bsv.primitives.schnorr import Schnorr
            from datetime import datetime, timezone
            
            seek_permission = args.get("seekPermission") or args.get("seek_permission")

            if seek_permission:
                self._check_permission("Reveal counterparty key linkage")

            # Validate inputs
            counterparty_arg = args.get("counterparty")
            verifier_arg = args.get("verifier")
            
            if counterparty_arg is None:
                return {"error": "reveal_counterparty_key_linkage: counterparty public key is required"}
            if verifier_arg is None:
                return {"error": "reveal_counterparty_key_linkage: verifier public key is required"}
            
            # Normalize to PublicKey
            counterparty_pubkey = self._to_public_key(counterparty_arg)
            verifier_pubkey = self._to_public_key(verifier_arg)
            
            # Get the identity key (root key)
            identity_key = self.key_deriver._root_private_key
            prover_public_key = self.key_deriver._root_public_key
            
            # Get the shared secret (linkage) as bytes
            counterparty_obj = Counterparty(CounterpartyType.OTHER, counterparty_pubkey)
            linkage_bytes = self.key_deriver.reveal_counterparty_secret(counterparty_obj)
            
            # Parse linkage as a Point for Schnorr proof
            linkage_point = PublicKey(linkage_bytes).point()
            
            # Generate Schnorr proof
            schnorr = Schnorr()
            proof = schnorr.generate_proof(identity_key, prover_public_key, counterparty_pubkey, linkage_point)
            
            # Serialize the proof components
            # Format: R compressed (33 bytes) || S' compressed (33 bytes) || z (32 bytes) = 98 bytes total
            r_bytes = self._encode_point(proof['R'])
            s_prime_bytes = self._encode_point(proof['SPrime'])
            z_bytes = proof['z'].to_bytes(32, 'big')
            proof_bytes = r_bytes + s_prime_bytes + z_bytes
            
            # Create revelation time
            revelation_time = datetime.now(timezone.utc).isoformat()
            
            # Encrypt the linkage for the verifier
            encrypt_result = self.encrypt({
                "plaintext": list(linkage_bytes),
                "protocolID": {"securityLevel": 2, "protocol": "counterparty linkage revelation"},
                "keyID": revelation_time,
                "counterparty": {"type": CounterpartyType.OTHER, "counterparty": verifier_pubkey}
            }, originator)
            
            if "error" in encrypt_result:
                return {"error": f"reveal_counterparty_key_linkage: failed to encrypt linkage: {encrypt_result['error']}"}
            
            # Encrypt the proof for the verifier
            encrypt_proof_result = self.encrypt({
                "plaintext": list(proof_bytes),
                "protocolID": {"securityLevel": 2, "protocol": "counterparty linkage revelation"},
                "keyID": revelation_time,
                "counterparty": {"type": CounterpartyType.OTHER, "counterparty": verifier_pubkey}
            }, originator)
            
            if "error" in encrypt_proof_result:
                return {"error": f"reveal_counterparty_key_linkage: failed to encrypt proof: {encrypt_proof_result['error']}"}
            
            return {
                "prover": prover_public_key.serialize(),
                "counterparty": counterparty_pubkey.serialize(),
                "verifier": verifier_pubkey.serialize(),
                "revelation_time": revelation_time,
                "encrypted_linkage": encrypt_result["ciphertext"],
                "encrypted_linkage_proof": encrypt_proof_result["ciphertext"]
            }
        except Exception as e:
            return {"error": f"reveal_counterparty_key_linkage: {e}"}

    def reveal_specific_key_linkage(
        self, args: RevealSpecificKeyLinkageArgs = None, originator: str = None
    ) -> Dict:
        """Reveal linkage information for a *specific* derived key.
        
        Args format:
            - counterparty: The counterparty's public key (required)
            - verifier: The verifier's public key (required)
            - protocol_id / protocolID: The protocol ID (required)
            - key_id / keyID: The key identifier (required)
            - seekPermission/seek_permission: Whether to ask for permission
            
        Returns:
            - prover: Prover's public key
            - counterparty: Counterparty's public key
            - verifier: Verifier's public key
            - protocol_id: Protocol ID
            - key_id: Key ID
            - encrypted_linkage: Encrypted linkage (list of ints)
            - encrypted_linkage_proof: Encrypted proof (list of ints)
            - proof_type: Proof type (0 = no proof for specific linkage)
            
        Reference: go-sdk/wallet/proto_wallet_reveal.go RevealSpecificKeyLinkage
        """
        try:
            seek_permission = args.get("seekPermission") or args.get("seek_permission")

            if seek_permission:
                self._check_permission("Reveal specific key linkage")

            # Validate inputs
            verifier_arg = args.get("verifier")
            if verifier_arg is None:
                return {"error": "reveal_specific_key_linkage: verifier public key is required"}
            
            # Check for forbidden snake_case keys
            forbidden_keys = {
                'protocol_id': 'protocolID',
                'key_id': 'keyID'
            }
            for snake_key, camel_key in forbidden_keys.items():
                if snake_key in args:
                    raise ValueError(f"Wallet API key '{snake_key}' is not supported. Use '{camel_key}' instead.")

            # Get protocol and key parameters (camelCase only)
            protocol_id = args.get("protocolID")
            key_id = args.get("keyID")
            counterparty_arg = args.get("counterparty")
            
            if protocol_id is None or key_id is None:
                return {"error": "reveal_specific_key_linkage: protocol_id and key_id are required"}
            if counterparty_arg is None:
                return {"error": "reveal_specific_key_linkage: counterparty is required"}
            
            # Normalize protocol
            protocol = self._normalize_protocol(protocol_id)
            
            # Normalize to PublicKey
            verifier_pubkey = self._to_public_key(verifier_arg)
            counterparty_pubkey = self._to_public_key(counterparty_arg)
            
            # Get the identity key (root key)
            prover_public_key = self.key_deriver._root_public_key
            
            # Get the specific secret (linkage)
            counterparty_obj = Counterparty(CounterpartyType.OTHER, counterparty_pubkey)
            linkage = self.key_deriver.reveal_specific_secret(
                counterparty_obj,
                Protocol(protocol.security_level, protocol.protocol),
                key_id
            )
            
            # For specific key linkage, we use proof type 0 (no proof)
            proof_bytes = bytes([0])
            
            # Create the special protocol ID for specific linkage revelation
            encrypt_protocol_name = f"specific linkage revelation {protocol.security_level} {protocol.protocol.strip().lower()}"
            
            # Encrypt the linkage for the verifier
            encrypt_result = self.encrypt({
                "plaintext": list(linkage),
                "protocolID": {"securityLevel": 2, "protocol": encrypt_protocol_name},
                "keyID": key_id,
                "counterparty": {"type": CounterpartyType.OTHER, "counterparty": verifier_pubkey}
            }, originator)
            
            if "error" in encrypt_result:
                return {"error": f"reveal_specific_key_linkage: failed to encrypt linkage: {encrypt_result['error']}"}
            
            # Encrypt the proof for the verifier
            encrypt_proof_result = self.encrypt({
                "plaintext": list(proof_bytes),
                "protocolID": {"securityLevel": 2, "protocol": encrypt_protocol_name},
                "keyID": key_id,
                "counterparty": {"type": CounterpartyType.OTHER, "counterparty": verifier_pubkey}
            }, originator)
            
            if "error" in encrypt_proof_result:
                return {"error": f"reveal_specific_key_linkage: failed to encrypt proof: {encrypt_proof_result['error']}"}
            
            return {
                "prover": prover_public_key.serialize(),
                "counterparty": counterparty_pubkey.serialize(),
                "verifier": verifier_pubkey.serialize(),
                "protocol_id": {"security_level": protocol.security_level, "protocol": protocol.protocol},
                "key_id": key_id,
                "encrypted_linkage": encrypt_result["ciphertext"],
                "encrypted_linkage_proof": encrypt_proof_result["ciphertext"],
                "proof_type": 0
            }
        except Exception as e:
            return {"error": f"reveal_specific_key_linkage: {e}"}

    def _extract_transaction_bytes(self, args: Dict) -> Optional[bytes]:
        """Extract transaction bytes from args."""
        if "tx" in args:
            return args["tx"]
        elif "signableTransaction" in args and "tx" in args["signableTransaction"]:
            return args["signableTransaction"]["tx"]
        return None

    def _parse_transaction(self, tx_bytes: bytes):
        """Parse transaction from bytes (BEEF or raw format)."""
        from bsv.transaction import Transaction
        from bsv.utils import Reader
        
        if tx_bytes[:4] == b'\x01\x00\xBE\xEF':  # BEEF magic
            return Transaction.from_beef(tx_bytes)
        else:
            return Transaction.from_reader(Reader(tx_bytes))

    def _get_or_generate_spends(self, tx, args: Dict, originator: str, spends: Dict) -> tuple[Dict, Optional[str]]:
        """Get spends from args or auto-generate them."""
        if spends:
            return spends, None
        
        if hasattr(self, "_prepare_spends"):
            return self._prepare_spends(tx, args, originator), None
        else:
            return {}, "sign_action: spends missing and _prepare_spends unavailable"

    def _apply_unlocking_scripts(self, tx, spends: Dict) -> Optional[str]:
        """Apply unlocking scripts from spends to transaction inputs."""
        from bsv.script.script import Script
        
        for idx, input in enumerate(tx.inputs):
            spend = spends.get(str(idx)) or spends.get(idx) or {}
            unlocking_script = spend.get("unlockingScript", b"")
            
            if unlocking_script and isinstance(unlocking_script, (bytes, bytearray)):
                if len(unlocking_script) < 2:
                    return f"sign_action: unlockingScript too short at input {idx}"
                input.unlocking_script = Script(unlocking_script)
            else:
                input.unlocking_script = unlocking_script
        return None

    def _build_sign_result(self, tx, spends: Dict) -> Dict:
        """Build result dictionary from signed transaction."""
        import binascii
        
        signed_tx_bytes = tx.serialize()
        txid = tx.txid() if hasattr(tx, "txid") else hashlib.sha256(signed_tx_bytes).hexdigest()
        
        result = {
            "tx": signed_tx_bytes,
            "tx_hex": binascii.hexlify(signed_tx_bytes).decode(),
            "txid": txid,
            "txid_hex": txid if isinstance(txid, str) else binascii.hexlify(txid).decode(),
            "spends": spends,
        }
        self._last_sign_action_result = result
        return result

    def sign_action(self, args: Dict = None, originator: str = None) -> Dict:
        """
        Sign the provided transaction using the provided spends (unlocking scripts).
        Returns the signed transaction and txid.
        """
        try:
            # Extract and parse transaction
            tx_bytes = self._extract_transaction_bytes(args)
            if not tx_bytes:
                return {"error": "sign_action: missing tx bytes"}
            
            tx = self._parse_transaction(tx_bytes)
            
            # Get or generate spends
            spends, error = self._get_or_generate_spends(tx, args, originator, args.get("spends") or {})
            if error:
                return {"error": error}
            
            # Apply unlocking scripts
            error = self._apply_unlocking_scripts(tx, spends)
            if error:
                return {"error": error}
            
            # Build and return result
            return self._build_sign_result(tx, spends)
            
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            return {"tx": b"\x00", "txid": "00" * 32, "error": f"sign_action: {e}", "traceback": tb}
    def wait_for_authentication(self, args: Dict = None, originator: str = None) -> Dict:
        return {"authenticated": True}

    def _determine_woc_network(self) -> str:
        """Determine WOC network (main/test) from private key."""
        if hasattr(self, 'private_key') and hasattr(self.private_key, 'network'):
            from bsv.constants import Network
            if self.private_key.network == Network.TESTNET:
                return "test"
        return "main"

    def _build_woc_headers(self, api_key: str) -> dict:
        """Build headers for WOC API request."""
        if not api_key:
            return {}
        return {
            "Authorization": api_key,
            "woc-api-key": api_key
        }

    def _convert_woc_utxo_to_output(self, utxo_data: dict, address: str) -> dict:
        """Convert WOC UTXO format to SDK output format."""
        # Derive locking script as fallback
        try:
            derived_ls = P2PKH().lock(address)
            derived_ls_hex = derived_ls.hex()
        except Exception:
            derived_ls_hex = ""
        
        return {
            "outputIndex": int(utxo_data.get("tx_pos", utxo_data.get("vout", 0))),
            "satoshis": int(utxo_data.get("value", 0)),
            "lockingScript": (utxo_data.get("script") or derived_ls_hex or ""),
            "spendable": True,
            "outputDescription": "WOC UTXO",
            "basket": address,
            "tags": [],
            "customInstructions": None,
            "txid": utxo_data.get("tx_hash", utxo_data.get("txid", "")),
        }

    def _get_utxos_from_woc(self, address: str, api_key: Optional[str] = None, timeout: int = 10) -> list:
        """
        Fetch UTXOs for the given address from Whatsonchain API and convert to SDK outputs format.
        """
        import requests
        
        # Resolve API key
        api_key = api_key or self._woc_api_key or os.environ.get("WOC_API_KEY") or ""
        
        # Build request
        network = self._determine_woc_network()
        url = f"https://api.whatsonchain.com/v1/bsv/{network}/address/{address}/unspent"
        headers = self._build_woc_headers(api_key)
        
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            
            # Convert each UTXO
            return [self._convert_woc_utxo_to_output(u, address) for u in data]
            
        except Exception as e:
            return [{"error": f"WOC UTXO fetch failed: {e}"}]

    def _resolve_woc_api_key(self, args: Dict) -> str:
        """Resolve WhatsOnChain API key similar to TS WhatsOnChainConfig.

        Precedence: args.apiKey -> args.woc.apiKey -> instance -> env -> empty string.
        """
        try:
            return (
                args.get("apiKey")
                or (args.get("woc") or {}).get("apiKey")
                or self._woc_api_key
                or os.environ.get("WOC_API_KEY")
                or ""
            )
        except Exception:
            return self._woc_api_key or os.environ.get("WOC_API_KEY") or ""

    # -----------------------------
    # Small helpers to reduce complexity
    # -----------------------------
    def _sum_outputs(self, outs: List[Dict]) -> int:
        return sum(int(o.get("satoshis", 0)) for o in outs)

    def _self_address(self) -> str:
        try:
            # Use the private key's network to generate the correct address
            network = self.private_key.network if hasattr(self, 'private_key') and hasattr(self.private_key, 'network') else None
            return self.public_key.address(network=network) if network else self.public_key.address()
        except Exception:
            return ""

    def _extract_protocol_params(self, args: Dict) -> tuple:
        """Extract protocol_id, key_id, and counterparty from args."""
        protocol_id = args.get("protocolID") or args.get("protocol_id")
        key_id = args.get("keyID") or args.get("key_id")
        counterparty = args.get("counterparty")
        
        # Also support nested pushdrop params
        if protocol_id is None or key_id is None:
            pd = args.get("pushdrop") or {}
            if protocol_id is None:
                protocol_id = pd.get("protocolID") or pd.get("protocol_id")
            if key_id is None:
                key_id = pd.get("keyID") or pd.get("key_id")
            if counterparty is None:
                counterparty = pd.get("counterparty")
        
        return protocol_id, key_id, counterparty

    def _derive_address_from_protocol(self, protocol_id, key_id, counterparty) -> Optional[str]:
        """Derive address from protocol, key_id, and counterparty."""
        try:
            if isinstance(protocol_id, dict):
                protocol = SimpleNamespace(
                    security_level=int(protocol_id.get("securityLevel", 0)),
                    protocol=str(protocol_id.get("protocol", ""))
                )
            else:
                protocol = protocol_id
            
            cp = self._normalize_counterparty(counterparty)
            derived_pub = self.key_deriver.derive_public_key(protocol, key_id, cp, for_self=False)
            
            network = self.private_key.network if hasattr(self, 'private_key') and hasattr(self.private_key, 'network') else None
            derived_addr = derived_pub.address(network=network) if network else derived_pub.address()
            
            if derived_addr and validate_address(derived_addr):
                return derived_addr
        except Exception as e:
            pass
        return None

    def _build_candidate_addresses(self, protocol_id, key_id, counterparty, args: Dict) -> List[str]:
        """Build list of candidate addresses to search for UTXOs."""
        candidate_addresses: List[str] = []
        
        # 1) Derived address candidate
        if protocol_id and key_id:
            derived_addr = self._derive_address_from_protocol(protocol_id, key_id, counterparty)
            if derived_addr:
                candidate_addresses.append(derived_addr)
        
        # 2) Master address fallback
        master_addr = self._self_address()
        if master_addr and validate_address(master_addr):
            candidate_addresses.append(master_addr)
        
        # 3) Optional explicit basket override
        explicit_basket = args.get("basket")
        if explicit_basket and isinstance(explicit_basket, str) and validate_address(explicit_basket):
            candidate_addresses.append(explicit_basket)
        
        return candidate_addresses

    def _search_utxos_in_addresses(self, candidate_addresses: List[str], originator: str) -> List[Dict[str, Any]]:
        """Search for UTXOs across candidate addresses."""
        use_woc = os.getenv("USE_WOC") != "0" and "USE_WOC" in os.environ
        
        for addr in candidate_addresses:
            lo = self.list_outputs({"basket": addr, "use_woc": use_woc}, originator) or {}
            outs = [u for u in lo.get("outputs", []) if isinstance(u, dict) and u.get("satoshis")]
            if outs:
                return outs
        return []

    def _list_self_utxos(self, args: Dict = None, originator: str = None) -> List[Dict[str, Any]]:
        """Prefer derived key UTXOs when protocol/key_id is provided; fallback to master if none found."""
        protocol_id, key_id, counterparty = self._extract_protocol_params(args)
        candidate_addresses = self._build_candidate_addresses(protocol_id, key_id, counterparty, args)
        return self._search_utxos_in_addresses(candidate_addresses, originator)

    def _sort_utxos_deterministic(self, utxos: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        def _sort_key(u: Dict[str, Any]):
            return (-int(u.get("satoshis", 0)), str(u.get("txid", "")), int(u.get("outputIndex", 0)))
        return sorted(utxos, key=_sort_key)

    def _estimate_fee(self, outs: List[Dict], unlocking_lens: List[int], fee_model: SatoshisPerKilobyte) -> int:
        try:
            from bsv.transaction import Transaction as _Tx
            from bsv.transaction_output import TransactionOutput as _TxOut
            from bsv.transaction_input import TransactionInput as _TxIn
            from bsv.script.script import Script as _Script
            from bsv.utils import encode_pushdata
            t = _Tx()
            for o in outs:
                ls = o.get("lockingScript", b"")
                ls_script = _Script(bytes.fromhex(ls)) if isinstance(ls, str) else _Script(ls)  # Scriptオブジェクトを直接作成
                t.add_output(_TxOut(ls_script, int(o.get("satoshis", 0))))
            for est_len in unlocking_lens:
                ti = _TxIn(source_txid="00" * 32, source_output_index=0)
                fake = encode_pushdata(b"x" * max(0, est_len - 1)) if est_len > 0 else b"\x00"
                ti.unlocking_script = _Script(fake)  # bytesからScriptオブジェクトを作成
                t.add_input(ti)
            return int(fee_model.compute_fee(t))
        except Exception:
            return 500

    def check_pubkey_hash(self, private_key, target_hash_hex):
        from bsv.hash import hash160

        """秘密鍵から生成される公開鍵ハッシュが目標ハッシュと一致するかチェック"""
        public_key = private_key.public_key()
        pubkey_bytes = bytes.fromhex(public_key.hex())
        derived_hash = hash160(pubkey_bytes).hex()

        return derived_hash == target_hash_hex
    
    def _extract_pubkey_hash_from_locking_script(self, locking_script_hex: str) -> Optional[str]:
        """P2PKHのlocking scriptから公開鍵ハッシュ(20 bytes hex)を抽出する。

        期待フォーマット: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
        例: 76a914{40-hex}88ac
        """
        try:
            if not isinstance(locking_script_hex, str):
                return None
            s = locking_script_hex.lower()
            # Fast-path for canonical pattern
            if s.startswith("76a914") and s.endswith("88ac") and len(s) >= 6 + 40 + 4:
                return s[6:6 + 40]
            # Fallback: parse bytes defensively
            b = bytes.fromhex(s)
            if len(b) >= 25 and b[0] == 0x76 and b[1] == 0xa9 and b[2] == 0x14 and b[-2] == 0x88 and b[-1] == 0xac:
                return b[3:23].hex()
            return None
        except Exception:
            return None

    def _pubkey_matches_hash(self, pub: PublicKey, target_hash_hex: str) -> bool:
        try:
            from bsv.hash import hash160
            pubkey_bytes = bytes.fromhex(pub.hex())
            return hash160(pubkey_bytes).hex() == target_hash_hex
        except Exception:
            return False
    
    def _check_prevout_pubkey(self, private_key: PrivateKey, prevout_script_bytes: bytes) -> None:
        """Debug-print whether hash160(pubkey) matches the prevout P2PKH hash."""
        try:
            utxo_hash_hex = self._extract_pubkey_hash_from_locking_script(prevout_script_bytes.hex())
            from bsv.hash import hash160 as _h160
            pubkey_hex = private_key.public_key().hex()
            pubkey_hash_hex = _h160(bytes.fromhex(pubkey_hex)).hex()
            print(f"[TRACE] [sign_check] utxo_hash={utxo_hash_hex} pubkey_hash={pubkey_hash_hex} match={utxo_hash_hex == pubkey_hash_hex}")
        except Exception as _dbg_e:
            print(f"[TRACE] [sign_check] prevout/pubkey hash check skipped: {_dbg_e}")

    def _read_push_from_script(self, buf: bytes, pos: int) -> tuple[bytes, int]:
        """Read a single push operation from script bytes."""
        if pos >= len(buf):
            raise ValueError("out of bounds")
        
        op = buf[pos]
        if op <= 75:
            ln = op
            pos += 1
        elif op == 76:  # OP_PUSHDATA1
            ln = buf[pos+1]
            pos += 2
        elif op == 77:  # OP_PUSHDATA2
            ln = int.from_bytes(buf[pos+1:pos+3], 'little')
            pos += 3
        elif op == 78:  # OP_PUSHDATA4
            ln = int.from_bytes(buf[pos+1:pos+5], 'little')
            pos += 5
        else:
            raise ValueError("unexpected push opcode")
        
        data = buf[pos:pos+ln]
        if len(data) != ln:
            raise ValueError("incomplete push data")
        return data, pos + ln

    def _validate_unlocking_script_components(self, sig: bytes, pub: bytes, private_key: PrivateKey) -> dict:
        """Validate components of unlocking script."""
        sighash_flag = sig[-1] if len(sig) > 0 else -1
        is_flag_ok = (sighash_flag == 0x41)
        is_pub_len_ok = (len(pub) == 33)
        pub_equals = (pub.hex() == private_key.public_key().hex())
        
        return {
            "sighash_flag": sighash_flag,
            "is_flag_ok": is_flag_ok,
            "is_pub_len_ok": is_pub_len_ok,
            "pub_equals": pub_equals
        }

    def _check_unlocking_sig(self, unlocking_script_bytes: bytes, private_key: PrivateKey) -> None:
        """Debug-print validation of unlocking script structure and SIGHASH flag.

        Expects two pushes: <DER+flag 0x41> <33-byte pubkey>.
        """
        try:
            # Read two pushes: signature and public key
            sig, pos = self._read_push_from_script(unlocking_script_bytes, 0)
            pub, pos = self._read_push_from_script(unlocking_script_bytes, pos)
            
            # Validate components
            validation = self._validate_unlocking_script_components(sig, pub, private_key)
            
            print(f"[TRACE] [sign_check] pushes_ok={validation['is_pub_len_ok']} "
                  f"sighash=0x{validation['sighash_flag']:02x} ok={validation['is_flag_ok']} "
                  f"pub_matches_priv={validation['pub_equals']}")
        except Exception as _dbg_e2:
            print(f"[TRACE] [sign_check] scriptSig structure check skipped: {_dbg_e2}")
        
    def _build_change_output_dict(self, basket_addr: str, satoshis: int) -> Dict[str, Any]:
        ls = P2PKH().lock(basket_addr)  # Script object
        return {
            "satoshis": int(satoshis),
            "lockingScript": ls.hex(),  # Script objectからHEX文字列を取得
            "outputDescription": "Change",
            "basket": basket_addr,
            "tags": [],
        }

    def _estimate_fee_with_change(self, outputs: List[Dict], existing_unlock_lens: List[int], sel_count: int, include_change: bool, fee_model) -> int:
        """Estimate fee optionally including a hypothetical change output."""
        base_outs = list(outputs)
        if include_change:
            addr = self._self_address()
            if addr:
                try:
                    print(f"[TRACE] [estimate_with_optional_change] addr: {addr}")
                    ch_ls = P2PKH().lock(addr)
                    base_outs = base_outs + [{"satoshis": 1, "lockingScript": ch_ls.hex()}]
                except Exception:
                    pass
        unlocking_lens = list(existing_unlock_lens) + [107] * sel_count
        return self._estimate_fee(base_outs, unlocking_lens, fee_model)

    def _select_single_utxo(self, utxos: List[Dict], need: int) -> Optional[Dict]:
        """Heuristic 1: single UTXO covering need with minimal excess."""
        for u in sorted(utxos, key=lambda x: int(x.get("satoshis", 0))):
            if int(u.get("satoshis", 0)) >= need:
                return u
        return None

    def _select_best_pair(self, utxos: List[Dict], need: int) -> Optional[tuple]:
        """Heuristic 2: try best pair (limit search space)."""
        pair = None
        best_sum = None
        limited = utxos[:50]
        
        for i in range(len(limited)):
            vi = int(limited[i].get("satoshis", 0))
            if vi >= need:
                if best_sum is None or vi < best_sum:
                    best_sum = vi
                    pair = (limited[i],)
                break
            for j in range(i + 1, len(limited)):
                vj = int(limited[j].get("satoshis", 0))
                s = vi + vj
                if s >= need and (best_sum is None or s < best_sum):
                    best_sum = s
                    pair = (limited[i], limited[j])
        
        return pair

    def _greedy_select_utxos(self, utxos: List[Dict], target: int, outputs: List[Dict], existing_unlock_lens: List[int], fee_model) -> List[Dict]:
        """Fallback to greedy largest-first selection."""
        selected: List[Dict] = []
        total_in = 0
        
        for u in utxos:
            selected.append(u)
            total_in += int(u.get("satoshis", 0))
            est_fee = self._estimate_fee_with_change(outputs, existing_unlock_lens, len(selected), True, fee_model)
            if total_in >= target + est_fee:
                break
        
        return selected

    def _refine_utxo_coverage(self, selected: List[Dict], utxos: List[Dict], target: int, outputs: List[Dict], existing_unlock_lens: List[int], fee_model) -> tuple[List[Dict], int]:
        """Ensure coverage with refined fee; add more greedily if needed."""
        remaining = [u for u in utxos if u not in selected]
        total_in = sum(int(u.get("satoshis", 0)) for u in selected)
        
        while True:
            est_fee = self._estimate_fee_with_change(outputs, existing_unlock_lens, len(selected), True, fee_model)
            need = target + est_fee
            if total_in >= need or not remaining:
                break
            u = remaining.pop(0)
            selected.append(u)
            total_in += int(u.get("satoshis", 0))
        
        return selected, total_in

    def _get_existing_outpoints(self, inputs_meta: List[Dict]) -> set:
        """Build a set of existing outpoints in inputs_meta."""
        existing_outpoints = set()
        
        for meta in inputs_meta:
            op = meta.get("outpoint") or meta.get("Outpoint")
            if op and isinstance(op, dict):
                txid_val = op.get("txid")
                txid_hex = self._convert_txid_to_hex(txid_val) if txid_val else None
                if txid_hex and txid_hex != "00" * 32:
                    key = (txid_hex, int(op.get("index", 0)))
                    existing_outpoints.add(key)
        
        return existing_outpoints

    def _extract_protocol_params_from_args(self, args: Dict) -> tuple:
        """Extract protocol parameters from args and pushdrop args."""
        pushdrop_args = args.get("pushdrop", {})
        protocol = pushdrop_args.get("protocolID") or pushdrop_args.get("protocol_id") or args.get("protocolID") or args.get("protocol_id")
        key_id = pushdrop_args.get("keyID") or pushdrop_args.get("key_id") or args.get("keyID") or args.get("key_id")
        counterparty = pushdrop_args.get("counterparty") or args.get("counterparty")
        return protocol, key_id, counterparty

    def _convert_protocol_to_obj(self, protocol) -> Any:
        """Convert protocol dict to SimpleNamespace object if needed."""
        if isinstance(protocol, dict):
            return SimpleNamespace(
                security_level=int(protocol.get("securityLevel", 0)),
                protocol=str(protocol.get("protocol", ""))
            )
        return protocol

    def _check_derived_key_match(self, protocol, key_id, counterparty, utxo_hash) -> bool:
        """Check if derived key matches UTXO hash."""
        if not (protocol and key_id is not None):
            return False
        
        protocol_obj = self._convert_protocol_to_obj(protocol)
        cp = self._normalize_counterparty(counterparty)
        derived_pub = self.key_deriver.derive_public_key(protocol_obj, key_id, cp, for_self=False)
        return self._pubkey_matches_hash(derived_pub, utxo_hash)

    def _determine_signing_key_for_utxo(self, u: Dict, args: Dict) -> tuple[Optional[Any], Optional[str], Optional[Any]]:
        """Determine which key (master vs derived) signs this UTXO."""
        protocol, key_id, counterparty = self._extract_protocol_params_from_args(args)
        
        ls_hex = u.get("lockingScript")
        utxo_hash = self._extract_pubkey_hash_from_locking_script(ls_hex) if isinstance(ls_hex, str) else None
        
        if not utxo_hash:
            return None, None, None
        
        # If master key matches, use it (return None values)
        if self.check_pubkey_hash(self.private_key, utxo_hash):
            return None, None, None
        
        # Try derived key
        try:
            if self._check_derived_key_match(protocol, key_id, counterparty, utxo_hash):
                return protocol, key_id, counterparty
        except Exception:
            pass
        
        return None, None, None

    def _build_funding_context(self, selected: List[Dict], inputs_meta: List[Dict], args: Dict, existing_outpoints: set) -> List[Dict[str, Any]]:
        """Build funding context from selected UTXOs."""
        funding_ctx: List[Dict[str, Any]] = []
        p2pkh_unlock_len = 107
        
        for u in selected:
            txid_hex = self._convert_txid_to_hex(u.get("txid"))
            outpoint_key = (txid_hex, int(u.get("outputIndex", 0)))
            
            if outpoint_key in existing_outpoints:
                continue
            
            use_protocol, use_key_id, use_counterparty = self._determine_signing_key_for_utxo(u, args)
            
            inputs_meta.append({
                "outpoint": {"txid": txid_hex, "index": int(u.get("outputIndex", 0))},
                "unlockingScriptLength": p2pkh_unlock_len,
                "inputDescription": u.get("outputDescription", "Funding UTXO"),
                "sequenceNumber": 0,
                "protocol": use_protocol,
                "key_id": use_key_id,
                "counterparty": use_counterparty,
            })
            existing_outpoints.add(outpoint_key)
            
            ls_val = u.get("lockingScript")
            ls_hex = ls_val.hex() if isinstance(ls_val, bytes) else (ls_val if isinstance(ls_val, str) else "")
            
            funding_ctx.append({
                "satoshis": int(u.get("satoshis", 0)),
                "lockingScript": ls_hex,
            })
        
        return funding_ctx

    def _select_funding_and_change(
        self,
        args: Dict,
        originator: str,
        outputs: List[Dict],
        inputs_meta: List[Dict],
        existing_unlock_lens: List[int],
        fee_model: SatoshisPerKilobyte,
    ) -> tuple[List[Dict[str, Any]], Optional[Dict]]:
        """Select funding inputs (deterministic order), append to inputs_meta and optionally produce a change output.

        Returns (funding_context_list, change_output_or_None).
        """
        target = self._sum_outputs(outputs)
        utxos = self._sort_utxos_deterministic(self._list_self_utxos(args, originator))
        
        # Initial need assumes we will add a change output (worst case for size)
        need0 = target + self._estimate_fee_with_change(outputs, existing_unlock_lens, 0, True, fee_model)
        
        # Try selection heuristics
        single = self._select_single_utxo(utxos, need0)
        pair = self._select_best_pair(utxos, need0)
        
        selected: List[Dict] = []
        if single is not None:
            selected = [single]
        elif pair is not None and len(pair) == 2:
            selected = [pair[0], pair[1]]
        
        # Fallback to greedy if no heuristic worked
        if not selected:
            selected = self._greedy_select_utxos(utxos, target, outputs, existing_unlock_lens, fee_model)
        
        # Ensure coverage with refined fee
        selected, total_in = self._refine_utxo_coverage(selected, utxos, target, outputs, existing_unlock_lens, fee_model)
        
        # Build funding context and change output
        funding_ctx: List[Dict[str, Any]] = []
        change_output: Optional[Dict] = None
        
        if selected:
            existing_outpoints = self._get_existing_outpoints(inputs_meta)
            funding_ctx = self._build_funding_context(selected, inputs_meta, args, existing_outpoints)
            
            p2pkh_unlock_len = 107
            unlocking_lens = list(existing_unlock_lens) + [p2pkh_unlock_len] * len(selected)
            est_fee = self._estimate_fee(outputs, unlocking_lens, fee_model)
            change_amt = total_in - target - est_fee
            
            if change_amt >= 0:
                addr = self._self_address()
                if addr:
                    change_output = self._build_change_output_dict(addr, int(change_amt))
        
        return funding_ctx, change_output
