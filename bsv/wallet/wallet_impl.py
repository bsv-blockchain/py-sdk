from typing import Any, Dict, Optional, List
from types import SimpleNamespace
import os
from .wallet_interface import WalletInterface
from .key_deriver import KeyDeriver, Protocol, Counterparty, CounterpartyType
from bsv.keys import PrivateKey, PublicKey
import hashlib
import hmac
import time
from bsv.script.type import P2PKH
from bsv.utils.address import validate_address
from bsv.fee_models.satoshis_per_kilobyte import SatoshisPerKilobyte
from bsv.chaintrackers import WhatsOnChainTracker

class WalletImpl(WalletInterface):
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
        if load_env and not WalletImpl._dotenv_loaded:
            try:
                from dotenv import load_dotenv  # type: ignore
                load_dotenv()
            except Exception:
                pass
            WalletImpl._dotenv_loaded = True
        # WhatsOnChain API key (TS parity: WhatsOnChainConfig.apiKey)
        self._woc_api_key: str = (woc_api_key or os.environ.get("WOC_API_KEY") or "")

    def _check_permission(self, action: str) -> None:
        if self.permission_callback:
            allowed = self.permission_callback(action)
        else:
            # Default for CLI: Ask the user for permission
            resp = input(f"[Wallet] Allow {action}? [y/N]: ")
            allowed = resp.strip().lower() in ("y", "yes")
        if os.getenv("BSV_DEBUG", "0") == "1":
            print(f"[DEBUG WalletImpl._check_permission] action={action!r} allowed={allowed}")
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
        if isinstance(counterparty, (bytes, str)):
            return Counterparty(CounterpartyType.OTHER, PublicKey(counterparty))
        if isinstance(counterparty, PublicKey):
            return Counterparty(CounterpartyType.OTHER, counterparty)
        # None or unknown -> self
        return Counterparty(CounterpartyType.SELF)

    def get_public_key(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
        try:
            seek_permission = args.get("seekPermission") or args.get("seek_permission")
            if os.getenv("BSV_DEBUG", "0") == "1":
                print(f"[DEBUG WalletImpl.get_public_key] originator=<redacted> seek_permission={seek_permission} args=<redacted>")  # Sensitive info omitted for security
            if seek_permission:
                self._check_permission("Get public key")
            if args.get("identityKey", False):
                return {"publicKey": self.public_key.hex()}
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
            else:
                protocol = protocol_id
            cp = self._normalize_counterparty(counterparty)
            derived_pub = self.key_deriver.derive_public_key(protocol, key_id, cp, for_self)
            return {"publicKey": derived_pub.hex()}
        except Exception as e:
            return {"error": f"get_public_key: {e}"}

    def encrypt(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
        try:
            encryption_args = args.get("encryption_args", {})
            if os.getenv("BSV_DEBUG", "0") == "1":
                print(f"[DEBUG WalletImpl.encrypt] enc_args keys={list(encryption_args.keys())}")  # Do not log originator or sensitive argument values
            self._maybe_seek_permission("Encrypt", encryption_args)
            plaintext = args.get("plaintext")
            if plaintext is None:
                return {"error": "encrypt: plaintext is required"}
            pubkey = self._resolve_encryption_public_key(encryption_args)
            ciphertext = pubkey.encrypt(plaintext)
            return {"ciphertext": ciphertext}
        except Exception as e:
            return {"error": f"encrypt: {e}"}

    def decrypt(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
        try:
            encryption_args = args.get("encryption_args", {})
            if os.getenv("BSV_DEBUG", "0") == "1":
                print(f"[DEBUG WalletImpl.decrypt] enc_args keys={list(encryption_args.keys())}")  # Do not log originator or sensitive argument values
            self._maybe_seek_permission("Decrypt", encryption_args)
            ciphertext = args.get("ciphertext")
            if ciphertext is None:
                return {"error": "decrypt: ciphertext is required"}
            plaintext = self._perform_decrypt_with_args(encryption_args, ciphertext)
            return {"plaintext": plaintext}
        except Exception as e:
            return {"error": f"decrypt: {e}"}

    def create_signature(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
        try:
            # BRC-100 compliant flat structure (Python snake_case)
            protocol_id = args.get("protocol_id")
            key_id = args.get("key_id")
            counterparty = args.get("counterparty")
            
            if os.getenv("BSV_DEBUG", "0") == "1":
                print(f"[DEBUG WalletImpl.create_signature] protocol_id={protocol_id}, key_id={key_id}")
            
            if protocol_id is None or key_id is None:
                return {"error": "create_signature: protocol_id and key_id are required"}
            
            # Normalize protocol_id (supports both camelCase and snake_case)
            protocol = self._normalize_protocol(protocol_id)
            
            cp = self._normalize_counterparty(counterparty)
            priv = self.key_deriver.derive_private_key(protocol, key_id, cp)
            
            # Get data or hash to sign
            data = args.get("data", b"")
            hash_to_sign = args.get("hash_to_directly_sign")
            
            if hash_to_sign:
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

    def _debug_log_verify_params(self, protocol_id, key_id, for_self, cp, pub):
        """Log verification parameters if debug is enabled."""
        if os.getenv("BSV_DEBUG", "0") == "1":
            try:
                proto_dbg = protocol_id if not isinstance(protocol_id, dict) else protocol_id.get('protocol')
                print(f"[DEBUG WalletImpl.verify_signature] protocol={proto_dbg} key_id={key_id} for_self={for_self}")
                cp_pub_dbg = cp.to_public_key(self.public_key)
                print(f"[DEBUG WalletImpl.verify_signature] cp.type={cp.type} cp.pub={cp_pub_dbg.hex()} derived.pub={pub.hex()}")
            except Exception:
                pass

    def _compute_hash_to_verify(self, args: Dict) -> tuple[bytes, bytes]:
        """Compute hash to verify and return (to_verify, data)."""
        data = args.get("data", b"")
        hash_to_verify = args.get("hash_to_directly_verify")
        
        if hash_to_verify:
            return hash_to_verify, data
        else:
            return hashlib.sha256(data).digest(), data

    def _debug_log_verification_data(self, data: bytes, to_verify: bytes, signature: bytes, pub):
        """Log verification data if debug is enabled."""
        if os.getenv("BSV_DEBUG", "0") == "1":
            try:
                print(f"[DEBUG WalletImpl.verify_signature] data_len={len(data)} sha256={to_verify.hex()[:32]}.. sig_len={len(signature)}")
                print(f"[DEBUG WalletImpl.verify_signature] pub.hex={pub.hex()}")
            except Exception:
                pass

    def _log_verification_details(self, originator: str, protocol_id, key_id, counterparty, pub, data: bytes, to_verify: bytes, signature: bytes):
        """Log detailed verification information."""
        print("[WALLET VERIFY] === SIGNATURE VERIFICATION START ===")
        print(f"[WALLET VERIFY] originator: {originator}")
        if isinstance(protocol_id, dict):
            print(f"[WALLET VERIFY] protocol: {protocol_id.get('protocol', 'NONE')}")
        print(f"[WALLET VERIFY] key_id: {key_id[:50] if key_id else 'NONE'}...")
        if isinstance(counterparty, dict):
            cp_obj = counterparty.get('counterparty')
            if hasattr(cp_obj, 'hex'):
                print(f"[WALLET VERIFY] counterparty.hex: {cp_obj.hex()}")
        
        print(f"[WALLET VERIFY] derived_public_key: {pub.hex()}")
        print(f"[WALLET VERIFY] data_to_verify_length: {len(data)}")
        print(f"[WALLET VERIFY] data_digest (SHA-256): {to_verify.hex()}")
        print(f"[WALLET VERIFY] signature_bytes: {signature.hex()}")
        print(f"[WALLET VERIFY] signature_length: {len(signature)}")

    def _log_verification_result(self, valid: bool, signature: bytes):
        """Log verification result and debug info."""
        print("[WALLET VERIFY] === CALLING pub.verify() ===")
        print(f"[WALLET VERIFY] === ECDSA RESULT: {valid} ===")
        
        if valid:
            print("[WALLET VERIFY] ✅ SIGNATURE VERIFICATION SUCCESS!")
        else:
            print("[WALLET VERIFY] ❌ SIGNATURE VERIFICATION FAILED!")
            try:
                print("[WALLET VERIFY] Signature DER format check...")
                print(f"[WALLET VERIFY] Signature first byte: 0x{signature[0]:02x}")
                print("[WALLET VERIFY] Expected DER start: 0x30")
            except Exception as e:
                print(f"[WALLET VERIFY] Signature format check error: {e}")

    def verify_signature(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
        try:
            # Extract and validate parameters
            protocol_id = args.get("protocol_id")
            key_id = args.get("key_id")
            counterparty = args.get("counterparty")
            for_self = args.get("for_self", False)
            
            if protocol_id is None or key_id is None:
                return {"error": "verify_signature: protocol_id and key_id are required"}
            
            # Normalize protocol and derive public key
            protocol = self._normalize_protocol(protocol_id)
            cp = self._normalize_counterparty(counterparty)
            pub = self.key_deriver.derive_public_key(protocol, key_id, cp, for_self)
            
            # Debug logging
            self._debug_log_verify_params(protocol_id, key_id, for_self, cp, pub)
            
            # Get data and signature
            signature = args.get("signature")
            if signature is None:
                return {"error": "verify_signature: signature is required"}
            
            to_verify, data = self._compute_hash_to_verify(args)
            
            # Debug log verification data
            self._debug_log_verification_data(data, to_verify, signature, pub)
            
            # Log detailed verification info
            self._log_verification_details(originator, protocol_id, key_id, counterparty, pub, data, to_verify, signature)
            
            # Perform verification
            valid = pub.verify(signature, to_verify, hasher=lambda m: m)
            
            # Log result
            self._log_verification_result(valid, signature)
            
            if os.getenv("BSV_DEBUG", "0") == "1":
                print(f"[DEBUG WalletImpl.verify_signature] valid={valid}")
            
            return {"valid": valid}
        except Exception as e:
            return {"error": f"verify_signature: {e}"}

    def create_hmac(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
        try:
            encryption_args = args.get("encryption_args", {})
            protocol_id = encryption_args.get("protocol_id")
            key_id = encryption_args.get("key_id")
            counterparty = encryption_args.get("counterparty")
            if os.getenv("BSV_DEBUG", "0") == "1":
                print(f"[DEBUG WalletImpl.create_hmac] enc_args={encryption_args}")
            if protocol_id is None or key_id is None:
                return {"error": "create_hmac: protocol_id and key_id are required"}
            if isinstance(protocol_id, dict):
                protocol = SimpleNamespace(security_level=int(protocol_id.get("securityLevel", 0)), protocol=str(protocol_id.get("protocol", "")))
            else:
                protocol = protocol_id
            cp = self._normalize_counterparty(counterparty)
            shared_secret = self.key_deriver.derive_symmetric_key(protocol, key_id, cp)
            data = args.get("data", b"")
            hmac_value = hmac.new(shared_secret, data, hashlib.sha256).digest()
            return {"hmac": hmac_value}
        except Exception as e:
            return {"error": f"create_hmac: {e}"}

    def _extract_hmac_params(self, args: Dict) -> tuple:
        """Extract HMAC verification parameters from args."""
        encryption_args = args.get("encryption_args", {})
        protocol_id = encryption_args.get("protocol_id")
        key_id = encryption_args.get("key_id")
        counterparty = encryption_args.get("counterparty")
        data = args.get("data", b"")
        hmac_value = args.get("hmac")
        return encryption_args, protocol_id, key_id, counterparty, data, hmac_value

    def _debug_log_hmac_params(self, encryption_args: dict, cp):
        """Log HMAC parameters if debug is enabled."""
        if os.getenv("BSV_DEBUG", "0") == "1":
            print(f"[DEBUG WalletImpl.verify_hmac] enc_args={encryption_args}")
            try:
                cp_pub_dbg = cp.to_public_key(self.public_key)
                print(f"[DEBUG WalletImpl.verify_hmac] cp.type={cp.type} cp.pub={cp_pub_dbg.hex()}")
            except Exception as dbg_e:
                print(f"[DEBUG WalletImpl.verify_hmac] cp normalization error: {dbg_e}")

    def verify_hmac(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
        try:
            # Extract parameters
            encryption_args, protocol_id, key_id, counterparty, data, hmac_value = self._extract_hmac_params(args)
            
            # Validate required fields
            if protocol_id is None or key_id is None:
                return {"error": "verify_hmac: protocol_id and key_id are required"}
            if hmac_value is None:
                return {"error": "verify_hmac: hmac is required"}
            
            # Normalize protocol and counterparty
            protocol = self._normalize_protocol(protocol_id) if isinstance(protocol_id, dict) else protocol_id
            cp = self._normalize_counterparty(counterparty)
            
            # Debug logging
            self._debug_log_hmac_params(encryption_args, cp)
            
            # Derive shared secret and verify HMAC
            shared_secret = self.key_deriver.derive_symmetric_key(protocol, key_id, cp)
            expected = hmac.new(shared_secret, data, hashlib.sha256).digest()
            valid = hmac.compare_digest(expected, hmac_value)
            
            return {"valid": valid}
        except Exception as e:
            return {"error": f"verify_hmac: {e}"}

    def abort_action(self, *a, **k):
        # NOTE: This mock wallet does not manage long-running actions, so there is
        # nothing to abort. The method is intentionally left empty to satisfy the
        # interface and to document that abort semantics are a no-op in tests.
        pass
    def acquire_certificate(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
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
    def create_action(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
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
        # --- PushDrop extension: fields/signature/lock-position/basket/retention ---
        pushdrop_args = args.get("pushdrop")
        print("[TRACE] [create_action] pushdrop_args:", pushdrop_args)
        if pushdrop_args:
            print("[TRACE] [create_action] found pushdrop_args")
            from bsv.transaction.pushdrop import build_lock_before_pushdrop
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
            # Build PushDrop locking script (Go/TS parity)
            print(f"[TRACE] [create_action] found pubkey:{pubkey}")
            # Always build the locking script, letting build_lock_before_pushdrop handle pubkey lookup if needed
            if pubkey:
                locking_script = build_lock_before_pushdrop(fields, pubkey, include_signature=include_signature, signature=signature, lock_position=lock_position)
            else:
                # If pubkey is None, try to fetch from wallet (Go/TS parity)
                from bsv.transaction.pushdrop import PushDrop
                pd = PushDrop(self, originator)
                locking_script = pd.lock(
                    ctx,
                    fields,
                    protocol_id,
                    key_id,
                    counterparty,
                    for_self=True,
                    include_signature=include_signature,
                    lock_position=lock_position,
                )
            # Calculate appropriate satoshis for PushDrop output (input - fee)
            # Default to 1 satoshi if no specific amount is provided
            pushdrop_satoshis = pushdrop_args.get("satoshis")
            if pushdrop_satoshis is None:
                # Will be calculated after funding selection
                pushdrop_satoshis = 1  # Placeholder, will be updated later
            output = {"lockingScript": locking_script, "satoshis": pushdrop_satoshis}
            if basket:
                output["basket"] = basket
            if retention:
                output["outputDescription"] = {"retentionSeconds": retention}

            # Avoid duplicating pushdrop output: only append if caller did not provide outputs
            if not outputs:
                outputs.append(output)

        print("[TRACE] [create_action] after pushdrop outputs:", outputs)
        print("[TRACE] [create_action] after pushdrop inputs_meta:", inputs_meta)
        # Fee model (default 500 sat/kB unless overridden)
        fee_rate = int(args.get("feeRate") or 500)
        fee_model = SatoshisPerKilobyte(fee_rate)
        # Compute current target output sum (for potential fee calculation)
        _ = self._sum_outputs(outputs)
        # Determine existing inputs' estimated unlocking lengths if provided
        existing_unlock_lens: List[int] = []
        for _ in inputs_meta:
            est = int(_.get("unlockingScriptLength", 73))
            existing_unlock_lens.append(est)
        # Auto-fund if needed (extracts funding inputs and optional change)
        funding_ctx: List[Dict[str, Any]]
        change_output: Optional[Dict]
        # Pass ca_args (args) to _select_funding_and_change for correct propagation
        funding_ctx, change_output = self._select_funding_and_change(
            ctx,
            args,  # <-- pass the original args/ca_args here
            originator,
            outputs,
            inputs_meta,
            existing_unlock_lens,
            fee_model,
        )
        
        # Update inputs_meta with the funding context returned from _select_funding_and_change
        # This ensures that the selected UTXOs are properly added to inputs_meta
        if funding_ctx:
            print(f"[TRACE] [create_action] funding_ctx returned: {len(funding_ctx)} UTXOs")
            # The _select_funding_and_change method already updated inputs_meta directly
            # Just verify that inputs_meta now contains the funding UTXOs
            print(f"[TRACE] [create_action] inputs_meta after funding: {len(inputs_meta)} inputs")
        else:
            print("[TRACE] [create_action] No funding UTXOs selected")
            
        # Only trace fee estimation for visibility; do not override KV output amount.
        if pushdrop_args and funding_ctx:
            _ = sum(int(c.get("satoshis", 0)) for c in funding_ctx)  # Calculate for validation
            if fee_rate and fee_rate > 0:
                estimated_size = len(inputs_meta) * 148 + len(outputs) * 34 + 10
                est_fee = int(estimated_size * fee_rate / 1000)
                print(f"[TRACE] [create_action] Using feeRate {fee_rate} sat/kB, estimated size: {estimated_size} bytes, calculated fee: {est_fee} satoshis")
            else:
                unlocking_lens = [107] * len(inputs_meta)
                est_fee = self._estimate_fee(outputs, unlocking_lens, fee_model)
                print(f"[TRACE] [create_action] Using fee_model, calculated fee: {est_fee} satoshis")
        
        print("[TRACE] [create_action] after _select_funding_and_change outputs:", outputs)
        print("[TRACE] [create_action] after _select_funding_and_change inputs_meta:", inputs_meta)
        # If change output is generated, add to outputs
        if change_output:
            # Calculate the total input sum
            input_sum = 0
            for meta in inputs_meta:
                outpoint = meta.get("outpoint") or meta.get("Outpoint")
                if outpoint and isinstance(outpoint, dict):
                    for o in outputs:
                        if (
                            (isinstance(o.get("txid"), str) and bytes.fromhex(o.get("txid")) == outpoint.get("txid")) or
                            (isinstance(o.get("txid"), (bytes, bytearray)) and o.get("txid") == outpoint.get("txid"))
                        ) and int(o.get("outputIndex", 0)) == int(outpoint.get("index", 0)):
                            input_sum += int(o.get("satoshis", 0))
                            break
            if input_sum == 0:
                input_sum = None
            # Find the key-value output (the main output, not change)
            keyvalue_satoshis = 0
            for o in outputs:
                desc = o.get("outputDescription", "")
                if (isinstance(desc, str) and "kv.set" in desc) or (isinstance(desc, dict) and desc.get("type") == "kv.set"):
                    keyvalue_satoshis = int(o.get("satoshis", 0))
                    break
            # Calculate the fee based on feeRate if specified, otherwise use fee_model
            fee = 0
            if fee_rate and fee_rate > 0:
                # Use the same fee calculation as above for consistency
                estimated_size = len(inputs_meta) * 148 + len(outputs) * 34 + 10
                fee = int(estimated_size * fee_rate / 1000)
                print(f"[TRACE] [create_action] Change calculation using feeRate {fee_rate} sat/kB, fee: {fee} satoshis")
            else:
                # Use fee_model as fallback
                try:
                    fee = fee_model.estimate(len(outputs), len(inputs_meta))
                    print(f"[TRACE] [create_action] Change calculation using fee_model, fee: {fee} satoshis")
                except Exception:
                    pass
            
            # Calculate the change amount
            if input_sum is not None:
                change_sats = input_sum - keyvalue_satoshis - fee
                print(f"[TRACE] [create_action] Change calculation: input_sum={input_sum}, keyvalue_satoshis={keyvalue_satoshis}, fee={fee}, change_sats={change_sats}")
            else:
                change_sats = int(change_output.get("satoshis", 0))
            
            if change_sats > 0:                # BSV does not have dust limits, so add any positive change output
                outputs.append(change_output)
                print(f"[TRACE] [create_action] Added change output: {change_sats} satoshis")
        total_out = self._sum_outputs(outputs)
        # lockingScriptを必ずhex stringに統一
        for o in outputs:
            ls = o.get("lockingScript")
            if isinstance(ls, bytes):
                o["lockingScript"] = ls.hex()
        print("[TRACE] [create_action] before _build_action_dict inputs_meta:", inputs_meta)
        action = self._build_action_dict(args, total_out, description, labels, inputs_meta, outputs)
        # Ensure txid is 32 bytes for wallet wire serialization (store bytes not hex)
        try:
            if isinstance(action.get("txid"), str) and len(action.get("txid")) == 64:
                action["txid"] = bytes.fromhex(action["txid"])  # 32 bytes
        except Exception:
            pass
        self._actions.append(action)
        # Build signable tx and pre-sign funding inputs (P2PKH)
        funding_start_index = len(inputs_meta) - len(funding_ctx) if funding_ctx else None
        print("[TRACE] [create_action] before _build_signable_transaction inputs_meta:", inputs_meta)
        signable_tx = self._build_signable_transaction(
            outputs,
            inputs_meta,
            prefill_funding=True,
            funding_start_index=funding_start_index,
            funding_context=funding_ctx,
        )
        # For test/E2E vector: return lockingScript as hex if not already
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

    def _build_signable_transaction(self, outputs, inputs_meta, prefill_funding: bool = False, funding_start_index: Optional[int] = None, funding_context: Optional[List[Dict[str, Any]]] = None):
        """
        Always return a Transaction object, even if outputs is empty (for remove flows).
        Ensure TransactionInput receives source_txid as hex string (str), not bytes.
        Ensure TransactionOutput receives int(satoshis) and Script in correct order.
        """
        # --- bytes→hex string変換を必ず最初に一括で実施 ---
        for output in outputs:
            ls = output.get("lockingScript")
            if isinstance(ls, bytes):
                output["lockingScript"] = ls.hex()
        print("[TRACE] [_build_signable_transaction] inputs_meta at entry:", inputs_meta)
        print("[TRACE] [_build_signable_transaction] outputs at entry:", outputs)
        try:
            from bsv.transaction import Transaction
            from bsv.transaction_output import TransactionOutput
            from bsv.transaction_input import TransactionInput
            from bsv.script.script import Script
            import logging
            logging.basicConfig(level=logging.DEBUG)
            logger = logging.getLogger(__name__)
            # Debug: Log outputs and inputs_meta
            logger.debug(f"Building transaction with outputs: {outputs}")
            logger.debug(f"Building transaction with inputs_meta: {inputs_meta}")
            t = Transaction()
            # After all outputs are constructed, ensure lockingScript is always hex string
            for output in outputs:
                ls = output.get("lockingScript")
                if isinstance(ls, bytes):
                    output["lockingScript"] = ls.hex()
            for o in outputs:
                ls = o.get("lockingScript", b"")
                if isinstance(ls, bytes):
                    ls_hex = ls.hex()
                else:
                    ls_hex = ls
                satoshis = o.get("satoshis", 0)
                logger.debug(f"Output satoshis type: {type(satoshis)}, value: {satoshis}")
                logger.debug(f"Output lockingScript type: {type(ls_hex)}, value: {ls_hex}")
                # Defensive: ensure satoshis is int, ls_hex is hex string
                assert isinstance(satoshis, int), f"satoshis must be int, got {type(satoshis)}"
                assert isinstance(ls_hex, str), f"lockingScript must be hex string, got {type(ls_hex)}"
                s = Script(ls_hex)  # Script constructor accepts hex string directly
                to = TransactionOutput(s, int(satoshis))
                t.add_output(to)
            # Map to track which inputs are funding (P2PKH) to optionally pre-sign
            funding_indices: List[int] = []
            for i, meta in enumerate(inputs_meta):
                print(f"[TRACE] [_build_signable_transaction] input_meta[{i}]:", meta)
                outpoint = meta.get("outpoint") or meta.get("Outpoint")
                if outpoint and isinstance(outpoint, dict):
                    txid = outpoint.get("txid")
                    index = outpoint.get("index", 0)
                    # Always pass txid as hex string
                    if isinstance(txid, bytes):
                        txid_str = txid.hex()
                    elif isinstance(txid, str):
                        txid_str = txid
                    else:
                        txid_str = "00" * 32
                    ti = TransactionInput(source_txid=txid_str, source_output_index=int(index))
                    t.add_input(ti)  # Add input to transaction
                    # Heuristic: treat inputs lacking custom descriptors as funding (P2PKH)
                    funding_indices.append(len(t.inputs) - 1)
            print("[TRACE] [_build_signable_transaction] funding_indices:", funding_indices)
            # Optionally prefill funding inputs with P2PKH signatures
            if prefill_funding and funding_indices:
                try:
                    # If caller provided funding context, use it to set precise prevout data
                    if funding_start_index is not None and funding_context:
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
                    else:
                        # Fallback: set generic P2PKH lock with our address
                        addr = self.public_key.address()
                        ls_fund = P2PKH().lock(addr)  # Script object
                        for idx in funding_indices:
                            tin = t.inputs[idx]
                            tin.satoshis = 0
                            tin.locking_script = ls_fund  # Script objectを直接使用
                    # Now produce signatures for those inputs
                    for idx in funding_indices:
                        meta = inputs_meta[idx] if idx < len(inputs_meta) else {}
                        protocol = meta.get("protocol")
                        key_id = meta.get("key_id")
                        counterparty = meta.get("counterparty")
                        if protocol is not None and key_id is not None:
                            # If protocol is a dict, convert to Protocol object
                            if isinstance(protocol, dict):
                                protocol_obj = SimpleNamespace(security_level=int(protocol.get("securityLevel", 0)), protocol=str(protocol.get("protocol", "")))
                            else:
                                protocol_obj = protocol
                            cp = self._normalize_counterparty(counterparty)
                            priv = self.key_deriver.derive_private_key(protocol_obj, key_id, cp)
                        else:
                            priv = self.private_key
                        print(f"[TRACE] [_build_signable_transaction] priv address: {priv.address()}")
                        # Verify pubkey-hash matches prevout's P2PKH before signing (debug aid)
                        try:
                            prevout_script_bytes = t.inputs[idx].locking_script.serialize()
                            self._check_prevout_pubkey(priv, prevout_script_bytes)
                        except Exception as _dbg_e:
                            print(f"[TRACE] [sign_check] prevout/pubkey hash check skipped: {_dbg_e}")
                        
                        unlock_tpl = P2PKH().unlock(priv)
                        t.inputs[idx].unlocking_script = unlock_tpl.sign(t, idx)
                        # Validate unlocking script structure: <sig+flag(0x41)> <33-byte pubkey>
                        try:
                            us_b = t.inputs[idx].unlocking_script.serialize()
                            self._check_unlocking_sig(us_b, priv)
                        except Exception as _dbg_e2:
                            print(f"[TRACE] [sign_check] scriptSig structure check skipped: {_dbg_e2}")
                except Exception:
                    pass
            return t  # Always return Transaction object
        except Exception as e:
            print(f"[ERROR] Exception in _build_signable_transaction: {e}")
            raise
            from bsv.transaction import Transaction
            return Transaction()  # Return empty Transaction on error

    def discover_by_attributes(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
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
    def discover_by_identity_key(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
        # naive: no identity index, return empty
        return {"totalCertificates": 0, "certificates": []}
    def get_header_for_height(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
        # minimal: return empty header bytes
        return {"header": b""}
    def get_height(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
        return {"height": 0}
    def get_network(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
        return {"network": "mocknet"}
    def get_version(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
        return {"version": "0.0.0"}
    def internalize_action(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
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
        disable_arc = os.getenv("DISABLE_ARC", "0") == "1" or args.get("disable_arc")
        use_arc = not disable_arc  # ARC is enabled by default
        use_woc = os.getenv("USE_WOC", "0") == "1" or args.get("use_woc")
        use_mapi = args.get("use_mapi")
        use_custom_node = args.get("use_custom_node")
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
    def is_authenticated(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
        return {"authenticated": True}
    def list_actions(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
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
    def list_certificates(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
        # Minimal: return stored certificates
        return {"totalCertificates": len(self._certificates), "certificates": self._certificates}
    def list_outputs(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
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
        
        if os.getenv("REGISTRY_DEBUG") == "1":
            print("[DEBUG list_outputs] basket", basket, "outputs_desc", outputs_desc)
        
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
            if os.getenv("BSV_DEBUG", "0") == "1":
                print(f"[DEBUG WalletImpl.decrypt] derived_priv int={derived_priv.int():x} ciphertext_len={len(ciphertext)}")
            try:
                plaintext = derived_priv.decrypt(ciphertext)
                if os.getenv("BSV_DEBUG", "0") == "1":
                    print(f"[DEBUG WalletImpl.decrypt] decrypt success, plaintext={plaintext.hex()}")
            except Exception as dec_err:
                if os.getenv("BSV_DEBUG", "0") == "1":
                    print(f"[DEBUG WalletImpl.decrypt] decrypt failed with derived key: {dec_err}")
                plaintext = b""
            return plaintext
        # Fallback path
        return self.private_key.decrypt(ciphertext)
    def prove_certificate(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
        return {"keyringForVerifier": {}, "verifier": args.get("verifier", b"")}
    def relinquish_certificate(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
        # Remove matching certificate if present
        typ = args.get("type")
        serial = args.get("serialNumber")
        certifier = args.get("certifier")
        self._certificates = [c for c in self._certificates if 
            c.get("match") != (typ, serial, certifier)
        ]
        return {}
    def relinquish_output(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
        return {}
    def reveal_counterparty_key_linkage(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
        """Reveal linkage information between our keys and a counterparty's key.

        The mock implementation does **not** actually compute any linkage bytes. The goal is
        simply to provide enough behaviour for the unit-tests:

        1. If `seekPermission` is truthy we call the standard `_check_permission` helper which
           may raise a `PermissionError` that we surface back to the caller as an `error` dict.
        2. On success we just return an empty dict – the serializer for linkage results does
           not expect any payload (it always returns an empty `bytes` string).
        """
        try:
            seek_permission = args.get("seekPermission") or args.get("seek_permission")
            if os.getenv("BSV_DEBUG", "0") == "1":
                print(f"[DEBUG WalletImpl.reveal_counterparty_key_linkage] originator={originator} seek_permission={seek_permission} args={args}")

            if seek_permission:
                # Ask the user (or callback) for permission
                self._check_permission("Reveal counterparty key linkage")

            # Real implementation would compute and return linkage data here. For test purposes
            # we return an empty dict which the serializer converts to an empty payload.
            return {}
        except Exception as e:
            return {"error": f"reveal_counterparty_key_linkage: {e}"}

    def reveal_specific_key_linkage(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
        """Reveal linkage information for a *specific* derived key.

        Mimics `reveal_counterparty_key_linkage` with the addition of protocol/key parameters
        but, for this mock implementation, does not actually use them.
        """
        try:
            seek_permission = args.get("seekPermission") or args.get("seek_permission")
            if os.getenv("BSV_DEBUG", "0") == "1":
                print(f"[DEBUG WalletImpl.reveal_specific_key_linkage] originator={originator} seek_permission={seek_permission} args={args}")

            if seek_permission:
                self._check_permission("Reveal specific key linkage")

            return {}
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

    def _get_or_generate_spends(self, ctx: Any, tx, args: Dict, originator: str, spends: Dict) -> tuple[Dict, Optional[str]]:
        """Get spends from args or auto-generate them."""
        if spends:
            return spends, None
        
        if hasattr(self, "_prepare_spends"):
            return self._prepare_spends(ctx, tx, args, originator), None
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

    def sign_action(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
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
            spends, error = self._get_or_generate_spends(ctx, tx, args, originator, args.get("spends") or {})
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
    def wait_for_authentication(self, ctx: Any = None, args: Dict = None, originator: str = None) -> Dict:
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

    def _list_self_utxos(self, ctx: Any = None, args: Dict = None, originator: str = None) -> List[Dict[str, Any]]:
        # Prefer derived key UTXOs when protocol/key_id is provided; fallback to master if none found
        # _list_self_utxosは「どのアドレスから取るか」を決めてから、実際の取得をlist_outputsに委譲。
        
        protocol_id = args.get("protocolID") or args.get("protocol_id")
        key_id = args.get("keyID") or args.get("key_id")
        counterparty = args.get("counterparty")
        # Also support nested pushdrop params (create_action passes ca_args under pushdrop)
        if protocol_id is None or key_id is None:
            pd = args.get("pushdrop") or {}
            if protocol_id is None:
                protocol_id = pd.get("protocolID") or pd.get("protocol_id")
            if key_id is None:
                key_id = pd.get("keyID") or pd.get("key_id")
            if counterparty is None:
                counterparty = pd.get("counterparty")

        candidate_addresses: List[str] = []
        # 1) Derived address candidate
        if protocol_id and key_id:
            try:
                if isinstance(protocol_id, dict):
                    protocol = SimpleNamespace(security_level=int(protocol_id.get("securityLevel", 0)), protocol=str(protocol_id.get("protocol", "")))
                else:
                    protocol = protocol_id
                cp = self._normalize_counterparty(counterparty)
                derived_pub = self.key_deriver.derive_public_key(protocol, key_id, cp, for_self=False)
                
                # Use the private key's network to generate the correct address
                network = self.private_key.network if hasattr(self, 'private_key') and hasattr(self.private_key, 'network') else None
                derived_addr = derived_pub.address(network=network) if network else derived_pub.address()
                
                if derived_addr and validate_address(derived_addr):
                    candidate_addresses.append(derived_addr)
                    if os.getenv("BSV_DEBUG", "0") == "1":
                        print(f"[DEBUG _list_self_utxos] Candidate derived address: {derived_addr}")
            except Exception as e:
                if os.getenv("BSV_DEBUG", "0") == "1":
                    print(f"[DEBUG _list_self_utxos] derive addr error: {e}")
        # 2) Master address fallback
        master_addr = self._self_address()
        if master_addr and validate_address(master_addr):
            candidate_addresses.append(master_addr)
            if os.getenv("BSV_DEBUG", "0") == "1":
                print(f"[DEBUG _list_self_utxos] Candidate master address: {master_addr}")

        # 3) Optional explicit basket override (lowest priority)
        explicit_basket = args.get("basket")
        if explicit_basket and isinstance(explicit_basket, str) and validate_address(explicit_basket):
            candidate_addresses.append(explicit_basket)

        # Use WOC for funding UTXOs only if USE_WOC environment variable is set and not "0"
        # E2E tests may set USE_WOC=1 to test real WOC integration, unit tests typically disable it
        use_woc = os.getenv("USE_WOC") != "0" and "USE_WOC" in os.environ
        for addr in candidate_addresses:
            lo = self.list_outputs(ctx, {"basket": addr, "use_woc": use_woc}, originator) or {}
            outs = [u for u in lo.get("outputs", []) if isinstance(u, dict) and u.get("satoshis")]
            if outs:
                return outs
        return []

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

    def _select_funding_and_change(
        self,
        ctx: Any,
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
        utxos = self._sort_utxos_deterministic(self._list_self_utxos(ctx, args, originator))

        # Helper: estimate fee optionally including a hypothetical change output
        def estimate_with_optional_change(sel_count: int, include_change: bool) -> int:
            base_outs = list(outputs)
            if include_change:
                addr = self._self_address()
                if addr:
                    try:
                        addr=self._self_address()
                        print(f"[TRACE] [estimate_with_optional_change] addr: {addr}")
                        ch_ls = P2PKH().lock(addr)  # Script object
                        base_outs = base_outs + [{"satoshis": 1, "lockingScript": ch_ls.hex()}]  # HEX文字列に変換
                    except Exception:
                        pass
            unlocking_lens = list(existing_unlock_lens) + [107] * sel_count
            return self._estimate_fee(base_outs, unlocking_lens, fee_model)

        # Initial need assumes we will add a change output (worst case for size)
        need0 = target + estimate_with_optional_change(0, include_change=True)

        # Heuristic 1: single UTXO covering need0 with minimal excess
        single = None
        for u in sorted(utxos, key=lambda x: int(x.get("satoshis", 0))):
            if int(u.get("satoshis", 0)) >= need0:
                single = u
                break

        # Heuristic 2: try best pair (limit search space)
        pair = None
        best_sum = None
        limited = utxos[:50]
        for i in range(len(limited)):
            vi = int(limited[i].get("satoshis", 0))
            if vi >= need0:
                if best_sum is None or vi < best_sum:
                    best_sum = vi
                    pair = (limited[i],)
                break
            for j in range(i + 1, len(limited)):
                vj = int(limited[j].get("satoshis", 0))
                s = vi + vj
                if s >= need0 and (best_sum is None or s < best_sum):
                    best_sum = s
                    pair = (limited[i], limited[j])

        selected: List[Dict] = []
        if single is not None:
            selected = [single]
        elif pair is not None and len(pair) == 2:
            selected = [pair[0], pair[1]]
        # If still empty, fallback to greedy largest-first
        if not selected:
            total_in = 0
            for u in utxos:
                selected.append(u)
                total_in += int(u.get("satoshis", 0))
                est_fee = estimate_with_optional_change(len(selected), include_change=True)
                if total_in >= target + est_fee:
                    break

        # Ensure coverage with refined fee using selected set; add more greedily if needed
        remaining = [u for u in utxos if u not in selected]
        total_in = sum(int(u.get("satoshis", 0)) for u in selected)
        while True:
            est_fee = estimate_with_optional_change(len(selected), include_change=True)
            need = target + est_fee
            if total_in >= need or not remaining:
                break
            u = remaining.pop(0)
            selected.append(u)
            total_in += int(u.get("satoshis", 0))

        funding_ctx: List[Dict[str, Any]] = []
        change_output: Optional[Dict] = None
        if selected:
            p2pkh_unlock_len = 107
            # Build a set of existing outpoints in inputs_meta
            existing_outpoints = set()
            for meta in inputs_meta:
                op = meta.get("outpoint") or meta.get("Outpoint")
                if op and isinstance(op, dict):
                    txid_val = op.get("txid")
                    if isinstance(txid_val, str) and len(txid_val) == 64:
                        # Use hex string as-is
                        txid_hex = txid_val
                    elif isinstance(txid_val, (bytes, bytearray)) and len(txid_val) == 32:
                        # Convert bytes to hex string
                        txid_hex = txid_val.hex()
                    else:
                        continue  # Skip invalid txid
                    key = (txid_hex, int(op.get("index", 0)))
                    existing_outpoints.add(key)
            for u in selected:
                txid_val = u.get("txid")
                if isinstance(txid_val, str) and len(txid_val) == 64:
                    txid_hex = txid_val
                elif isinstance(txid_val, (bytes, bytearray)) and len(txid_val) == 32:
                    txid_hex = txid_val.hex()
                else:
                    txid_hex = "00" * 32
                # Use hex string for comparison with existing_outpoints
                outpoint_key = (txid_hex, int(u.get("outputIndex", 0)))
                # Skip if this outpoint already exists in inputs_meta
                if outpoint_key in existing_outpoints:
                    continue
                # Decide which key signs this UTXO: master vs derived
                pushdrop_args = args.get("pushdrop", {})
                protocol = pushdrop_args.get("protocolID") or pushdrop_args.get("protocol_id") or args.get("protocolID") or args.get("protocol_id")
                key_id = pushdrop_args.get("keyID") or pushdrop_args.get("key_id") or args.get("keyID") or args.get("key_id")
                counterparty = pushdrop_args.get("counterparty") or args.get("counterparty")

                # Extract pubkey hash from UTXO locking script
                ls_hex = u.get("lockingScript")
                utxo_hash = self._extract_pubkey_hash_from_locking_script(ls_hex) if isinstance(ls_hex, str) else None

                # Default: assume master key signs
                use_protocol = None
                use_key_id = None
                use_counterparty = None

                try:
                    if utxo_hash:
                        # If matches master, keep defaults (master priv)
                        if not self.check_pubkey_hash(self.private_key, utxo_hash):
                            # Try derived key
                            if protocol and key_id is not None:
                                if isinstance(protocol, dict):
                                    protocol_obj = SimpleNamespace(security_level=int(protocol.get("securityLevel", 0)), protocol=str(protocol.get("protocol", "")))
                                else:
                                    protocol_obj = protocol
                                cp = self._normalize_counterparty(counterparty)
                                derived_pub = self.key_deriver.derive_public_key(protocol_obj, key_id, cp, for_self=False)
                                if self._pubkey_matches_hash(derived_pub, utxo_hash):
                                    use_protocol = protocol
                                    use_key_id = key_id
                                    use_counterparty = counterparty
                except Exception:
                    # On any error, fall back to master key
                    pass

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
                if isinstance(ls_val, bytes):
                    ls_hex = ls_val.hex()
                elif isinstance(ls_val, str):
                    ls_hex = ls_val
                else:
                    ls_hex = ""
                funding_ctx.append({
                    "satoshis": int(u.get("satoshis", 0)),
                    "lockingScript": ls_hex,
                })
            unlocking_lens = list(existing_unlock_lens) + [p2pkh_unlock_len] * len(selected)
            est_fee = self._estimate_fee(outputs, unlocking_lens, fee_model)
            change_amt = total_in - target - est_fee
            if change_amt >= 0: # 546
                addr = self._self_address()
                if addr:
                    # First pass: append tentative change
                    change_output = self._build_change_output_dict(addr, int(change_amt))
                    # In _select_funding_and_change, do NOT append change_output to outputs. Only set change_output and return it.
                    # Remove or comment out any outputs.append(change_output) in this method.
                    # (No code to add here, just remove the append in the relevant place.)

        return funding_ctx, change_output
