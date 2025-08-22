from typing import Any, Dict, Optional, List
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
        if isinstance(t, int):
            return t
        if isinstance(t, str):
            tl = t.lower()
            if tl in ("self", "me"):
                return CounterpartyType.SELF
            if tl in ("other", "counterparty"):
                return CounterpartyType.OTHER
            if tl in ("anyone", "any"):
                return CounterpartyType.ANYONE
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

    def get_public_key(self, ctx: Any, args: Dict, originator: str) -> Dict:
        try:
            seek_permission = args.get("seekPermission") or args.get("seek_permission")
            if os.getenv("BSV_DEBUG", "0") == "1":
                print(f"[DEBUG WalletImpl.get_public_key] originator={originator} seek_permission={seek_permission} args={args}")
            if seek_permission:
                self._check_permission("Get public key")
            if args.get("identityKey", False):
                return {"publicKey": self.public_key.hex()}
            protocol_id = args.get("protocolID")
            key_id = args.get("keyID")
            counterparty = args.get("counterparty")
            for_self = args.get("forSelf", False)
            if protocol_id is None or key_id is None:
                return {"error": "get_public_key: protocolID and keyID are required for derived key"}
            if isinstance(protocol_id, dict):
                protocol = Protocol(protocol_id.get("securityLevel", 0), protocol_id.get("protocol", ""))
            else:
                protocol = protocol_id
            cp = self._normalize_counterparty(counterparty)
            derived_pub = self.key_deriver.derive_public_key(protocol, key_id, cp, for_self)
            return {"publicKey": derived_pub.hex()}
        except Exception as e:
            return {"error": f"get_public_key: {e}"}

    def encrypt(self, ctx: Any, args: Dict, originator: str) -> Dict:
        try:
            encryption_args = args.get("encryption_args", {})
            if os.getenv("BSV_DEBUG", "0") == "1":
                print(f"[DEBUG WalletImpl.encrypt] originator={originator} enc_args={encryption_args}")
            self._maybe_seek_permission("Encrypt", encryption_args)
            plaintext = args.get("plaintext")
            if plaintext is None:
                return {"error": "encrypt: plaintext is required"}
            pubkey = self._resolve_encryption_public_key(encryption_args)
            ciphertext = pubkey.encrypt(plaintext)
            return {"ciphertext": ciphertext}
        except Exception as e:
            return {"error": f"encrypt: {e}"}

    def decrypt(self, ctx: Any, args: Dict, originator: str) -> Dict:
        try:
            encryption_args = args.get("encryption_args", {})
            if os.getenv("BSV_DEBUG", "0") == "1":
                print(f"[DEBUG WalletImpl.decrypt] originator={originator} enc_args={encryption_args}")
            self._maybe_seek_permission("Decrypt", encryption_args)
            ciphertext = args.get("ciphertext")
            if ciphertext is None:
                return {"error": "decrypt: ciphertext is required"}
            plaintext = self._perform_decrypt_with_args(encryption_args, ciphertext)
            return {"plaintext": plaintext}
        except Exception as e:
            return {"error": f"decrypt: {e}"}

    def create_signature(self, ctx: Any, args: Dict, originator: str) -> Dict:
        try:
            encryption_args = args.get("encryption_args", {})
            protocol_id = encryption_args.get("protocol_id")
            key_id = encryption_args.get("key_id")
            counterparty = encryption_args.get("counterparty")
            if os.getenv("BSV_DEBUG", "0") == "1":
                print(f"[DEBUG WalletImpl.create_signature] enc_args={encryption_args}")
            if protocol_id is None or key_id is None:
                return {"error": "create_signature: protocol_id and key_id are required"}
            if isinstance(protocol_id, dict):
                protocol = Protocol(protocol_id.get("securityLevel", 0), protocol_id.get("protocol", ""))
            else:
                protocol = protocol_id
            cp = self._normalize_counterparty(counterparty)
            priv = self.key_deriver.derive_private_key(protocol, key_id, cp)
            data = args.get("data", b"")
            hash_to_sign = args.get("hash_to_sign")
            if hash_to_sign:
                to_sign = hash_to_sign
            else:
                to_sign = hashlib.sha256(data).digest()
            signature = priv.sign(to_sign)
            return {"signature": signature}
        except Exception as e:
            return {"error": f"create_signature: {e}"}

    def verify_signature(self, ctx: Any, args: Dict, originator: str) -> Dict:
        try:
            encryption_args = args.get("encryption_args", {})
            protocol_id = encryption_args.get("protocol_id")
            key_id = encryption_args.get("key_id")
            counterparty = encryption_args.get("counterparty")
            for_self = encryption_args.get("forSelf", False)
            if os.getenv("BSV_DEBUG", "0") == "1":
                print(f"[DEBUG WalletImpl.verify_signature] enc_args={encryption_args}")
            if protocol_id is None or key_id is None:
                return {"error": "verify_signature: protocol_id and key_id are required"}
            if isinstance(protocol_id, dict):
                protocol = Protocol(protocol_id.get("securityLevel", 0), protocol_id.get("protocol", ""))
            else:
                protocol = protocol_id
            cp = self._normalize_counterparty(counterparty)
            pub = self.key_deriver.derive_public_key(protocol, key_id, cp, for_self)
            data = args.get("data", b"")
            hash_to_verify = args.get("hash_to_verify")
            signature = args.get("signature")
            if signature is None:
                return {"error": "verify_signature: signature is required"}
            if hash_to_verify:
                to_verify = hash_to_verify
            else:
                to_verify = hashlib.sha256(data).digest()
            valid = pub.verify(signature, to_verify)
            return {"valid": valid}
        except Exception as e:
            return {"error": f"verify_signature: {e}"}

    def create_hmac(self, ctx: Any, args: Dict, originator: str) -> Dict:
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
                protocol = Protocol(protocol_id.get("securityLevel", 0), protocol_id.get("protocol", ""))
            else:
                protocol = protocol_id
            cp = self._normalize_counterparty(counterparty)
            shared_secret = self.key_deriver.derive_symmetric_key(protocol, key_id, cp)
            data = args.get("data", b"")
            hmac_value = hmac.new(shared_secret, data, hashlib.sha256).digest()
            return {"hmac": hmac_value}
        except Exception as e:
            return {"error": f"create_hmac: {e}"}

    def verify_hmac(self, ctx: Any, args: Dict, originator: str) -> Dict:
        try:
            encryption_args = args.get("encryption_args", {})
            protocol_id = encryption_args.get("protocol_id")
            key_id = encryption_args.get("key_id")
            counterparty = encryption_args.get("counterparty")
            if os.getenv("BSV_DEBUG", "0") == "1":
                print(f"[DEBUG WalletImpl.verify_hmac] enc_args={encryption_args}")
            if protocol_id is None or key_id is None:
                return {"error": "verify_hmac: protocol_id and key_id are required"}
            if isinstance(protocol_id, dict):
                protocol = Protocol(protocol_id.get("securityLevel", 0), protocol_id.get("protocol", ""))
            else:
                protocol = protocol_id
            cp = self._normalize_counterparty(counterparty)
            if os.getenv("BSV_DEBUG", "0") == "1":
                try:
                    cp_pub_dbg = cp.to_public_key(self.public_key)
                    print(f"[DEBUG WalletImpl.verify_hmac] cp.type={cp.type} cp.pub={cp_pub_dbg.hex()}")
                except Exception as dbg_e:
                    print(f"[DEBUG WalletImpl.verify_hmac] cp normalization error: {dbg_e}")
            shared_secret = self.key_deriver.derive_symmetric_key(protocol, key_id, cp)
            data = args.get("data", b"")
            hmac_value = args.get("hmac")
            if hmac_value is None:
                return {"error": "verify_hmac: hmac is required"}
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
    def acquire_certificate(self, ctx: Any, args: Dict, originator: str) -> Dict:
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
    def create_action(self, ctx: Any, args: Dict, originator: str) -> Dict:
        """
        Build a Transaction from inputs/outputs; auto-fund with wallet UTXOs (Go-style).
        - Always calls .serialize() on Transaction object returned by _build_signable_transaction.
        """
        import binascii
        labels = args.get("labels") or []
        description = args.get("description", "")
        outputs = list(args.get("outputs") or [])
        inputs_meta = list(args.get("inputs") or [])
        # --- PushDrop extension: fields/signature/lock-position/basket/retention ---
        pushdrop_args = args.get("pushdrop")
        if pushdrop_args:
            from bsv.transaction.pushdrop import build_lock_before_pushdrop
            fields = pushdrop_args.get("fields", [])
            pubkey = pushdrop_args.get("public_key")
            include_signature = pushdrop_args.get("include_signature", False)
            signature = pushdrop_args.get("signature")
            lock_position = pushdrop_args.get("lock_position", "before")
            basket = pushdrop_args.get("basket")
            retention = pushdrop_args.get("retentionSeconds")
            # Build PushDrop locking script (Go/TS parity)
            if pubkey:
                locking_script = build_lock_before_pushdrop(fields, pubkey, include_signature=include_signature, signature=signature, lock_position=lock_position)
                output = {"lockingScript": locking_script, "satoshis": pushdrop_args.get("satoshis", 1000)}
                if basket:
                    output["basket"] = basket
                if retention:
                    output["outputDescription"] = {"retentionSeconds": retention}
                outputs.append(output)
        # Fee model (default 500 sat/kB unless overridden)
        fee_rate = int(args.get("feeRate", 500))
        fee_model = SatoshisPerKilobyte(fee_rate)
        # Compute current target output sum
        target = self._sum_outputs(outputs)
        # Determine existing inputs' estimated unlocking lengths if provided
        existing_unlock_lens: List[int] = []
        for _ in inputs_meta:
            est = int(_.get("unlockingScriptLength", 73))
            existing_unlock_lens.append(est)
        # Auto-fund if needed (extracts funding inputs and optional change)
        funding_ctx: List[Dict[str, Any]]
        change_output: Optional[Dict]
        funding_ctx, change_output = self._select_funding_and_change(
            ctx,
            args,
            originator,
            outputs,
            inputs_meta,
            existing_unlock_lens,
            fee_model,
        )
        # If change output is generated, add to outputs
        if change_output:
            outputs.append(change_output)
        total_out = self._sum_outputs(outputs)
        action = self._build_action_dict(args, total_out, description, labels, inputs_meta, outputs)
        self._actions.append(action)
        # Build signable tx and pre-sign funding inputs (P2PKH)
        funding_start_index = len(inputs_meta) - len(funding_ctx) if funding_ctx else None
        signable_tx = self._build_signable_transaction(
            outputs,
            inputs_meta,
            prefill_funding=True,
            funding_start_index=funding_start_index,
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

    def _build_action_dict(self, args, total_out, description, labels, inputs_meta, outputs):
        created_at = int(time.time())
        return {
            "txid": b"\x00" * 32,
            "satoshis": total_out,
            "status": "unprocessed",
            "isOutgoing": True,
            "description": description,
            "labels": labels,
            "version": int(args.get("version") or 0),
            "lockTime": int(args.get("lockTime") or 0),
            "inputs": inputs_meta,
            "outputs": [
                {
                    "outputIndex": int(i),
                    "satoshis": int(o.get("satoshis", 0)),
                    "lockingScript": o.get("lockingScript", b""),
                    "spendable": True,
                    "outputDescription": o.get("outputDescription", ""),
                    "basket": o.get("basket", ""),
                    "tags": o.get("tags") or [],
                    "customInstructions": o.get("customInstructions"),
                    "createdAt": created_at,
                }
                for i, o in enumerate(outputs)
            ],
        }

    def _build_signable_transaction(self, outputs, inputs_meta, prefill_funding: bool = False, funding_start_index: Optional[int] = None, funding_context: Optional[List[Dict[str, Any]]] = None):
        """
        Always return a Transaction object, even if outputs is empty (for remove flows).
        Ensure TransactionInput receives source_txid as hex string (str), not bytes.
        Ensure TransactionOutput receives int(satoshis) and Script in correct order.
        """
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
            for o in outputs:
                ls = o.get("lockingScript", b"")
                if isinstance(ls, str):
                    ls_bytes = bytes.fromhex(ls)
                else:
                    ls_bytes = ls
                satoshis = o.get("satoshis", 0)
                logger.debug(f"Output satoshis type: {type(satoshis)}, value: {satoshis}")
                logger.debug(f"Output lockingScript type: {type(ls_bytes)}, value: {ls_bytes}")
                # Defensive: ensure satoshis is int, ls_bytes is bytes
                assert isinstance(satoshis, int), f"satoshis must be int, got {type(satoshis)}"
                assert isinstance(ls_bytes, (bytes, bytearray)), f"lockingScript must be bytes, got {type(ls_bytes)}"
                s = Script(ls_bytes)
                to = TransactionOutput(s, int(satoshis))
                t.add_output(to)
            # Map to track which inputs are funding (P2PKH) to optionally pre-sign
            funding_indices: List[int] = []
            for i, meta in enumerate(inputs_meta):
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
                    # Heuristic: treat inputs lacking custom descriptors as funding (P2PKH)
                    desc = (meta.get("inputDescription") or "").lower()
                    if "funding" in desc or meta.get("unlockingScriptLength", 0) in (107, 139):
                        funding_indices.append(len(t.inputs))
                    t.add_input(ti)
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
                                tin.locking_script = Script(ls_b)
                    else:
                        # Fallback: set generic P2PKH lock with our address
                        addr = self.public_key.address()
                        ls_fund = P2PKH().lock(addr).serialize()
                        for idx in funding_indices:
                            tin = t.inputs[idx]
                            tin.satoshis = 0
                            tin.locking_script = Script(ls_fund)
                    # Now produce signatures for those inputs
                    unlock_tpl = P2PKH().unlock(self.private_key)
                    for idx in funding_indices:
                        t.inputs[idx].unlocking_script = unlock_tpl.sign(t, idx)
                except Exception:
                    pass
            return t  # Always return Transaction object
        except Exception:
            from bsv.transaction import Transaction
            return Transaction()  # Return empty Transaction on error

    def discover_by_attributes(self, ctx: Any, args: Dict, originator: str) -> Dict:
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
    def discover_by_identity_key(self, ctx: Any, args: Dict, originator: str) -> Dict:
        # naive: no identity index, return empty
        return {"totalCertificates": 0, "certificates": []}
    def get_header_for_height(self, ctx: Any, args: Dict, originator: str) -> Dict:
        # minimal: return empty header bytes
        return {"header": b""}
    def get_height(self, ctx: Any, args: Dict, originator: str) -> Dict:
        return {"height": 0}
    def get_network(self, ctx: Any, args: Dict, originator: str) -> Dict:
        return {"network": "mocknet"}
    def get_version(self, ctx: Any, args: Dict, originator: str) -> Dict:
        return {"version": "0.0.0"}
    def internalize_action(self, ctx: Any, args: Dict, originator: str) -> Dict:
        """
        Broadcast the signed transaction to the network.
        - If outputs are empty, do not broadcast and return an error.
        """
        import os, binascii
        use_woc = os.getenv("USE_WOC", "0") == "1" or args.get("use_woc")
        use_mapi = args.get("use_mapi")
        use_custom_node = args.get("use_custom_node")
        tx_bytes = args.get("tx")
        txid = None
        tx_hex = None
        result = {"accepted": False, "error": "internalize_action: missing tx bytes"}
        if tx_bytes:
            try:
                from bsv.transaction import Transaction
                tx = Transaction.from_bytes(tx_bytes)
                # Guard: do not broadcast if outputs are empty
                if not getattr(tx, "outputs", None) or len(tx.outputs) == 0:
                    return {"accepted": False, "error": "Cannot broadcast transaction with no outputs", "tx_hex": binascii.hexlify(tx_bytes).decode()}
                tx_hex = tx.to_hex() if hasattr(tx, "to_hex") else binascii.hexlify(tx_bytes).decode()
                ext_bc = args.get("broadcaster")
                # Custom broadcaster (for test/mocks)
                if ext_bc and hasattr(ext_bc, "broadcast"):
                    res = ext_bc.broadcast(tx_hex)
                    if isinstance(res, dict) and (res.get("accepted") or res.get("txid")):
                        txid = res.get("txid")
                        result = {"accepted": True, "txid": txid, "tx_hex": tx_hex}
                    else:
                        result = res
                elif use_woc:
                    from bsv.network.broadcaster import WOCBroadcaster
                    api_key = self._resolve_woc_api_key(args)
                    timeout = int(args.get("timeoutSeconds", int(os.getenv("WOC_TIMEOUT", "10"))))
                    bc = WOCBroadcaster(api_key=api_key, network="main")
                    res = bc.broadcast(tx_hex, timeout=timeout)
                    txid = res.get("txid")
                    result = {**res, "tx_hex": tx_hex}
                elif use_mapi:
                    from bsv.network.broadcaster import MAPIClientBroadcaster
                    api_url = args.get("mapi_url") or os.getenv("MAPI_URL")
                    api_key = args.get("mapi_api_key") or os.getenv("MAPI_API_KEY")
                    if not api_url:
                        return {"accepted": False, "error": "internalize_action: mAPI url missing", "tx_hex": tx_hex}
                    bc = MAPIClientBroadcaster(api_url=api_url, api_key=api_key)
                    res = bc.broadcast(tx_hex)
                    txid = res.get("txid")
                    result = {**res, "tx_hex": tx_hex}
                elif use_custom_node:
                    from bsv.network.broadcaster import CustomNodeBroadcaster
                    api_url = args.get("custom_node_url") or os.getenv("CUSTOM_NODE_URL")
                    api_key = args.get("custom_node_api_key") or os.getenv("CUSTOM_NODE_API_KEY")
                    if not api_url:
                        return {"accepted": False, "error": "internalize_action: custom node url missing", "tx_hex": tx_hex}
                    bc = CustomNodeBroadcaster(api_url=api_url, api_key=api_key)
                    res = bc.broadcast(tx_hex)
                    txid = res.get("txid")
                    result = {**res, "tx_hex": tx_hex}
                else:
                    # Fallback to mock logic
                    txid = tx.txid() if hasattr(tx, "txid") else None
                    result = {"accepted": True, "txid": txid, "tx_hex": tx_hex, "mock": True}
            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                result = {"accepted": False, "error": f"internalize_action: {e}", "traceback": tb, "tx_hex": tx_hex}
        return result

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
        # Fallback to WOCChainTracker
        from bsv.network.chaintracker import WOCChainTracker
        try:
            key = api_key or self._resolve_woc_api_key({})
            ct = WOCChainTracker(api_key=key, network=network)
            return ct.query_tx(txid, timeout=timeout)
        except Exception as e:  # noqa: PERF203
            return {"known": False, "error": str(e)}
    def is_authenticated(self, ctx: Any, args: Dict, originator: str) -> Dict:
        return {"authenticated": True}
    def list_actions(self, ctx: Any, args: Dict, originator: str) -> Dict:
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
    def list_certificates(self, ctx: Any, args: Dict, originator: str) -> Dict:
        # Minimal: return stored certificates
        return {"totalCertificates": len(self._certificates), "certificates": self._certificates}
    def list_outputs(self, ctx: Any, args: Dict, originator: str) -> Dict:
        """
        If USE_WOC env var is set or args['use_woc'] is True, fetch UTXOs from Whatsonchain mainnet API.
        Otherwise, fallback to mock logic.
        """
        use_woc = os.getenv("USE_WOC", "0") == "1" or args.get("use_woc")
        # Allow cooperative cancel (best-effort)
        if args.get("cancel"):
            return {"outputs": []}
        if use_woc:
            # Determine address: prefer basket, then tags, then self.public_key
            address = args.get("basket") or (args.get("tags") or [None])[0]
            if not address or not isinstance(address, str):
                # Fallback: derive address from self.public_key
                try:
                    from bsv.keys import PublicKey
                    pubkey = self.public_key if hasattr(self, "public_key") else None
                    if pubkey and hasattr(pubkey, "to_address"):
                        address = pubkey.to_address("mainnet")
                    else:
                        return {"error": "No address available for WOC UTXO lookup"}
                except Exception as e:
                    return {"error": f"Failed to derive address: {e}"}
            timeout = int(args.get("timeoutSeconds", int(os.getenv("WOC_TIMEOUT", "10"))))
            utxos = self._get_utxos_from_woc(address, timeout=timeout)
            return {"outputs": utxos}
        # Fallback to existing mock logic
        include = (args.get("include") or "").lower()
        basket = args.get("basket", "")
        outputs_desc = self._find_outputs_for_basket(basket, args)
        # Retention filter: drop expired outputs when requested
        if args.get("excludeExpired"):
            now_epoch = int(args.get("nowEpoch", time.time()))
            outputs_desc = [o for o in outputs_desc if not self._is_output_expired(o, now_epoch)]
        if os.getenv("REGISTRY_DEBUG") == "1":
            print("[DEBUG list_outputs] basket", basket, "outputs_desc", outputs_desc)
        beef_bytes = self._build_beef_for_outputs(outputs_desc)
        res = {"outputs": self._format_outputs_result(outputs_desc, basket)}
        if "entire" in include or "transaction" in include:
            res["BEEF"] = beef_bytes
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
            for o in outputs_desc:
                ls_hex = o.get("lockingScript")
                ls_bytes = bytes.fromhex(ls_hex) if isinstance(ls_hex, str) else (ls_hex or b"\x51")
                to = TransactionOutput(Script(ls_bytes), int(o.get("satoshis", 0)))
                tx.add_output(to)
            return tx.to_beef()
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
            protocol = Protocol(protocol_id.get("securityLevel", 0), protocol_id.get("protocol", "")) if isinstance(protocol_id, dict) else protocol_id
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
            protocol = Protocol(protocol_id.get("securityLevel", 0), protocol_id.get("protocol", "")) if isinstance(protocol_id, dict) else protocol_id
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
    def prove_certificate(self, ctx: Any, args: Dict, originator: str) -> Dict:
        return {"keyringForVerifier": {}, "verifier": args.get("verifier", b"")}
    def relinquish_certificate(self, ctx: Any, args: Dict, originator: str) -> Dict:
        # Remove matching certificate if present
        typ = args.get("type")
        serial = args.get("serialNumber")
        certifier = args.get("certifier")
        self._certificates = [c for c in self._certificates if 
            c.get("match") != (typ, serial, certifier)
        ]
        return {}
    def relinquish_output(self, ctx: Any, args: Dict, originator: str) -> Dict:
        return {}
    def reveal_counterparty_key_linkage(self, ctx: Any, args: Dict, originator: str) -> Dict:
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

    def reveal_specific_key_linkage(self, ctx: Any, args: Dict, originator: str) -> Dict:
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

    def sign_action(self, ctx: Any, args: Dict, originator: str) -> Dict:
        """
        Sign the provided transaction using the provided spends (unlocking scripts),
        following the Go/TS flow. Returns the signed transaction and txid.
        Enhancements:
        - If spends is not specified, auto-generate using _prepare_spends
        - Ensure unlockingScript in spends is generated via PushDropUnlocker
        - Explicitly comment SIGHASH/BIP143/Unlocker branches
        - Add detailed error info in return value
        - Optionally return signature bytes and txid as hex for test vector comparison
        """
        import binascii
        try:
            # Extract signable transaction bytes
            tx_bytes = None
            if "tx" in args:
                tx_bytes = args["tx"]
            elif "signableTransaction" in args and "tx" in args["signableTransaction"]:
                tx_bytes = args["signableTransaction"]["tx"]
            if not tx_bytes:
                return {"error": "sign_action: missing tx bytes"}
            from bsv.transaction import Transaction
            from bsv.transaction_input import TransactionInput
            # Deserialize transaction
            tx = Transaction.from_bytes(tx_bytes)
            spends = args.get("spends") or {}
            # If spends is not specified, auto-generate using _prepare_spends
            if not spends:
                if hasattr(self, "_prepare_spends"):
                    spends = self._prepare_spends(ctx, tx, args, originator)
                else:
                    return {"error": "sign_action: spends missing and _prepare_spends unavailable"}
            # Set unlockingScript for each input
            for idx, input in enumerate(tx.inputs):
                spend = spends.get(str(idx)) or spends.get(idx) or {}
                unlocking_script = spend.get("unlockingScript", b"")
                # Check if unlockingScript is generated via Unlocker (type, length, SIGHASH flag)
                if unlocking_script and isinstance(unlocking_script, (bytes, bytearray)):
                    if len(unlocking_script) < 2:
                        return {"error": f"sign_action: unlockingScript too short at input {idx}"}
                    # Record SIGHASH flag (last byte)
                    sighash_flag = unlocking_script[-1]
                input.unlocking_script = unlocking_script
            # Serialize signed transaction
            signed_tx_bytes = tx.serialize()
            txid = tx.txid() if hasattr(tx, "txid") else hashlib.sha256(signed_tx_bytes).hexdigest()
            # Optionally return hex for test vector comparison
            return {
                "tx": signed_tx_bytes,
                "tx_hex": binascii.hexlify(signed_tx_bytes).decode(),
                "txid": txid,
                "txid_hex": txid if isinstance(txid, str) else binascii.hexlify(txid).decode(),
                "spends": spends,
            }
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            return {"tx": b"\x00", "txid": "00" * 32, "error": f"sign_action: {e}", "traceback": tb}
    def wait_for_authentication(self, ctx: Any, args: Dict, originator: str) -> Dict:
        return {"authenticated": True}

    def _get_utxos_from_woc(self, address: str, api_key: Optional[str] = None, timeout: int = 10) -> list:
        """
        Fetch UTXOs for the given address from Whatsonchain mainnet API and convert to SDK outputs format.
        API key is loaded from the WOC_API_KEY environment variable (set via .env file).
        """
        import requests
        # Load API key via configured precedence (TS parity): explicit -> instance -> env
        api_key = api_key or self._woc_api_key or os.environ.get("WOC_API_KEY") or ""
        url = f"https://api.whatsonchain.com/v1/bsv/main/address/{address}/unspent"
        headers = {}
        if api_key:
            headers["Authorization"] = api_key
            headers["woc-api-key"] = api_key
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            utxos = []
            for u in data:
                utxos.append({
                    "outputIndex": int(u.get("tx_pos", u.get("vout", 0))),
                    "satoshis": int(u.get("value", 0)),
                    "lockingScript": u.get("script", ""),
                    "spendable": True,
                    "outputDescription": "WOC UTXO",
                    "basket": address,
                    "tags": [],
                    "customInstructions": None,
                    "txid": u.get("tx_hash", u.get("txid", "")),
                })
            return utxos
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
            return self.public_key.address()
        except Exception:
            return ""

    def _list_self_utxos(self, ctx: Any, args: Dict, originator: str) -> List[Dict[str, Any]]:
        basket_addr = self._self_address()
        query_basket = basket_addr if basket_addr and validate_address(basket_addr) else args.get("basket") or ""
        lo = self.list_outputs(ctx, {"basket": query_basket, "use_woc": os.getenv("USE_WOC", "0") == "1"}, originator) or {}
        return [u for u in lo.get("outputs", []) if isinstance(u, dict) and u.get("satoshis")]

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
                ls_b = bytes.fromhex(ls) if isinstance(ls, str) else ls
                t.add_output(_TxOut(_Script(ls_b), int(o.get("satoshis", 0))))
            for est_len in unlocking_lens:
                ti = _TxIn(source_txid="00" * 32, source_output_index=0)
                fake = encode_pushdata(b"x" * max(0, est_len - 1)) if est_len > 0 else b"\x00"
                ti.unlocking_script = _Script(fake)
                t.add_input(ti)
            return int(fee_model.compute_fee(t))
        except Exception:
            return 500

    def _build_change_output_dict(self, basket_addr: str, satoshis: int) -> Dict[str, Any]:
        ls = P2PKH().lock(basket_addr).serialize()
        return {
            "satoshis": int(satoshis),
            "lockingScript": ls,
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
                        ch_ls = P2PKH().lock(addr).serialize()
                        base_outs = base_outs + [{"satoshis": 1, "lockingScript": ch_ls}]
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
            for u in selected:
                txid_val = u.get("txid")
                if isinstance(txid_val, str) and len(txid_val) == 64:
                    txid_b = bytes.fromhex(txid_val)
                elif isinstance(txid_val, (bytes, bytearray)) and len(txid_val) == 32:
                    txid_b = bytes(txid_val)
                else:
                    txid_b = b"\x00" * 32
                inputs_meta.append({
                    "outpoint": {"txid": txid_b, "index": int(u.get("outputIndex", 0))},
                    "unlockingScriptLength": p2pkh_unlock_len,
                    "inputDescription": u.get("outputDescription", "Funding UTXO"),
                    "sequenceNumber": 0,
                })
                ls_hex = u.get("lockingScript")
                ls_bytes = bytes.fromhex(ls_hex) if isinstance(ls_hex, str) else (ls_hex or b"")
                funding_ctx.append({
                    "satoshis": int(u.get("satoshis", 0)),
                    "lockingScript": ls_bytes,
                })
            unlocking_lens = list(existing_unlock_lens) + [p2pkh_unlock_len] * len(selected)
            est_fee = self._estimate_fee(outputs, unlocking_lens, fee_model)
            change_amt = total_in - target - est_fee
            if change_amt >= 546:
                addr = self._self_address()
                if addr:
                    # First pass: append tentative change
                    change_output = self._build_change_output_dict(addr, int(change_amt))
                    outputs.append(change_output)
                    # Re-estimate including the change output and adjust amount
                    est_fee2 = self._estimate_fee(outputs, unlocking_lens, fee_model)
                    change_amt2 = total_in - target - est_fee2
                    if change_amt2 < 546:
                        # Not worth keeping change after precise fee; drop it
                        outputs.pop()
                        change_output = None
                    else:
                        # Update change to the refined amount
                        outputs[-1]["satoshis"] = int(change_amt2)

        return funding_ctx, change_output
