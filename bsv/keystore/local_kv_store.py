from __future__ import annotations

"""
local_kv_store.py (Python port of go-sdk/kvstore/local_kv_store.go)
-------------------------------------------------------------------

This module provides a *work-in-progress* Python implementation of the Bitcoin
SV on-chain key–value store originally implemented in Go.  Only a **minimal**
prototype is supplied at the moment – it fulfils the public API so that the
rest of the Python SDK can compile/import, yet the heavy blockchain logic is
still to be implemented.

Missing functionality is enumerated at the bottom of the file and returned via
`get_unimplemented_features()` so that build scripts / documentation can query
it programmatically.
"""

from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Dict, List
import base64
import re
import json

from .interfaces import (
    ErrEmptyContext,
    ErrInvalidKey,
    ErrInvalidValue,
    ErrInvalidWallet,
    KVStoreConfig,
    KVStoreInterface,
)
from bsv.transaction.pushdrop import PushDrop

# ---------------------------------------------------------------------------
# Helper types
# ---------------------------------------------------------------------------

@dataclass
class _StoredValue:
    value: str
    # In the full implementation the fields below will reference on-chain
    # artefacts.  They are included here so that the public API (return types)
    # remain stable while the backing logic is developed.
    outpoint: str = ""  # txid.vout string – placeholder for now


# ---------------------------------------------------------------------------
# LocalKVStore prototype
# ---------------------------------------------------------------------------

class LocalKVStore(KVStoreInterface):
    """A *local* (in-memory) key–value store that mimics the Go behaviour.

    The real implementation must:
    1. Leverage *WalletInterface* to create PushDrop outputs on-chain
    2. Support optional encryption via wallet.Encrypt / wallet.Decrypt
    3. Collapse multiple values for the same key into a single UTXO when `set`
       is called repeatedly
    4. Handle removal by creating spending transactions that consume all
       matching outputs

    None of the above is done yet – instead we keep data in-memory so that unit
    tests targeting higher-level components can progress.
    """

    _UNIMPLEMENTED: List[str] = [
        "On-chain storage via wallet.CreateAction / SignAction",
        "PushDrop script generation & parsing",
        "BEEF / AtomicBEEF parsing for bulk tx retrieval",
        "Retention period & basket name support",
    ]

    # NOTE: We do *not* attempt to replicate the rich context propagation of Go
    # right now – the `ctx` parameter is accepted but not inspected.

    def __init__(self, config: KVStoreConfig):
        if config.wallet is None:
            raise ErrInvalidWallet("wallet cannot be None")
        if not config.context:
            raise ErrEmptyContext("context cannot be empty")

        self._wallet = config.wallet
        self._context = config.context
        # Optional extended options (duck-typed from NewLocalKVStoreOptions)
        self._retention_period: int = int(getattr(config, "retention_period", 0) or 0)
        self._basket_name: str = (getattr(config, "basket_name", "") or self._context)
        # sanitised protocol string (letters/numbers only)
        self._protocol = re.sub(r'[^A-Za-z0-9 ]', '', self._context).replace(' ', '')
        self._originator = config.originator
        self._encrypt = bool(config.encrypt)
        # optional: choose lock position ('before' default). allow testing lock-after
        self._lock_position: str = getattr(config, "lock_position", "before") or "before"

        # Simple in-memory dict mapping key->StoredValue
        self._store: Dict[str, _StoredValue] = {}
        self._lock = Lock()

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------

    def get(self, ctx: Any, key: str, default_value: str = "") -> str:  # noqa: N802
        if not key:
            raise ErrInvalidKey(KEY_EMPTY_MSG)
        value = self._get_onchain_value(ctx, key)
        if value is not None:
            return value
        return self._get_local_value(ctx, key, default_value)

    def _get_onchain_value(self, ctx: Any, key: str) -> str | None:
        """Try to retrieve the value from on-chain outputs (BEEF/PushDrop). Return None if not found/decodable."""
        try:
            args = {
                "basket": self._context,
                "tags": [key],
                "include": ENTIRE_TXS,
                "limit": 10,
            }
            lo = self._wallet.list_outputs(ctx, args, self._originator) or {}
            outputs = lo.get("outputs") or []
            if not outputs:
                return None
            most_recent = outputs[-1]
            locking_script = self._extract_locking_script_from_output(lo, most_recent)
            if not locking_script:
                return None
            decoded = PushDrop.decode(locking_script)
            if decoded and isinstance(decoded.get("fields"), list) and decoded["fields"]:
                first_field = decoded["fields"][0]
                # Go/TS parity: if encrypt, always return enc:base64 ciphertext, not decrypted plaintext
                if self._encrypt:
                    # If already base64, return as enc:...
                    if isinstance(first_field, (bytes, bytearray)):
                        return "enc:" + base64.b64encode(first_field).decode('ascii')
                    elif isinstance(first_field, str) and not first_field.startswith("enc:"):
                        return "enc:" + base64.b64encode(first_field.encode('utf-8')).decode('ascii')
                    else:
                        return first_field
                # Plaintext: return as utf-8 string
                try:
                    return first_field.decode('utf-8')
                except Exception:
                    return None
        except Exception:
            return None
        return None

    def _extract_locking_script_from_output(self, lo: dict, output: dict) -> bytes:
        """Extract the locking script from output, using BEEF if available."""
        locking_script = output.get("lockingScript") or b""
        beef_bytes = lo.get("BEEF")
        if not beef_bytes:
            return locking_script
        try:
            match_tx = self._find_matching_tx_from_beef(beef_bytes, output)
            if match_tx is not None:
                vout = int(output.get("outputIndex", 0))
                if 0 <= vout < len(match_tx.outputs):
                    return match_tx.outputs[vout].locking_script.serialize()
        except Exception:
            pass
        return locking_script

    def _find_matching_tx_from_beef(self, beef_bytes: bytes, output: dict):
        """Find the matching transaction from BEEF using subject, txid hint, or last_tx."""
        from bsv.transaction import parse_beef_ex
        beef, subject, last_tx = parse_beef_ex(beef_bytes)
        txid_hint = output.get("txid")
        match_tx = self._find_tx_by_subject(beef, subject)
        if match_tx is not None:
            return match_tx
        match_tx = self._find_tx_by_txid_hint(beef, txid_hint)
        if match_tx is not None:
            return match_tx
        return last_tx

    def _find_tx_by_subject(self, beef, subject):
        """Find transaction by subject in BEEF."""
        if not subject:
            return None
        btxs = beef.find_transaction(subject)
        if btxs and getattr(btxs, 'tx_obj', None):
            return btxs.tx_obj
        return None

    def _find_tx_by_txid_hint(self, beef, txid_hint):
        """Find transaction by txid hint in BEEF."""
        if not (txid_hint and isinstance(txid_hint, str)):
            return None
        btx = beef.find_transaction(txid_hint)
        if btx and getattr(btx, 'tx_obj', None):
            return btx.tx_obj
        return None

    def _try_decrypt_field(self, ctx: Any, key: str, field: bytes) -> str | None:
        """Attempt to decrypt a field using the wallet. Return plaintext string or None."""
        enc = {
            "protocol_id": {"securityLevel": 2, "protocol": self._protocol},
            "key_id": key,
            "counterparty": {"type": 0},
        }
        try:
            if hasattr(self._wallet, 'decrypt_decoded'):
                res = self._wallet.decrypt_decoded(ctx, {"encryption_args": enc, "ciphertext": field}, self._originator)
            else:
                res = self._wallet.decrypt(ctx, {"encryption_args": enc, "ciphertext": field}, self._originator)
            pt = res.get("plaintext") if isinstance(res, dict) else None
            if isinstance(pt, (bytes, bytearray)):
                return pt.decode('utf-8')
        except Exception:
            pass
        return None

    def _get_local_value(self, ctx: Any, key: str, default_value: str) -> str:
        """Retrieve the value from the local cache, decrypting if needed."""
        with self._lock:
            stored = self._store.get(key)
            if stored is None:
                return default_value
            # Go/TS parity: if encrypt, always return enc:... ciphertext
            if self._encrypt and isinstance(stored.value, str) and stored.value.startswith("enc:"):
                return stored.value
            return stored.value

    def set(self, ctx: Any, key: str, value: str) -> str:  # noqa: N802
        if not key:
            raise ErrInvalidKey(KEY_EMPTY_MSG)
        if value == "":
            raise ErrInvalidValue("value cannot be empty")
        outpoint_placeholder, to_store = self._prepare_encrypted_value(ctx, key, value)
        with self._lock:
            self._store[key] = _StoredValue(value=to_store, outpoint=outpoint_placeholder)
        self._onchain_set_flow(ctx, key, value, to_store)
        return outpoint_placeholder

    def _prepare_encrypted_value(self, ctx: Any, key: str, value: str) -> tuple[str, str]:
        """Prepare the value for storage, encrypting if needed. Returns (outpoint_placeholder, to_store)."""
        outpoint_placeholder = f"{key}.0"
        to_store = value
        if not self._encrypt:
            return outpoint_placeholder, to_store
        try:
            enc = {
                "protocol_id": {"securityLevel": 2, "protocol": self._protocol},
                "key_id": key,
                "counterparty": {"type": 0},
            }
            field_bytes = value.encode('utf-8')
            if hasattr(self._wallet, 'encrypt_decoded'):
                res = self._wallet.encrypt_decoded(ctx, {"encryption_args": enc, "plaintext": field_bytes}, self._originator)
                ct = res.get("ciphertext") if isinstance(res, dict) else None
            else:
                res = self._wallet.encrypt(ctx, {"encryption_args": enc, "plaintext": field_bytes}, self._originator)
                ct = res.get("ciphertext") if isinstance(res, dict) else None
            if isinstance(ct, (bytes, bytearray)):
                to_store = "enc:" + base64.b64encode(ct).decode('ascii')
        except Exception:
            to_store = value
        return outpoint_placeholder, to_store

    def _onchain_set_flow(self, ctx: Any, key: str, value: str, to_store: str) -> None:
        """Perform the on-chain flow for set: lookup outputs, build scripts, call wallet actions."""
        try:
            outs, input_beef = self._lookup_outputs_for_set(ctx, key)
            locking_script = self._build_locking_script(ctx, key, value)
            inputs_meta = self._prepare_inputs_meta(ctx, key, outs)
            ca_args = self._build_create_action_args_set(key, value, locking_script, inputs_meta, input_beef)
            ca = self._wallet.create_action(ctx, ca_args, self._originator) or {}
            signable = (ca.get("signableTransaction") or {}) if isinstance(ca, dict) else {}
            signable_tx_bytes = signable.get("tx") or b""
            signed_tx_bytes: bytes | None = None
            if inputs_meta:
                signed_tx_bytes = self._sign_and_relinquish_set(ctx, key, outs, inputs_meta, signable, signable_tx_bytes, input_beef)
            # Broadcast: use signed tx when available, otherwise best-effort signable bytes
            self._wallet.internalize_action(ctx, {"tx": signed_tx_bytes or signable_tx_bytes}, self._originator)
        except Exception:
            pass

    def _lookup_outputs_for_set(self, ctx: Any, key: str) -> tuple[list, bytes]:
        """Lookup outputs and BEEF for set operation."""
        lo = self._wallet.list_outputs(ctx, {
            "basket": self._context,
            "tags": [key],
            "include": ENTIRE_TXS,
            "limit": 100,
        }, self._originator) or {}
        outs = lo.get("outputs") or []
        input_beef = lo.get("BEEF") or b""
        return outs, input_beef

    def _build_create_action_args_set(self, key: str, value: str, locking_script: bytes, inputs_meta: list, input_beef: bytes) -> dict:
        """Build the arguments for create_action in set operation."""
        return {
            "labels": ["kv", "set"],
            "description": "kvstore set",
            "inputs": inputs_meta,
            "inputBEEF": input_beef,
            "outputs": [
                {
                    "satoshis": 1,
                    "lockingScript": locking_script,
                    "outputDescription": json.dumps({
                        "type": "kv.set",
                        "key": key,
                        "value": value,
                        "retentionSeconds": int(self._retention_period),
                    }, separators=(",", ":")),
                    "basket": self._basket_name or self._context or "",
                    "tags": [key],
                }
            ],
        }

    def _sign_and_relinquish_set(self, ctx: Any, key: str, outs: list, inputs_meta: list, signable: dict, signable_tx_bytes: bytes, input_beef: bytes) -> bytes | None:
        """Sign the transaction for set, and relinquish outputs on failure. Returns signed tx bytes or None."""
        spends = self._prepare_spends(ctx, key, inputs_meta, signable_tx_bytes, input_beef, outs)
        try:
            spends_str_keys = {str(int(k)): v for k, v in spends.items()}
            res = self._wallet.sign_action(ctx, {"spends": spends_str_keys, "reference": signable.get("reference") or b""}, self._originator)
            return (res or {}).get("tx") if isinstance(res, dict) else None
        except Exception:
            for o in outs:
                try:
                    self._wallet.relinquish_output(ctx, {
                        "basket": self._context,
                        "output": {
                            "txid": bytes.fromhex(o.get("txid", "00" * 32)) if isinstance(o.get("txid"), str) else (o.get("txid") or b"\x00" * 32),
                            "index": int(o.get("outputIndex", 0)),
                        }
                    }, self._originator)
                except Exception:
                    pass
            return None

    def _build_locking_script(self, ctx: Any, key: str, value: str) -> bytes:
        """Build the PushDrop locking script for the set operation."""
        # 属性（fields）
        field_bytes = value.encode('utf-8')
        fields = [field_bytes]
        # 暗号化対応
        if self._encrypt:
            enc = {
                "protocol_id": {"securityLevel": 2, "protocol": self._protocol},
                "key_id": key,
                "counterparty": {"type": 0},
            }
            if hasattr(self._wallet, 'encrypt_decoded'):
                res = self._wallet.encrypt_decoded(ctx, {"encryption_args": enc, "plaintext": field_bytes}, self._originator)
                ct = res.get("ciphertext") if isinstance(res, dict) else None
            else:
                res = self._wallet.encrypt(ctx, {"encryption_args": enc, "plaintext": field_bytes}, self._originator)
                ct = res.get("ciphertext") if isinstance(res, dict) else None
            if isinstance(ct, (bytes, bytearray)):
                fields = [ct]
        # PushDrop クラスで lock（署名は既定で include）
        pd = PushDrop(self._wallet, self._originator)
        return pd.lock(
            ctx,
            fields,
            {"securityLevel": 2, "protocol": self._protocol},
            key,
            {"type": 0},
            for_self=True,
            include_signature=True,
            lock_position=self._lock_position,
        )

    def _prepare_inputs_meta(self, ctx: Any, key: str, outs: list) -> list:
        """Prepare the inputs metadata for the set operation."""
        pd = PushDrop(self._wallet, self._originator)
        unlock_iface = pd.unlock({"securityLevel": 2, "protocol": self._protocol}, key, {"type": 0}, sign_outputs='all')
        inputs_meta = []
        for o in outs:
            outpoint = {
                "txid": bytes.fromhex(o.get("txid", "")) if isinstance(o.get("txid"), str) and len(o.get("txid")) == 64 else (o.get("txid") or b"\x00" * 32),
                "index": int(o.get("outputIndex", 0)),
            }
            try:
                # unlock_iface exposes estimateLength only
                max_len = unlock_iface.estimateLength()
            except Exception:
                max_len = 73 + 2
            inputs_meta.append({
                "outpoint": outpoint,
                "unlockingScriptLength": max_len,
                "inputDescription": o.get("outputDescription", "Previous key-value token"),
                "sequenceNumber": 0,
            })
        return inputs_meta

    def remove(self, ctx: Any, key: str) -> List[str]:  # noqa: N802
        if not key:
            raise ErrInvalidKey(KEY_EMPTY_MSG)
        removed: List[str] = []
        loop_guard = 0
        last_count = None
        while True:
            if loop_guard > 10:
                break
            loop_guard += 1
            outs, input_beef = self._lookup_outputs_for_remove(ctx, key)
            count = len(outs)
            if count == 0:
                break
            if last_count is not None and count >= last_count:
                break
            last_count = count
            inputs_meta = self._prepare_inputs_meta(ctx, key, outs)
            self._onchain_remove_flow(ctx, key, inputs_meta, input_beef)
            removed.append(f"removed:{key}")
        self._update_local_cache_after_remove(key, removed)
        return removed

    def _lookup_outputs_for_remove(self, ctx: Any, key: str) -> tuple[list, bytes]:
        """Lookup outputs and BEEF for remove operation."""
        lo = self._wallet.list_outputs(ctx, {
            "basket": self._context,
            "tags": [key],
            "include": ENTIRE_TXS,
            "limit": 100,
        }, self._originator) or {}
        outs = lo.get("outputs") or []
        input_beef = lo.get("BEEF") or b""
        return outs, input_beef

    def _onchain_remove_flow(self, ctx: Any, key: str, inputs_meta: list, input_beef: bytes) -> None:
        """Perform the on-chain flow for remove: create_action, sign_action, internalize_action."""
        ca_res = self._wallet.create_action(ctx, {
            "labels": ["kv", "remove"],
            "description": f"kvstore remove {key}",
            "inputs": inputs_meta,
            "inputBEEF": input_beef,
            "outputs": [],
        }, self._originator) or {}
        signable = (ca_res.get("signableTransaction") or {}) if isinstance(ca_res, dict) else {}
        signable_tx_bytes = signable.get("tx") or b""
        reference = signable.get("reference") or b""
        spends = self._prepare_spends(ctx, key, inputs_meta, signable_tx_bytes, input_beef, [])
        spends_str = {str(int(k)): v for k, v in (spends or {}).items()}
        res = self._wallet.sign_action(ctx, {"spends": spends_str, "reference": reference}, self._originator) or {}
        signed_tx_bytes = res.get("tx") if isinstance(res, dict) else None
        self._wallet.internalize_action(ctx, {"tx": signed_tx_bytes or signable_tx_bytes}, self._originator)

    def _update_local_cache_after_remove(self, key: str, removed: list) -> None:
        """Update the local cache after remove operation."""
        with self._lock:
            if key in self._store:
                del self._store[key]
        if not removed:
            removed.append(f"removed:{key}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _prepare_spends(
        self,
        ctx: Any,
        key: str,
        inputs: List[dict],
        signable_tx_bytes: bytes,
        input_beef: bytes | None = None,
        outs: List[dict] | None = None,
    ) -> Dict[int, Dict[str, bytes]]:
        """Generate spends map {inputIndex: {unlockingScript}} using PushDropUnlocker.

        Mirrors the Go flow:
          - Parse provided InputBEEF to enable input linking (best-effort)
          - Parse signable tx bytes to compute txid (best-effort)
          - Produce unlocking scripts per input using the PushDrop unlocker
        """
        # Parse BEEF to enable prevout context lookup and input linking
        beef = None
        try:
            if input_beef:
                from bsv.transaction import parse_beef_ex as _parse_beef_ex
                beef, _, _ = _parse_beef_ex(input_beef)
        except Exception:
            beef = None

        # Decode signable tx for BIP143 preimage path
        tx_obj_for_signing = None
        try:
            if signable_tx_bytes:
                from bsv.transaction import Transaction as _Tx
                from bsv.utils import Reader as _Reader
                tx_obj_for_signing = _Tx.from_reader(_Reader(signable_tx_bytes))
        except Exception:
            tx_obj_for_signing = None

        pd = PushDrop(self._wallet, self._originator)

        spends: Dict[int, Dict[str, bytes]] = {}
        outs = outs or []
        # Quick lookup for provided outs by (txid, index)
        out_map: Dict[tuple, dict] = {}
        for o in outs:
            try:
                out_map[(o.get("txid"), int(o.get("outputIndex", 0)))] = o
            except Exception:
                pass

        for idx, meta in enumerate(inputs or []):
            prev_txid_hex: str | None = None
            prev_vout: int | None = None
            prev_satoshis: int | None = None
            prev_locking_script: bytes | None = None
            try:
                outpoint = meta.get("outpoint") or meta.get("Outpoint")
                if outpoint and isinstance(outpoint, dict):
                    txid = outpoint.get("txid")
                    prev_vout = int(outpoint.get("index", 0))
                    if isinstance(txid, (bytes, bytearray)):
                        prev_txid_hex = bytes(txid)[::-1].hex()
                    elif isinstance(txid, str) and len(txid) == 64:
                        prev_txid_hex = txid
                    # Try BEEF
                    if beef and prev_txid_hex:
                        btx = beef.find_transaction(prev_txid_hex)
                        if btx and getattr(btx, "tx_obj", None):
                            ptx = btx.tx_obj
                            if 0 <= (prev_vout or 0) < len(ptx.outputs):
                                prev_satoshis = getattr(ptx.outputs[prev_vout], "satoshis", None) or getattr(ptx.outputs[prev_vout], "value", None)
                                ls_obj = getattr(ptx.outputs[prev_vout], "locking_script", None) or getattr(ptx.outputs[prev_vout], "script", None)
                                prev_locking_script = ls_obj.serialize() if hasattr(ls_obj, "serialize") else (
                                    bytes.fromhex(ls_obj) if isinstance(ls_obj, str) else (ls_obj or b"")
                                )
                    # Fallback to provided outs
                    key_t = (prev_txid_hex, int(prev_vout or 0))
                    if key_t in out_map and (prev_satoshis is None or prev_locking_script is None):
                        o = out_map[key_t]
                        prev_satoshis = int(o.get("satoshis", 0))
                        ls_hex = o.get("lockingScript")
                        prev_locking_script = bytes.fromhex(ls_hex) if isinstance(ls_hex, str) else (ls_hex or b"")
            except Exception:
                prev_txid_hex = prev_txid_hex

            unlock_iface = pd.unlock(
                {"securityLevel": 2, "protocol": self._protocol},
                key,
                {"type": 0},
                prev_txid=prev_txid_hex,
                prev_vout=prev_vout,
                prev_satoshis=prev_satoshis,
                prev_locking_script=prev_locking_script,
            )

            to_sign = tx_obj_for_signing if tx_obj_for_signing is not None else signable_tx_bytes
            unlocking_script = unlock_iface.sign(ctx, to_sign, int(idx))
            spends[int(idx)] = {"unlockingScript": unlocking_script, "sequenceNumber": 0}

        return spends

    # ------------------------------------------------------------------
    # Introspection helpers
    # ------------------------------------------------------------------

    @classmethod
    def get_unimplemented_features(cls) -> List[str]:
        """Return a *copy* of the list enumerating missing capabilities."""
        return list(cls._UNIMPLEMENTED)


ENTIRE_TXS = "entire transactions"
KEY_EMPTY_MSG = "key cannot be empty"

