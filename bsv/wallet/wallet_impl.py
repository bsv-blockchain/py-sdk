from typing import Any, Dict, Optional, List
import os
from .wallet_interface import WalletInterface
from .key_deriver import KeyDeriver, Protocol, Counterparty, CounterpartyType
from bsv.keys import PrivateKey, PublicKey
import hashlib
import hmac
import time

class WalletImpl(WalletInterface):
    def __init__(self, private_key: PrivateKey, permission_callback=None):
        self.private_key = private_key
        self.key_deriver = KeyDeriver(private_key)
        self.public_key = private_key.public_key()
        self.permission_callback = permission_callback  # Optional[Callable[[str], bool]]
        # in-memory stores
        self._actions: List[Dict[str, Any]] = []
        self._certificates: List[Dict[str, Any]] = []

    def _check_permission(self, action: str) -> None:
        if self.permission_callback:
            allowed = self.permission_callback(action)
        else:
            # Default for CLI: Ask the user for permission
            resp = input(f"[Wallet] {action} を許可しますか？ [y/N]: ")
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
            if isinstance(inner, (bytes, str)):
                inner = PublicKey(inner)
            elif not isinstance(inner, PublicKey) and inner is not None:
                # Fallback attempt to construct from hex-like
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
                self._check_permission("公開鍵取得 (get_public_key)")
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
            seek_permission = encryption_args.get("seekPermission") or encryption_args.get("seek_permission")
            if os.getenv("BSV_DEBUG", "0") == "1":
                print(f"[DEBUG WalletImpl.encrypt] originator={originator} enc_args={encryption_args}")
            if seek_permission:
                self._check_permission("暗号化 (encrypt)")
            plaintext = args.get("plaintext")
            if plaintext is None:
                return {"error": "encrypt: plaintext is required"}
            protocol_id = encryption_args.get("protocol_id")
            key_id = encryption_args.get("key_id")
            counterparty = encryption_args.get("counterparty")
            for_self = encryption_args.get("forSelf", False)
            if protocol_id and key_id:
                if isinstance(protocol_id, dict):
                    protocol = Protocol(protocol_id.get("securityLevel", 0), protocol_id.get("protocol", ""))
                else:
                    protocol = protocol_id
                # normalize counterparty for KeyDeriver
                if isinstance(counterparty, dict):
                    inner = counterparty.get("counterparty")
                    if isinstance(inner, (bytes, str)):
                        inner = PublicKey(inner)
                    cp = Counterparty(counterparty.get("type", CounterpartyType.OTHER), inner)
                else:
                    if isinstance(counterparty, (bytes, str)):
                        cp = Counterparty(CounterpartyType.OTHER, PublicKey(counterparty))
                    elif isinstance(counterparty, PublicKey):
                        cp = Counterparty(CounterpartyType.OTHER, counterparty)
                    else:
                        cp = Counterparty(CounterpartyType.SELF)
                pubkey = self.key_deriver.derive_public_key(protocol, key_id, cp, for_self)
            else:
                if isinstance(counterparty, PublicKey):
                    pubkey = counterparty
                elif isinstance(counterparty, str):
                    pubkey = PublicKey(counterparty)
                else:
                    pubkey = self.public_key
            ciphertext = pubkey.encrypt(plaintext)
            return {"ciphertext": ciphertext}
        except Exception as e:
            return {"error": f"encrypt: {e}"}

    def decrypt(self, ctx: Any, args: Dict, originator: str) -> Dict:
        try:
            encryption_args = args.get("encryption_args", {})
            seek_permission = encryption_args.get("seekPermission") or encryption_args.get("seek_permission")
            if os.getenv("BSV_DEBUG", "0") == "1":
                print(f"[DEBUG WalletImpl.decrypt] originator={originator} enc_args={encryption_args}")
            if seek_permission:
                self._check_permission("復号 (decrypt)")
            ciphertext = args.get("ciphertext")
            if ciphertext is None:
                return {"error": "decrypt: ciphertext is required"}
            protocol_id = encryption_args.get("protocol_id")
            key_id = encryption_args.get("key_id")
            counterparty = encryption_args.get("counterparty")
            for_self = encryption_args.get("forSelf", False)
            if protocol_id and key_id:
                if isinstance(protocol_id, dict):
                    protocol = Protocol(protocol_id.get("securityLevel", 0), protocol_id.get("protocol", ""))
                else:
                    protocol = protocol_id
                # normalize counterparty (sender pub)
                if isinstance(counterparty, dict):
                    inner = counterparty.get("counterparty")
                    if isinstance(inner, (bytes, str)):
                        inner = PublicKey(inner)
                    cp = Counterparty(counterparty.get("type", CounterpartyType.OTHER), inner)
                else:
                    if isinstance(counterparty, (bytes, str)):
                        cp = Counterparty(CounterpartyType.OTHER, PublicKey(counterparty))
                    elif isinstance(counterparty, PublicKey):
                        cp = Counterparty(CounterpartyType.OTHER, counterparty)
                    else:
                        cp = Counterparty(CounterpartyType.SELF)
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
            else:
                plaintext = self.private_key.decrypt(ciphertext)
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

    def abort_action(self, *a, **k): pass
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
        # Simplified: register an action in memory and return a signable skeleton
        labels = args.get("labels") or []
        description = args.get("description", "")
        outputs = args.get("outputs") or []
        # Capture inputs meta for tests to verify unlockingScriptLength estimation
        inputs_meta = args.get("inputs") or []
        total_out = sum(int(o.get("satoshis", 0)) for o in outputs)
        action = {
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
                }
                for i, o in enumerate(outputs)
            ],
        }
        self._actions.append(action)
        # Build a naive signable transaction bytes from inputs/outputs counts for testing
        try:
            from bsv.utils import Writer
            from bsv.transaction import Transaction
            t = Transaction()
            # Populate outputs with provided lockingScript/satoshis
            for o in outputs:
                from bsv.transaction_output import TransactionOutput
                from bsv.script.script import Script
                s = Script.from_hex((o.get("lockingScript") or b"").hex()) if hasattr(Script, 'from_hex') else Script()
                to = TransactionOutput(o.get("satoshis", 0), s)
                t.add_output(to)
            signable_tx = t.serialize()
        except Exception:
            signable_tx = b"\x00"
        return {"signableTransaction": {"tx": signable_tx, "reference": b"ref"}}
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
        # Mark last action as completed (mock behavior)
        if self._actions:
            self._actions[-1]["status"] = "completed"
        return {"accepted": True}
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
        # Return outputs for the requested basket from the most recent action, and include a BEEF
        include = (args.get("include") or "").lower()
        basket = args.get("basket", "")
        outputs_desc = []
        # Find the most recent action with outputs matching the basket
        for action in reversed(self._actions):
            outs = action.get("outputs") or []
            filtered = [o for o in outs if (not basket) or (o.get("basket") == basket)]
            if filtered:
                outputs_desc = filtered
                break
        if not outputs_desc:
            # Fallback to one mock output
            outputs_desc = [
                {
                    "outputIndex": 0,
                    "satoshis": 1000,
                    "lockingScript": b"\x51",
                    "spendable": True,
                    "outputDescription": "mock",
                    "basket": basket,
                    "tags": args.get("tags", []) or [],
                    "customInstructions": None,
                }
            ]
        # Build Transaction with these outputs for BEEF inclusion; ensure locking script is the one we stored
        if os.getenv("REGISTRY_DEBUG") == "1":
            print("[DEBUG list_outputs] basket", basket, "outputs_desc", outputs_desc)
        try:
            from bsv.transaction import Transaction
            from bsv.transaction_output import TransactionOutput
            from bsv.script.script import Script
            tx = Transaction()
            for o in outputs_desc:
                ls_hex = o.get("lockingScript")
                if isinstance(ls_hex, str):
                    ls_bytes = bytes.fromhex(ls_hex)
                else:
                    ls_bytes = ls_hex or b"\x51"
                to = TransactionOutput(Script(ls_bytes), int(o.get("satoshis", 0)))
                tx.add_output(to)
            beef_bytes = tx.to_beef()
        except Exception:
            beef_bytes = b""
        # Prepare result
        result_outputs = []
        for idx, o in enumerate(outputs_desc):
            # ensure lockingScript hex string
            ls_hex = o.get("lockingScript")
            if not isinstance(ls_hex, str):
                ls_hex = (ls_hex or b"\x51").hex()

            ro = {
                "outputIndex": int(o.get("outputIndex", idx)),
                "satoshis": int(o.get("satoshis", 0)),
                "lockingScript": ls_hex,
                "spendable": True,
                "outputDescription": o.get("outputDescription", ""),
                "basket": o.get("basket", basket),
                "tags": o.get("tags") or [],
                "customInstructions": o.get("customInstructions"),
                "txid": "00" * 32,
            }
            result_outputs.append(ro)
        res = {"outputs": result_outputs}
        if "entire" in include or "transaction" in include:
            res["BEEF"] = beef_bytes
        return res
    def prove_certificate(self, ctx: Any, args: Dict, originator: str) -> Dict:
        return {"keyringForVerifier": {}, "verifier": args.get("verifier", b"")}
    def relinquish_certificate(self, ctx: Any, args: Dict, originator: str) -> Dict:
        # Remove matching certificate if present
        typ = args.get("type")
        serial = args.get("serialNumber")
        certifier = args.get("certifier")
        self._certificates = [c for c in self._certificates if not (
            c.get("match") == (typ, serial, certifier)
        )]
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
                self._check_permission("鍵リンク開示 (counterparty)")

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
                self._check_permission("鍵リンク開示 (specific)")

            return {}
        except Exception as e:
            return {"error": f"reveal_specific_key_linkage: {e}"}

    def sign_action(self, ctx: Any, args: Dict, originator: str) -> Dict:
        # Return a pseudo-signed transaction and txid
        ref = (args or {}).get("reference") or b""
        spends = (args or {}).get("spends") or {}
        body = b"signed" + ref + b";" + b";".join((spends.get(i, {}).get("unlockingScript", b"") for i in sorted(spends)))
        fake_txid = hashlib.sha256(body).digest()[::-1]
        return {"tx": body, "txid": fake_txid}
    def wait_for_authentication(self, ctx: Any, args: Dict, originator: str) -> Dict:
        return {"authenticated": True}
