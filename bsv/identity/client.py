from typing import Optional, List, Dict, Any, Tuple
import base64
from .types import (
    DisplayableIdentity, IdentityClientOptions, CertificateFieldNameUnder50Bytes, OriginatorDomainNameStringUnder250Bytes
)
from bsv.wallet.wallet_interface import WalletInterface

class IdentityClient:
    def __init__(self, wallet: Optional[WalletInterface] = None, options: Optional[IdentityClientOptions] = None, originator: OriginatorDomainNameStringUnder250Bytes = ""):
        if wallet is None:
            from bsv.wallet.wallet_impl import WalletImpl
            from bsv.keys import PrivateKey
            private_key = PrivateKey()  # Generates a random private key
            wallet = WalletImpl(private_key)
        self.wallet = wallet
        self.options = options or IdentityClientOptions()
        self.originator = originator

    def _reveal_fields_from_master_certificate(self, certificate, fields_to_reveal):
        from bsv.auth.master_certificate import MasterCertificate
        revealed = {}
        cert_fields = getattr(certificate, 'fields', {}) or {}
        master_keyring = getattr(certificate, 'master_keyring', None)
        certifier = getattr(certificate, 'certifier', None)
        if master_keyring is not None and cert_fields:
            try:
                decrypted = MasterCertificate.decrypt_fields(
                    self.wallet,
                    master_keyring,
                    cert_fields,
                    counterparty=certifier,
                    privileged=False,
                    privileged_reason=None,
                )
                for f in fields_to_reveal:
                    if f in decrypted:
                        revealed[f] = decrypted[f]
            except Exception:
                pass
        return revealed

    def _reveal_fields_from_dict(self, certificate, fields_to_reveal):
        revealed = {}
        decrypted = certificate.get('decryptedFields') or {}
        for f in fields_to_reveal:
            if f in decrypted:
                revealed[f] = decrypted[f]
        return revealed

    def _build_outputs_for_reveal(self, revealed):
        from bsv.transaction.pushdrop import build_pushdrop_locking_script
        pd_items: List[str] = ["identity.reveal"]
        for k, v in revealed.items():
            pd_items.append(k)
            pd_items.append(v)
        locking_script = build_pushdrop_locking_script(pd_items)
        description = "identity attribute revelation"
        labels = ["identity", "reveal"]
        outputs = [{
            "satoshis": int(self.options.token_amount or 1),
            "lockingScript": locking_script,
            "outputDescription": "identity.reveal",
            "basket": "",
            "tags": ["identity", "reveal"],
        }]
        return labels, description, outputs

    def publicly_reveal_attributes(self, ctx: Any, certificate: Any, fields_to_reveal: List[CertificateFieldNameUnder50Bytes]):
        """
        Reveals some specified certificate attributes publicly (generates transaction, broadcast, etc.).
        Simplified: Extracts specified fields as plaintext, formats them as transaction output metadata, and sends (mock WalletImpl compatible).
        In the future: PushDrop scripting and integration with encryption/certificate workflows.
        """
        if self.wallet is None:
            raise ValueError("wallet is required")
        revealed: Dict[str, str] = {}
        try:
            from bsv.auth.master_certificate import MasterCertificate
            if isinstance(certificate, MasterCertificate):
                revealed = self._reveal_fields_from_master_certificate(certificate, fields_to_reveal)
            # Fallback: Case where plaintext is already provided (e.g., dict with decryptedFields)
            if not revealed and isinstance(certificate, dict):
                revealed = self._reveal_fields_from_dict(certificate, fields_to_reveal)
        except Exception:
            pass
        # 2) Create action → sign → internalize (mock WalletImpl compatible)
        labels, description, outputs = self._build_outputs_for_reveal(revealed)
        create_args = {"labels": labels, "description": description, "outputs": outputs}
        _ = self.wallet.create_action(ctx, create_args, self.originator)
        _ = self.wallet.sign_action(ctx, {}, self.originator)
        result = self.wallet.internalize_action(ctx, {}, self.originator)
        return {"revealed": revealed, **(result or {})}

    def publicly_reveal_attributes_simple(self, ctx: Any, certificate: Any, fields_to_reveal: List[CertificateFieldNameUnder50Bytes]) -> str:
        """
        Equivalent to the simple API in TypeScript/Go. Returns only the transaction ID.
        """
        res = self.publicly_reveal_attributes(ctx, certificate, fields_to_reveal)
        # In the mock implementation, returns a zero TXID because actual txid cannot be obtained
        return "00" * 32

    def resolve_by_identity_key(self, ctx: Any, args: Dict) -> List[DisplayableIdentity]:
        """
        Resolves certificates linked to the specified identity key and returns them as a DisplayableIdentity list.
        Connects to discover_by_identity_key in wallet/substrates.
        args: { 'identityKey': bytes|hex-str, 'limit'?: int, 'offset'?: int, 'seekPermission'?: bool }
        """
        if self.wallet is None:
            return []
        try:
            # Call via Wallet wire transceiver
            from bsv.wallet.substrates.wallet_wire_transceiver import WalletWireTransceiver
            # In most implementations, wallet is expected to have direct methods (WalletImpl standard). If not, can switch to transceiver as fallback.
            if hasattr(self.wallet, 'discover_by_identity_key'):
                result = self.wallet.discover_by_identity_key(ctx, args, self.originator)
            else:
                # Fallback: For future extension using transceiver (not currently supported)
                return []
            # Expected structure: { 'totalCertificates': int, 'certificates': [ { 'certificateBytes': bytes, 'certifierInfo': {...}, 'publiclyRevealedKeyring': {}, 'decryptedFields': {} } ] }
            certs = (result or {}).get('certificates', [])
            identities: List[DisplayableIdentity] = []
            from bsv.transaction.pushdrop import parse_pushdrop_locking_script, parse_identity_reveal
            for item in certs:
                # If wallet provides raw locking script, try to parse identity.reveal
                locking = item.get('lockingScript') if isinstance(item, dict) else None
                disp: DisplayableIdentity
                if isinstance(locking, (bytes, bytearray)):
                    fields = parse_identity_reveal(parse_pushdrop_locking_script(locking))
                    decrypted = self._maybe_decrypt_fields(ctx, fields)
                    disp = self._from_kv(list(decrypted.items()))
                else:
                    disp = self.parse_identity(item)
                identities.append(disp)
            return identities
        except Exception:
            return []

    def resolve_by_attributes(self, ctx: Any, args: Dict) -> List[DisplayableIdentity]:
        """
        Resolves certificates linked to the specified attributes and returns them as a DisplayableIdentity list.
        Connects to discover_by_attributes in wallet/substrates.
        args: { 'attributes': Dict[str,str], 'limit'?: int, 'offset'?: int, 'seekPermission'?: bool }
        """
        if self.wallet is None:
            return []
        try:
            if hasattr(self.wallet, 'discover_by_attributes'):
                result = self.wallet.discover_by_attributes(ctx, args, self.originator)
            else:
                return []
            certs = (result or {}).get('certificates', [])
            identities: List[DisplayableIdentity] = []
            from bsv.transaction.pushdrop import parse_pushdrop_locking_script, parse_identity_reveal
            for item in certs:
                locking = item.get('lockingScript') if isinstance(item, dict) else None
                if isinstance(locking, (bytes, bytearray)):
                    fields = parse_identity_reveal(parse_pushdrop_locking_script(locking))
                    decrypted = self._maybe_decrypt_fields(ctx, fields)
                    identities.append(self._from_kv(list(decrypted.items())))
                else:
                    identities.append(self.parse_identity(item))
            return identities
        except Exception:
            return []

    @staticmethod
    def parse_identity(identity: Any) -> DisplayableIdentity:
        """
        Generates a DisplayableIdentity from a certificate.
        Expected input: elements returned by wallet's discover_* (minimum structure).
        { 'certificateBytes': bytes, 'certifierInfo': { 'name': str?, 'iconUrl': str?, 'description': str?, 'trust': int? },
          'publiclyRevealedKeyring': dict, 'decryptedFields': dict }
        Even if fields are missing, safely supplement with default values.
        """
        try:
            decrypted = (identity or {}).get('decryptedFields', {}) if isinstance(identity, dict) else {}
            name = decrypted.get('name') or decrypted.get('displayName') or 'Unknown'
            identity_key = decrypted.get('identityKey') or ''
            # Abbreviate public key (head/tail)
            abbreviated = ''
            if isinstance(identity_key, str) and len(identity_key) >= 10:
                abbreviated = f"{identity_key[:6]}…{identity_key[-4:]}"
            certifier = (identity or {}).get('certifierInfo', {}) if isinstance(identity, dict) else {}
            avatar_url = certifier.get('iconUrl') or DisplayableIdentity().avatar_url
            badge_icon_url = DisplayableIdentity().badge_icon_url
            badge_label = DisplayableIdentity().badge_label
            return DisplayableIdentity(
                name=name,
                avatar_url=avatar_url,
                abbreviated_key=abbreviated,
                identity_key=identity_key,
                badge_icon_url=badge_icon_url,
                badge_label=badge_label,
            )
        except Exception:
            return DisplayableIdentity()

    @staticmethod
    def _from_kv(fields: List[tuple]) -> DisplayableIdentity:
        d = {k: v for k, v in (fields or [])}
        name = d.get('name') or d.get('displayName') or 'Unknown'
        identity_key = d.get('identityKey') or ''
        abbreviated = f"{identity_key[:6]}…{identity_key[-4:]}" if isinstance(identity_key, str) and len(identity_key) >= 10 else ''
        return DisplayableIdentity(
            name=name,
            avatar_url=DisplayableIdentity().avatar_url,
            abbreviated_key=abbreviated,
            identity_key=identity_key,
            badge_icon_url=DisplayableIdentity().badge_icon_url,
            badge_label=DisplayableIdentity().badge_label,
        )

    def _decrypt_field(self, ctx: Any, k: str, v: str) -> str:
        if not (isinstance(v, str) and v.startswith('enc:') and self.wallet is not None):
            return v
        try:
            import base64
            ciphertext = base64.b64decode(v[4:])
            protocol = self.options.protocol_id or {"securityLevel": 2, "protocol": (self.originator or "identity")}
            enc = {
                "protocol_id": protocol,
                "key_id": f"identity:{k}",
                "counterparty": {"type": 11},
            }
            # Prefer decoded helpers
            if hasattr(self.wallet, 'decrypt_decoded'):
                res = self.wallet.decrypt_decoded(ctx, {"encryption_args": enc, "ciphertext": ciphertext}, self.originator)
                pt = res.get("plaintext") if isinstance(res, dict) else None
            else:
                res = self.wallet.decrypt(ctx, {"encryption_args": enc, "ciphertext": ciphertext}, self.originator)
                pt = res.get("plaintext") if isinstance(res, dict) else None
            if isinstance(pt, (bytes, bytearray)):
                return pt.decode('utf-8')
        except Exception:
            pass
        return v

    def _maybe_decrypt_fields(self, ctx: Any, fields: List[Tuple[str, str]]) -> Dict[str, str]:
        """
        Decrypt values that are tagged with 'enc:' base64 ciphertext using wallet.decrypt.
        Protocol/key parameters are derived from options or sensible defaults.
        """
        result: Dict[str, str] = {}
        for k, v in fields:
            result[k] = self._decrypt_field(ctx, k, v)
        return result
