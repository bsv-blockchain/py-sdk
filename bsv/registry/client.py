from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, List, Optional, Tuple, Union, cast

from bsv.registry.types import (
    DefinitionType,
    BasketDefinitionData,
    ProtocolDefinitionData,
    CertificateDefinitionData,
    DefinitionData,
    TokenData,
)
from bsv.wallet.wallet_interface import WalletInterface
from bsv.wallet.key_deriver import Protocol as WalletProtocol
from bsv.transaction.pushdrop import (
    build_lock_before_pushdrop,
    decode_lock_before_pushdrop,
    make_pushdrop_unlocker,
    SignOutputsMode,
)
from bsv.transaction import Transaction
from bsv.broadcasters import default_broadcaster
from bsv.overlay.lookup import LookupResolver, LookupQuestion
from bsv.overlay.topic import TopicBroadcaster, BroadcasterConfig


REGISTRANT_TOKEN_AMOUNT = 1


def _map_definition_type_to_wallet_protocol(definition_type: DefinitionType) -> Dict[str, Any]:
    if definition_type == "basket":
        return {"securityLevel": 1, "protocol": "basketmap"}
    if definition_type == "protocol":
        return {"securityLevel": 1, "protocol": "protomap"}
    if definition_type == "certificate":
        return {"securityLevel": 1, "protocol": "certmap"}
    raise ValueError(f"Unknown definition type: {definition_type}")


def _map_definition_type_to_basket_name(definition_type: DefinitionType) -> str:
    return {
        "basket": "basketmap",
        "protocol": "protomap",
        "certificate": "certmap",
    }[definition_type]


def _build_pushdrop_fields(data: DefinitionData, registry_operator: str) -> List[bytes]:
    if isinstance(data, BasketDefinitionData):
        fields = [
            data.basketID,
            data.name,
            data.iconURL,
            data.description,
            data.documentationURL,
        ]
    elif isinstance(data, ProtocolDefinitionData):
        import json

        fields = [
            json.dumps(data.protocolID),
            data.name,
            data.iconURL,
            data.description,
            data.documentationURL,
        ]
    elif isinstance(data, CertificateDefinitionData):
        import json

        fields = [
            data.type,
            data.name,
            data.iconURL,
            data.description,
            data.documentationURL,
            json.dumps(data.fields),
        ]
    else:
        raise ValueError("Unsupported definition type")

    fields.append(registry_operator)
    return [f.encode("utf-8") for f in fields]


def _parse_locking_script(definition_type: DefinitionType, locking_script_hex: str) -> DefinitionData:
    from bsv.script.script import Script

    script = Script(locking_script_hex)
    decoded = decode_lock_before_pushdrop(script.serialize())
    if not decoded or not decoded.get("fields"):
        raise ValueError("Not a valid registry pushdrop script")

    fields: List[bytes] = cast(List[bytes], decoded["fields"])

    # Expect last field is registry operator
    if definition_type == "basket":
        if len(fields) != 6:
            raise ValueError("Unexpected field count for basket type")
        return BasketDefinitionData(
            definitionType="basket",
            basketID=fields[0].decode(),
            name=fields[1].decode(),
            iconURL=fields[2].decode(),
            description=fields[3].decode(),
            documentationURL=fields[4].decode(),
            registryOperator=fields[5].decode(),
        )
    if definition_type == "protocol":
        if len(fields) != 6:
            raise ValueError("Unexpected field count for protocol type")
        import json

        return ProtocolDefinitionData(
            definitionType="protocol",
            protocolID=json.loads(fields[0].decode()),
            name=fields[1].decode(),
            iconURL=fields[2].decode(),
            description=fields[3].decode(),
            documentationURL=fields[4].decode(),
            registryOperator=fields[5].decode(),
        )
    if definition_type == "certificate":
        if len(fields) != 7:
            raise ValueError("Unexpected field count for certificate type")
        import json

        parsed_fields: Dict[str, Any]
        try:
            parsed_fields = json.loads(fields[5].decode())
        except Exception:
            parsed_fields = {}
        return CertificateDefinitionData(
            definitionType="certificate",
            type=fields[0].decode(),
            name=fields[1].decode(),
            iconURL=fields[2].decode(),
            description=fields[3].decode(),
            documentationURL=fields[4].decode(),
            fields=cast(Dict[str, Any], parsed_fields),
            registryOperator=fields[6].decode(),
        )
    raise ValueError(f"Unsupported definition type: {definition_type}")


class RegistryClient:
    def __init__(self, wallet: WalletInterface, originator: str = "registry-client") -> None:
        self.wallet = wallet
        self.originator = originator
        self._resolver = LookupResolver()

    def register_definition(self, ctx: Any, data: DefinitionData) -> Dict[str, Any]:
        pub = self.wallet.get_public_key(ctx, {"identityKey": True}, self.originator) or {}
        operator = cast(str, pub.get("publicKey") or "")

        protocol = _map_definition_type_to_wallet_protocol(data.definitionType)
        fields = _build_pushdrop_fields(data, operator)

        # Build lock-before pushdrop script
        from bsv.keys import PublicKey

        op_bytes = PublicKey(operator).serialize(compressed=True)
        locking_script_bytes = build_lock_before_pushdrop(fields, op_bytes, include_signature=False)

        # Create transaction
        randomize_outputs = False
        ca_res = self.wallet.create_action(
            ctx,
            {
                "description": f"Register a new {data.definitionType} item",
                "outputs": [
                    {
                        "satoshis": REGISTRANT_TOKEN_AMOUNT,
                        "lockingScript": locking_script_bytes,
                        "outputDescription": f"New {data.definitionType} registration token",
                        "basket": _map_definition_type_to_basket_name(data.definitionType),
                    }
                ],
                "options": {"randomizeOutputs": randomize_outputs},
            },
            self.originator,
        ) or {}

        # For now, return create_action-like structure; broadcasting can be done by caller via Transaction.broadcast
        return ca_res

    def list_own_registry_entries(self, ctx: Any, definition_type: DefinitionType) -> List[Dict[str, Any]]:
        include_instructions = True
        include_tags = True
        include_labels = True
        lo = self.wallet.list_outputs(
            ctx,
            {
                "basket": _map_definition_type_to_basket_name(definition_type),
                "include": "entire transactions",
                "includeCustomInstructions": include_instructions,
                "includeTags": include_tags,
                "includeLabels": include_labels,
            },
            self.originator,
        ) or {}

        outputs = cast(List[Dict[str, Any]], lo.get("outputs") or [])
        beef = cast(bytes, lo.get("BEEF") or b"")
        results: List[Dict[str, Any]] = []
        if not outputs or not beef:
            return results

        try:
            tx = Transaction.from_beef(beef)
        except Exception:
            return results

        for out in outputs:
            if not out.get("spendable", False):
                continue
            idx = int(out.get("outputIndex", 0))
            try:
                ls_hex = tx.outputs[idx].locking_script.hex()
            except Exception:
                continue
            try:
                record = _parse_locking_script(definition_type, ls_hex)
            except Exception:
                continue
            # Merge with token data
            results.append(
                {
                    **asdict(record),
                    "txid": out.get("txid", ""),
                    "outputIndex": idx,
                    "satoshis": int(out.get("satoshis", 0)),
                    "lockingScript": ls_hex,
                    "beef": beef,
                }
            )

        return results

    def revoke_own_registry_entry(self, ctx: Any, record: Dict[str, Any]) -> Dict[str, Any]:
        # Owner check: ensure this wallet controls the registry operator key
        me = self.wallet.get_public_key(ctx, {"identityKey": True}, self.originator) or {}
        my_pub = cast(str, me.get("publicKey") or "")
        operator = cast(str, record.get("registryOperator") or "")
        if operator and my_pub and operator.lower() != my_pub.lower():
            raise ValueError("this registry token does not belong to the current wallet")

        txid = cast(str, record.get("txid") or "")
        output_index = int(record.get("outputIndex") or 0)
        beef = cast(bytes, record.get("beef") or b"")
        satoshis = int(record.get("satoshis") or 0)
        if not txid or not beef:
            raise ValueError("Invalid registry record - missing txid or beef")

        # Create partial transaction that spends the registry UTXO
        ca_res = self.wallet.create_action(
            ctx,
            {
                "description": f"Revoke {record.get('definitionType', 'registry')} item",
                "inputBEEF": beef,
                "inputs": [
                    {
                        "outpoint": f"{txid}.{output_index}",
                        "unlockingScriptLength": 73,
                        "inputDescription": "Revoking registry token",
                    }
                ],
            },
            self.originator,
        ) or {}

        signable = cast(Dict[str, Any], (ca_res.get("signableTransaction") or {}))
        reference = signable.get("reference") or b""

        # Build a real unlocker and sign the partial transaction input
        # signableTransaction.tx is expected to be raw tx bytes (WalletWire signable), not BEEF
        # signable["tx"] holds raw transaction bytes; use from_reader for consistency with WalletImpl
        from bsv.utils import Reader
        tx_bytes = cast(bytes, signable.get("tx") or b"")
        partial_tx = Transaction.from_reader(Reader(tx_bytes)) if tx_bytes else Transaction()
        unlocker = make_pushdrop_unlocker(
            self.wallet,
            protocol_id=_map_definition_type_to_wallet_protocol(cast(DefinitionType, record.get("definitionType", "basket"))),
            key_id="1",
            counterparty={"type": 2},  # anyone
            sign_outputs_mode=SignOutputsMode.ALL,
            anyone_can_pay=False,
            prev_txid=txid,
            prev_vout=output_index,
            prev_satoshis=satoshis,
            prev_locking_script=bytes.fromhex(cast(str, record.get("lockingScript", ""))) if record.get("lockingScript") else None,
        )
        unlocking_script = unlocker.sign(ctx, partial_tx, 0)

        spends = {0: {"unlockingScript": unlocking_script}}
        sign_res = self.wallet.sign_action(
            ctx,
            {
                "reference": reference,
                "spends": spends,
                "tx": tx_bytes,
                "options": {"acceptDelayedBroadcast": False},
            },
            self.originator,
        ) or {}

        # Broadcast via default broadcaster if tx present
        tx_bytes = cast(bytes, sign_res.get("tx") or tx_bytes)
        if tx_bytes:
            try:
                tx = Transaction.from_reader(Reader(tx_bytes))
                # Broadcast via topic mapping (tm_*) using TopicBroadcaster
                topic_map = {
                    "basket": "tm_basketmap",
                    "protocol": "tm_protomap",
                    "certificate": "tm_certmap",
                }
                topic = topic_map.get(cast(str, record.get("definitionType", "basket")), "tm_basketmap")
                # network preset from wallet
                net_res = self.wallet.get_network(ctx, {}, self.originator) or {}
                network_preset = cast(str, net_res.get("network") or "mainnet")
                tb = TopicBroadcaster([topic], BroadcasterConfig(network_preset))
                try:
                    tb.sync_broadcast(tx)
                except Exception:
                    pass
            except Exception:
                pass
        return sign_res

    def resolve(self, ctx: Any, definition_type: DefinitionType, query: Dict[str, Any], resolver: Optional[Any] = None) -> List[DefinitionData]:
        """Resolve registry records using a provided resolver compatible with TS/Go.

        Resolver signature: resolver(ctx, service_name: str, query: Dict) -> List[{"beef": bytes, "outputIndex": int}]
        Service names: ls_basketmap | ls_protomap | ls_certmap
        """
        if resolver is None:
            return []

        service_name = {"basket": "ls_basketmap", "protocol": "ls_protomap", "certificate": "ls_certmap"}[definition_type]
        self._resolver.set_backend(resolver)
        ans = self._resolver.query(ctx, LookupQuestion(service=service_name, query=query))
        outputs = [{"beef": o.beef, "outputIndex": o.outputIndex} for o in ans.outputs]
        parsed: List[DefinitionData] = []
        for o in outputs:
            try:
                tx = Transaction.from_beef(cast(bytes, o.get("beef") or b""))
                idx = int(o.get("outputIndex") or 0)
                ls_hex = tx.outputs[idx].locking_script.hex()
                rec = _parse_locking_script(definition_type, ls_hex)
                parsed.append(rec)
            except Exception:
                continue
        if parsed:
            return parsed
        # Fallback: use list_own_registry_entries and re-parse locking scripts
        own = self.list_own_registry_entries(ctx, definition_type)
        for it in own:
            try:
                ls_hex = cast(str, it.get("lockingScript", ""))
                rec = _parse_locking_script(definition_type, ls_hex)
                parsed.append(rec)
            except Exception:
                continue
        # Apply simple filters if present
        if definition_type == "basket" and "basketID" in query:
            parsed = [r for r in parsed if getattr(r, "basketID", None) == query.get("basketID")]
        return parsed


