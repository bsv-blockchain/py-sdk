from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Any, Dict, List, Optional, Tuple, Union, cast

from bsv.broadcasters import default_broadcaster
from bsv.overlay.lookup import LookupQuestion, LookupResolver
from bsv.overlay.topic import BroadcasterConfig, TopicBroadcaster
from bsv.registry.types import (
    BasketDefinitionData,
    CertificateDefinitionData,
    DefinitionData,
    DefinitionType,
    ProtocolDefinitionData,
    TokenData,
)
from bsv.transaction import Transaction
from bsv.transaction.pushdrop import (
    SignOutputsMode,
    build_lock_before_pushdrop,
    decode_lock_before_pushdrop,
    make_pushdrop_unlocker,
)
from bsv.utils import Reader
from bsv.wallet.key_deriver import Protocol as WalletProtocol
from bsv.wallet.wallet_interface import WalletInterface

REGISTRANT_TOKEN_AMOUNT = 1


def _map_definition_type_to_wallet_protocol(definition_type: DefinitionType) -> dict[str, Any]:
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


def _build_pushdrop_fields(data: DefinitionData, registry_operator: str) -> list[bytes]:
    if isinstance(data, BasketDefinitionData):
        fields = [
            data.basket_id,
            data.name,
            data.icon_url,
            data.description,
            data.documentation_url,
        ]
    elif isinstance(data, ProtocolDefinitionData):
        import json

        fields = [
            json.dumps(data.protocol_id),
            data.name,
            data.icon_url,
            data.description,
            data.documentation_url,
        ]
    elif isinstance(data, CertificateDefinitionData):
        import json

        fields = [
            data.type,
            data.name,
            data.icon_url,
            data.description,
            data.documentation_url,
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

    fields: list[bytes] = cast(list[bytes], decoded["fields"])

    # Expect last field is registry operator
    if definition_type == "basket":
        if len(fields) != 6:
            raise ValueError("Unexpected field count for basket type")
        return BasketDefinitionData(
            definition_type="basket",
            basket_id=fields[0].decode(),
            name=fields[1].decode(),
            icon_url=fields[2].decode(),
            description=fields[3].decode(),
            documentation_url=fields[4].decode(),
            registry_operator=fields[5].decode(),
        )
    if definition_type == "protocol":
        if len(fields) != 6:
            raise ValueError("Unexpected field count for protocol type")
        import json

        return ProtocolDefinitionData(
            definition_type="protocol",
            protocol_id=json.loads(fields[0].decode()),
            name=fields[1].decode(),
            icon_url=fields[2].decode(),
            description=fields[3].decode(),
            documentation_url=fields[4].decode(),
            registry_operator=fields[5].decode(),
        )
    if definition_type == "certificate":
        if len(fields) != 7:
            raise ValueError("Unexpected field count for certificate type")
        import json

        parsed_fields: dict[str, Any]
        try:
            parsed_fields = json.loads(fields[5].decode())
        except Exception:
            parsed_fields = {}
        return CertificateDefinitionData(
            definition_type="certificate",
            type=fields[0].decode(),
            name=fields[1].decode(),
            icon_url=fields[2].decode(),
            description=fields[3].decode(),
            documentation_url=fields[4].decode(),
            fields=cast(dict[str, Any], parsed_fields),
            registry_operator=fields[6].decode(),
        )
    raise ValueError(f"Unsupported definition type: {definition_type}")


class RegistryClient:
    def __init__(self, wallet: WalletInterface, originator: str = "registry-client") -> None:
        self.wallet = wallet
        self.originator = originator
        self._resolver = LookupResolver()

    def register_definition(self, _ctx: Any, data: DefinitionData) -> dict[str, Any]:
        pub = self.wallet.get_public_key({"identityKey": True}, self.originator) or {}
        operator = cast(str, pub.get("publicKey") or "")

        _ = _map_definition_type_to_wallet_protocol(
            data.definition_type
        )  # Validate definition_type; mapping reserved for future use
        fields = _build_pushdrop_fields(data, operator)

        # Build lock-before pushdrop script
        from bsv.keys import PublicKey

        op_bytes = PublicKey(operator).serialize(compressed=True)
        locking_script_bytes = build_lock_before_pushdrop(fields, op_bytes, include_signature=False)

        # Create transaction
        randomize_outputs = False
        ca_res = (
            self.wallet.create_action(
                {
                    "description": f"Register a new {data.definition_type} item",
                    "outputs": [
                        {
                            "satoshis": REGISTRANT_TOKEN_AMOUNT,
                            "lockingScript": locking_script_bytes,
                            "outputDescription": f"New {data.definition_type} registration token",
                            "basket": _map_definition_type_to_basket_name(data.definition_type),
                        }
                    ],
                    "options": {"randomizeOutputs": randomize_outputs},
                },
                self.originator,
            )
            or {}
        )

        # For now, return create_action-like structure; broadcasting can be done by caller via Transaction.broadcast
        return ca_res

    def list_own_registry_entries(self, _ctx: Any, definition_type: DefinitionType) -> list[dict[str, Any]]:
        include_instructions = True
        include_tags = True
        include_labels = True
        lo = (
            self.wallet.list_outputs(
                {
                    "basket": _map_definition_type_to_basket_name(definition_type),
                    "include": "entire transactions",
                    "includeCustomInstructions": include_instructions,
                    "includeTags": include_tags,
                    "includeLabels": include_labels,
                },
                self.originator,
            )
            or {}
        )

        outputs = cast(list[dict[str, Any]], lo.get("outputs") or [])
        beef = cast(bytes, lo.get("BEEF") or b"")
        results: list[dict[str, Any]] = []
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

    def revoke_own_registry_entry(self, ctx: Any, record: dict[str, Any]) -> dict[str, Any]:
        """Revoke a registry entry owned by this wallet."""
        self._validate_ownership(record)
        txid, output_index, beef, satoshis = self._extract_record_data(record)

        ca_res = self._create_revocation_transaction(txid, output_index, beef, record)
        sign_res = self._sign_revocation_transaction(ca_res, txid, output_index, satoshis, record)

        self._broadcast_revocation_transaction(ctx, sign_res, record)
        return sign_res

    def _validate_ownership(self, record: dict[str, Any]) -> None:
        """Validate that this wallet owns the registry token."""
        me = self.wallet.get_public_key({"identityKey": True}, self.originator) or {}
        my_pub = cast(str, me.get("publicKey") or "")
        operator = cast(str, record.get("registryOperator") or "")
        if operator and my_pub and operator.lower() != my_pub.lower():
            raise ValueError("this registry token does not belong to the current wallet")

    def _extract_record_data(self, record: dict[str, Any]) -> tuple[str, int, bytes, int]:
        """Extract required data from registry record."""
        txid = cast(str, record.get("txid") or "")
        output_index = int(record.get("outputIndex") or 0)
        beef = cast(bytes, record.get("beef") or b"")
        satoshis = int(record.get("satoshis") or 0)

        if not txid or not beef:
            raise ValueError("Invalid registry record - missing txid or beef")

        return txid, output_index, beef, satoshis

    def _create_revocation_transaction(
        self, txid: str, output_index: int, beef: bytes, record: dict[str, Any]
    ) -> dict[str, Any]:
        """Create the partial revocation transaction."""
        return (
            self.wallet.create_action(
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
            )
            or {}
        )

    def _sign_revocation_transaction(
        self, ca_res: dict[str, Any], txid: str, output_index: int, satoshis: int, record: dict[str, Any]
    ) -> dict[str, Any]:
        """Sign the revocation transaction."""
        signable = cast(dict[str, Any], (ca_res.get("signableTransaction") or {}))
        reference = signable.get("reference") or b""

        from bsv.utils import Reader

        tx_bytes = cast(bytes, signable.get("tx") or b"")
        partial_tx = Transaction.from_reader(Reader(tx_bytes)) if tx_bytes else Transaction()

        unlocker = self._create_revocation_unlocker(txid, output_index, satoshis, record)
        unlocking_script = unlocker.sign(partial_tx, 0)

        spends = {0: {"unlockingScript": unlocking_script}}
        return (
            self.wallet.sign_action(
                {
                    "reference": reference,
                    "spends": spends,
                    "tx": tx_bytes,
                    "options": {"acceptDelayedBroadcast": False},
                },
                self.originator,
            )
            or {}
        )

    def _create_revocation_unlocker(self, txid: str, output_index: int, satoshis: int, record: dict[str, Any]):
        """Create unlocker for the revocation transaction."""
        return make_pushdrop_unlocker(
            self.wallet,
            protocol_id=_map_definition_type_to_wallet_protocol(
                cast(DefinitionType, record.get("definitionType", "basket"))
            ),
            key_id="1",
            counterparty={"type": 2},  # anyone
            sign_outputs_mode=SignOutputsMode.ALL,
            anyone_can_pay=False,
            prev_txid=txid,
            prev_vout=output_index,
            prev_satoshis=satoshis,
            prev_locking_script=(
                bytes.fromhex(cast(str, record.get("lockingScript", ""))) if record.get("lockingScript") else None
            ),
        )

    def _broadcast_revocation_transaction(self, ctx: Any, sign_res: dict[str, Any], record: dict[str, Any]) -> None:
        """Broadcast the signed revocation transaction."""
        tx_bytes = cast(bytes, sign_res.get("tx") or b"")
        if not tx_bytes:
            return

        try:
            tx = Transaction.from_reader(Reader(tx_bytes))
            topic = self._get_broadcast_topic(record)
            network_preset = self._get_network_preset(ctx)
            tb = TopicBroadcaster([topic], BroadcasterConfig(network_preset))
            tb.sync_broadcast(tx)
        except Exception as e:
            logging.warning(f"Broadcast failed for registry record: {e}")

    def _get_broadcast_topic(self, record: dict[str, Any]) -> str:
        """Get the broadcast topic for the registry type."""
        topic_map = {
            "basket": "tm_basketmap",
            "protocol": "tm_protomap",
            "certificate": "tm_certmap",
        }
        return topic_map.get(cast(str, record.get("definitionType", "basket")), "tm_basketmap")

    def _get_network_preset(self, ctx: Any) -> str:
        """Get the network preset from wallet."""
        net_res = self.wallet.get_network(ctx, {}, self.originator) or {}
        return cast(str, net_res.get("network") or "mainnet")

    def resolve(
        self, ctx: Any, definition_type: DefinitionType, query: dict[str, Any], resolver: Any | None = None
    ) -> list[DefinitionData]:
        """Resolve registry records using a provided resolver compatible with TS/Go.

        Resolver signature: resolver(ctx, service_name: str, query: Dict) -> List[{"beef": bytes, "outputIndex": int}]
        Service names: ls_basketmap | ls_protomap | ls_certmap
        """
        if resolver is None:
            return []

        service_name = {"basket": "ls_basketmap", "protocol": "ls_protomap", "certificate": "ls_certmap"}[
            definition_type
        ]
        self._resolver.set_backend(resolver)
        ans = self._resolver.query(ctx, LookupQuestion(service=service_name, query=query))
        outputs = [{"beef": o.beef, "outputIndex": o.outputIndex} for o in ans.outputs]
        parsed: list[DefinitionData] = []
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
            parsed = [r for r in parsed if getattr(r, "basket_id", None) == query.get("basketID")]
        return parsed
