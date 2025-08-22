from __future__ import annotations

from typing import Any, Dict, List, Optional, cast
import os

from bsv.registry.types import DefinitionType
from bsv.registry.client import _parse_locking_script
from bsv.transaction import Transaction
from bsv.wallet.wallet_interface import WalletInterface


def _basket_name(definition_type: DefinitionType) -> str:
    return {
        "basket": "basketmap",
        "protocol": "protomap",
        "certificate": "certmap",
    }[definition_type]


class WalletWireResolver:
    """Simple resolver that uses the wallet wire list_outputs to emulate a lookup service.

    This does not discover global registry entries across the network; it queries the connected
    wallet and filters locally by parsed registry fields.
    """

    def __init__(self, wallet: WalletInterface, originator: str = "registry-resolver") -> None:
        self.wallet = wallet
        self.originator = originator

    def __call__(self, ctx: Any, service_name: str, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        # Map service name to definition type (TS/Go alias)
        # For responsibility separation and reusability
        # __call__(service_name, ...) is the interoperability entry point, query(definition_type, ...) is the actual logic.
        # The mapping allows both to be unified, and the internal logic is reusable and readable.
        # Even if service names increase or change in the future, only the mapping needs to be updated.
        # The design allows for invalid service names to be handled gracefully.

        service_to_type = {
            "ls_basketmap": "basket",
            "ls_protomap": "protocol",
            "ls_certmap": "certificate",
        }
        definition_type = cast(DefinitionType, service_to_type.get(service_name))
        if not definition_type:
            return []
        return self.query(ctx, definition_type, query)

    def query(self, ctx: Any, definition_type: DefinitionType, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        lo = self.wallet.list_outputs(
            ctx,
            {
                "basket": _basket_name(definition_type),
                "include": "entire transactions",
            },
            self.originator,
        ) or {}

        outputs = cast(List[Dict[str, Any]], lo.get("outputs") or [])
        if os.getenv("REGISTRY_DEBUG") == "1":
            print("[DEBUG resolver.outputs]", len(outputs), outputs[:1])
        # For WalletWire-backed resolver, prefer direct lockingScript from outputs (BEEF not required)

        matches: List[Dict[str, Any]] = []
        for out in outputs:
            idx = int(out.get("outputIndex", 0))
            try:
                ls_field = out.get("lockingScript") or ""
                if isinstance(ls_field, str):
                    ls_hex = ls_field
                else:
                    from bsv.script.script import Script
                    ls_hex = Script(cast(bytes, ls_field)).hex()
                rec = _parse_locking_script(definition_type, ls_hex)
            except Exception:
                continue

            # NOTE: WalletWireResolver only targets outputs within the wallet for simple interoperability.
            # The main Lookup is for global search + detailed filtering, but here we only keep it at the basket level.

            matches.append({"beef": b"", "outputIndex": idx})

        return matches


