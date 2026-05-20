import unittest
from typing import Any, Dict, List

from bsv.keys import PrivateKey
from bsv.registry.client import RegistryClient
from bsv.registry.resolver import WalletWireResolver
from bsv.registry.types import (
    BasketDefinitionData,
    CertificateDefinitionData,
    ProtocolDefinitionData,
)
from bsv.wallet import ProtoWallet


class TestRegistryClient(unittest.TestCase):
    def setUp(self) -> None:
        self.wallet = ProtoWallet(PrivateKey())
        self.client = RegistryClient(self.wallet, originator="test-registry")

    def test_register_and_list_basket(self):
        data = BasketDefinitionData(
            definition_type="basket",
            basket_id="b123",
            name="basket-name",
            icon_url="https://icon",
            description="desc",
            documentation_url="https://docs",
        )

        res = self.client.register_definition(None, data)
        self.assertIn("signableTransaction", res)

        listed = self.client.list_own_registry_entries(None, "basket")
        self.assertIsInstance(listed, list)
        assert len(listed) == 1

    def test_register_protocol_and_list(self):
        data = ProtocolDefinitionData(
            definition_type="protocol",
            protocol_id={"securityLevel": 1, "protocol": "protomap"},
            name="proto",
            icon_url="",
            description="",
            documentation_url="",
        )
        _ = self.client.register_definition(None, data)
        _ = self.client.list_own_registry_entries(None, "protocol")

    def test_register_certificate_and_list(self):
        data = CertificateDefinitionData(
            definition_type="certificate",
            type="cert.type",
            name="cert",
            icon_url="",
            description="",
            documentation_url="",
            fields={"fieldA": {"friendlyName": "A", "description": "", "type": "text", "fieldIcon": ""}},
        )
        _ = self.client.register_definition(None, data)
        _ = self.client.list_own_registry_entries(None, "certificate")

    def test_resolve_mock(self):
        # Mock resolver returns one output with dummy BEEF and output index 0
        def resolver(_ctx: Any, _service_name: str, _query: dict[str, Any]) -> list[dict[str, Any]]:
            # Reuse list_own_registry_entries BEEF path by creating a basket definition first
            data = BasketDefinitionData(
                definition_type="basket",
                basket_id="b1",
                name="n",
                icon_url="",
                description="",
                documentation_url="",
            )
            _ = self.client.register_definition(None, data)
            listed = self.client.list_own_registry_entries(None, "basket")
            if not listed:
                return []
            rec = listed[0]
            return [{"beef": rec.get("beef"), "outputIndex": rec.get("outputIndex")}]  # type: ignore

        out = self.client.resolve(None, "basket", {"basketID": "b1"}, resolver=resolver)
        self.assertIsInstance(out, list)
        assert len(out) == 1

    def test_revoke_flow_mock(self):
        data = BasketDefinitionData(
            definition_type="basket",
            basket_id="b2",
            name="n2",
            icon_url="",
            description="",
            documentation_url="",
        )
        _ = self.client.register_definition(None, data)
        listed = self.client.list_own_registry_entries(None, "basket")
        if listed:
            res = self.client.revoke_own_registry_entry(None, listed[0])
            self.assertIn("tx", res)

    def test_walletwire_resolver_filters(self):
        # create three entries with differing values
        for bid in ("bx", "by", "bz"):
            data = BasketDefinitionData(
                definition_type="basket",
                basket_id=bid,
                name=f"name-{bid}",
                icon_url="",
                description="",
                documentation_url="",
            )
            _ = self.client.register_definition(None, data)

        r = WalletWireResolver(self.wallet)
        # Call via TS/Go-compatible entry (__call__ takes service name)
        outs = r(None, "ls_basketmap", {"basketID": "by"})
        self.assertIsInstance(outs, list)
        assert len(outs) == 1


if __name__ == "__main__":
    unittest.main()
