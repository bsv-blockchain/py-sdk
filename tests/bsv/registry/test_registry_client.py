import unittest
from typing import Any, Dict, List

from bsv.keys import PrivateKey
from bsv.wallet.wallet_impl import WalletImpl
from bsv.registry.client import RegistryClient
from bsv.registry.types import (
    BasketDefinitionData,
    ProtocolDefinitionData,
    CertificateDefinitionData,
)
from bsv.registry.resolver import WalletWireResolver


class TestRegistryClient(unittest.TestCase):
    def setUp(self) -> None:
        self.wallet = WalletImpl(PrivateKey())
        self.client = RegistryClient(self.wallet, originator="test-registry")

    def test_register_and_list_basket(self):
        data = BasketDefinitionData(
            definitionType="basket",
            basketID="b123",
            name="basket-name",
            iconURL="https://icon",
            description="desc",
            documentationURL="https://docs",
        )

        res = self.client.register_definition(None, data)
        self.assertIn("signableTransaction", res)

        listed = self.client.list_own_registry_entries(None, "basket")
        self.assertIsInstance(listed, list)

    def test_register_protocol_and_list(self):
        data = ProtocolDefinitionData(
            definitionType="protocol",
            protocolID={"securityLevel": 1, "protocol": "protomap"},
            name="proto",
            iconURL="",
            description="",
            documentationURL="",
        )
        _ = self.client.register_definition(None, data)
        _ = self.client.list_own_registry_entries(None, "protocol")

    def test_register_certificate_and_list(self):
        data = CertificateDefinitionData(
            definitionType="certificate",
            type="cert.type",
            name="cert",
            iconURL="",
            description="",
            documentationURL="",
            fields={"fieldA": {"friendlyName": "A", "description": "", "type": "text", "fieldIcon": ""}},
        )
        _ = self.client.register_definition(None, data)
        _ = self.client.list_own_registry_entries(None, "certificate")

    def test_resolve_mock(self):
        # Mock resolver returns one output with dummy BEEF and output index 0
        def resolver(_ctx: Any, _service_name: str, _query: Dict[str, Any]) -> List[Dict[str, Any]]:
            # Reuse list_own_registry_entries BEEF path by creating a basket definition first
            data = BasketDefinitionData(
                definitionType="basket",
                basketID="b1",
                name="n",
                iconURL="",
                description="",
                documentationURL="",
            )
            _ = self.client.register_definition(None, data)
            listed = self.client.list_own_registry_entries(None, "basket")
            if not listed:
                return []
            rec = listed[0]
            return [{"beef": rec.get("beef"), "outputIndex": rec.get("outputIndex")}]  # type: ignore

        out = self.client.resolve(None, "basket", {"basketID": "b1"}, resolver=resolver)
        self.assertIsInstance(out, list)

    def test_revoke_flow_mock(self):
        data = BasketDefinitionData(
            definitionType="basket",
            basketID="b2",
            name="n2",
            iconURL="",
            description="",
            documentationURL="",
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
                definitionType="basket",
                basketID=bid,
                name=f"name-{bid}",
                iconURL="",
                description="",
                documentationURL="",
            )
            _ = self.client.register_definition(None, data)

        r = WalletWireResolver(self.wallet)
        # Call via TS/Go-compatible entry (__call__ takes service name)
        outs = r(None, "ls_basketmap", {"basketID": "by"})
        self.assertTrue(isinstance(outs, list))


if __name__ == "__main__":
    unittest.main()


