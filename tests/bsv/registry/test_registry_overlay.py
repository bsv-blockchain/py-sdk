# import unittest

# from bsv.keys import PrivateKey
# from bsv.wallet.wallet_impl import WalletImpl
# from bsv.registry.client import RegistryClient
# from bsv.registry.types import BasketDefinitionData
# from bsv.registry.resolver import WalletWireResolver


# class TestRegistryOverlay(unittest.TestCase):
#     def setUp(self) -> None:
#         self.wallet = WalletImpl(PrivateKey())
#         self.client = RegistryClient(self.wallet, originator="test-registry")

#     def test_register_resolve_list_revoke_roundtrip(self):
#         # Register
#         data = BasketDefinitionData(
#             definitionType="basket",
#             basketID="overlay.b",
#             name="overlay-b",
#             iconURL="",
#             description="",
#             documentationURL="",
#         )
#         _ = self.client.register_definition(None, data)

#         # Resolve via overlay-compatible resolver
#         resolver = WalletWireResolver(self.wallet)
#         found = self.client.resolve(None, "basket", {"basketID": "overlay.b"}, resolver=resolver)
#         self.assertTrue(any(getattr(r, "basketID", "") == "overlay.b" for r in found))

#         # List
#         listed = self.client.list_own_registry_entries(None, "basket")
#         self.assertTrue(len(listed) >= 1)

#         # Revoke
#         res = self.client.revoke_own_registry_entry(None, listed[0])
#         self.assertIn("tx", res)


# if __name__ == "__main__":
#     unittest.main()


