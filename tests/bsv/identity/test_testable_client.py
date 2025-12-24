import unittest
from unittest.mock import Mock, patch
from bsv.identity.testable_client import TestableIdentityClient
from bsv.identity.types import DisplayableIdentity


class TestTestableIdentityClient(unittest.TestCase):
    """Test cases for TestableIdentityClient."""

    def setUp(self):
        """Set up test fixtures."""
        self.wallet = Mock()
        self.ctx = Mock()
        self.client = TestableIdentityClient(wallet=self.wallet, record_calls=True)

    def test_initialization(self):
        """Test initialization of TestableIdentityClient."""
        self.assertEqual(self.client.wallet, self.wallet)
        self.assertTrue(self.client.record_calls)
        self.assertEqual(len(self.client.calls), 0)
        self.assertEqual(self.client._dummy_txid, "dummy-txid")
        self.assertEqual(len(self.client._dummy_identities), 1)
        self.assertEqual(self.client._dummy_identities[0].name, "Test User")
        self.assertEqual(self.client._dummy_identities[0].identity_key, "testkey1")

    def test_initialization_without_wallet(self):
        """Test initialization without providing a wallet."""
        with patch('bsv.wallet.wallet_impl.ProtoWallet'), \
             patch('bsv.keys.PrivateKey'):
            client = TestableIdentityClient()
            self.assertIsNotNone(client.wallet)
            self.assertTrue(client.record_calls)

    def test_record_calls_disabled(self):
        """Test that calls are not recorded when record_calls is False."""
        client = TestableIdentityClient(record_calls=False)
        client._record("test_method", arg1="value1")
        self.assertEqual(len(client.calls), 0)

    def test_record_calls_enabled(self):
        """Test that calls are recorded when record_calls is True."""
        client = TestableIdentityClient(record_calls=True)
        client._record("test_method", arg1="value1", arg2="value2")
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(client.calls[0]["method"], "test_method")
        self.assertEqual(client.calls[0]["arg1"], "value1")
        self.assertEqual(client.calls[0]["arg2"], "value2")

    def test_publicly_reveal_attributes(self):
        """Test publicly_reveal_attributes method."""
        certificate = Mock()
        fields_to_reveal = ["field1", "field2"]

        result = self.client.publicly_reveal_attributes(self.ctx, certificate, fields_to_reveal)

        self.assertEqual(result["txid"], "dummy-txid")
        self.assertEqual(result["fields"], fields_to_reveal)
        self.assertEqual(len(self.client.calls), 1)
        self.assertEqual(self.client.calls[0]["method"], "publicly_reveal_attributes")
        self.assertEqual(self.client.calls[0]["ctx"], self.ctx)
        self.assertEqual(self.client.calls[0]["certificate"], certificate)
        self.assertEqual(self.client.calls[0]["fields_to_reveal"], fields_to_reveal)

    def test_publicly_reveal_attributes_simple(self):
        """Test publicly_reveal_attributes_simple method."""
        certificate = Mock()
        fields_to_reveal = ["field1", "field2"]

        result = self.client.publicly_reveal_attributes_simple(self.ctx, certificate, fields_to_reveal)

        self.assertEqual(result, "dummy-txid")
        self.assertEqual(len(self.client.calls), 1)
        self.assertEqual(self.client.calls[0]["method"], "publicly_reveal_attributes_simple")

    def test_resolve_by_identity_key(self):
        """Test resolve_by_identity_key method."""
        args = {"identity_key": "test123"}

        result = self.client.resolve_by_identity_key(self.ctx, args)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].name, "Test User")
        self.assertEqual(result[0].identity_key, "testkey1")
        self.assertEqual(len(self.client.calls), 1)
        self.assertEqual(self.client.calls[0]["method"], "resolve_by_identity_key")

    def test_resolve_by_attributes(self):
        """Test resolve_by_attributes method."""
        args = {"attribute": "test"}

        result = self.client.resolve_by_attributes(self.ctx, args)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].name, "Test User")
        self.assertEqual(len(self.client.calls), 1)
        self.assertEqual(self.client.calls[0]["method"], "resolve_by_attributes")

    def test_parse_identity_displayable_identity(self):
        """Test parse_identity with DisplayableIdentity input."""
        identity = DisplayableIdentity(name="Test Name", identity_key="testkey")

        result = TestableIdentityClient.parse_identity(identity)

        self.assertEqual(result, identity)

    def test_parse_identity_dict(self):
        """Test parse_identity with dict input."""
        identity_dict = {"name": "Dict Name", "identity_key": "dictkey"}

        result = TestableIdentityClient.parse_identity(identity_dict)

        self.assertEqual(result.name, "Dict Name")
        self.assertEqual(result.identity_key, "dictkey")

    def test_parse_identity_dict_missing_fields(self):
        """Test parse_identity with dict missing some fields."""
        identity_dict = {"name": "Only Name"}

        result = TestableIdentityClient.parse_identity(identity_dict)

        self.assertEqual(result.name, "Only Name")
        self.assertEqual(result.identity_key, "testkey1")  # default value

    def test_parse_identity_invalid_type(self):
        """Test parse_identity with invalid input type."""
        result = TestableIdentityClient.parse_identity(123)

        self.assertEqual(result.name, "Unknown Test Identity")
        self.assertEqual(result.identity_key, "")  # empty string from DisplayableIdentity default


if __name__ == '__main__':
    unittest.main()
