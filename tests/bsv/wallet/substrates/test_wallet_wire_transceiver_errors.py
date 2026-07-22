"""
Comprehensive error handling tests for wallet_wire_transceiver.py
"""

from unittest.mock import Mock, patch

import pytest

from bsv.wallet.substrates.wallet_wire_calls import WalletWireCall


class TestWalletWireTransceiverErrors:
    """Test error handling in WalletWireTransceiver."""

    def setup_method(self):
        """Set up test fixtures."""
        try:
            from bsv.wallet.substrates.wallet_wire_transceiver import WalletWireTransceiver

            self.mock_wire = Mock()
            self.transceiver = WalletWireTransceiver(self.mock_wire)
        except ImportError:
            self.transceiver = None

    def test_transmit_wire_error(self):
        """Test transmit method with wire transmission error."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        # Mock successful frame write but wire transmission fails
        with patch("bsv.wallet.serializer.frame.write_request_frame", return_value=b"frame"):
            self.mock_wire.transmit_to_wallet.side_effect = Exception("Wire transmission failed")

            with pytest.raises(Exception, match="Wire transmission failed"):
                self.transceiver.transmit(None, WalletWireCall.CREATE_ACTION, "test", b"params")

    def test_create_action_serialize_error(self):
        """Test create_action with serialization error."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        with patch(
            "bsv.wallet.serializer.create_action_args.serialize_create_action_args",
            side_effect=RuntimeError("Serialize failed"),
        ):
            with pytest.raises(RuntimeError, match="Serialize failed"):
                self.transceiver.create_action(None, {}, "test")

    def test_create_action_transmit_error(self):
        """Test create_action with transmission error."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        # Mock successful serialization but transmission fails
        with patch("bsv.wallet.serializer.create_action_args.serialize_create_action_args", return_value=b"serialized"):
            self.mock_wire.transmit_to_wallet.side_effect = Exception("Transmit failed")

            with pytest.raises(Exception, match="Transmit failed"):
                self.transceiver.create_action(None, {}, "test")

    def test_sign_action_serialize_error(self):
        """Test sign_action with serialization error."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        with patch(
            "bsv.wallet.serializer.sign_action_args.serialize_sign_action_args",
            side_effect=RuntimeError("Sign serialize failed"),
        ):
            with pytest.raises(RuntimeError, match="Sign serialize failed"):
                self.transceiver.sign_action(None, {}, "test")

    def test_sign_action_transmit_error(self):
        """Test sign_action with transmission error."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        with patch("bsv.wallet.serializer.sign_action_args.serialize_sign_action_args", return_value=b"serialized"):
            self.mock_wire.transmit_to_wallet.side_effect = Exception("Sign transmit failed")

            with pytest.raises(Exception, match="Sign transmit failed"):
                self.transceiver.sign_action(None, {}, "test")

    def test_abort_action_serialize_error(self):
        """Test abort_action with serialization error."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        with patch(
            "bsv.wallet.serializer.abort_action.serialize_abort_action_args",
            side_effect=RuntimeError("Abort serialize failed"),
        ):
            with pytest.raises(RuntimeError, match="Abort serialize failed"):
                self.transceiver.abort_action(None, {}, "test")

    def test_list_actions_serialize_error(self):
        """Test list_actions with serialization error."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        # Patch the name bound in the transceiver module (imported at module top level)
        with patch(
            "bsv.wallet.substrates.wallet_wire_transceiver.serialize_list_actions_args",
            side_effect=RuntimeError("List serialize failed"),
        ):
            with pytest.raises(RuntimeError, match="List serialize failed"):
                self.transceiver.list_actions(None, {}, "test")

    def test_internalize_action_serialize_error(self):
        """Test internalize_action with serialization error."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        # Patch the name bound in the transceiver module (imported at module top level)
        with patch(
            "bsv.wallet.substrates.wallet_wire_transceiver.serialize_internalize_action_args",
            side_effect=RuntimeError("Internalize serialize failed"),
        ):
            with pytest.raises(RuntimeError, match="Internalize serialize failed"):
                self.transceiver.internalize_action(None, {"tx": b"\x01"}, "test")

    def test_list_certificates_serialize_error(self):
        """Test list_certificates with serialization error."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        # Patch the name bound in the transceiver module (imported at module top level)
        with patch(
            "bsv.wallet.substrates.wallet_wire_transceiver.serialize_list_certificates_args",
            side_effect=RuntimeError("List certs serialize failed"),
        ):
            with pytest.raises(RuntimeError, match="List certs serialize failed"):
                self.transceiver.list_certificates(None, {}, "test")

    def test_relinquish_output_serialize_error(self):
        """Test relinquish_output with serialization error."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        # Patch the name bound in the transceiver module (imported at module top level)
        with patch(
            "bsv.wallet.substrates.wallet_wire_transceiver.serialize_relinquish_output_args",
            side_effect=RuntimeError("Relinquish serialize failed"),
        ):
            with pytest.raises(RuntimeError, match="Relinquish serialize failed"):
                self.transceiver.relinquish_output(None, {"outpoint": "00" * 32 + ":0"}, "test")

    def test_create_hmac_serialize_error(self):
        """Test create_hmac with serialization error."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        # Patch the name bound in the transceiver module (imported at module top level)
        with patch(
            "bsv.wallet.substrates.wallet_wire_transceiver.serialize_create_hmac_args",
            side_effect=RuntimeError("HMAC serialize failed"),
        ):
            with pytest.raises(RuntimeError, match="HMAC serialize failed"):
                self.transceiver.create_hmac(None, {"data": b"payload"}, "test")

    def test_verify_hmac_serialize_error(self):
        """Test verify_hmac with serialization error."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        # Patch the name bound in the transceiver module (imported at module top level)
        with patch(
            "bsv.wallet.substrates.wallet_wire_transceiver.serialize_verify_hmac_args",
            side_effect=RuntimeError("Verify HMAC serialize failed"),
        ):
            with pytest.raises(RuntimeError, match="Verify HMAC serialize failed"):
                self.transceiver.verify_hmac(None, {"hmac": b"\x01" * 32, "data": b"payload"}, "test")

    def test_create_signature_serialize_error(self):
        """Test create_signature with serialization error."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        # Patch the name bound in the transceiver module (imported at module top level)
        with patch(
            "bsv.wallet.substrates.wallet_wire_transceiver.serialize_create_signature_args",
            side_effect=RuntimeError("Signature serialize failed"),
        ):
            with pytest.raises(RuntimeError, match="Signature serialize failed"):
                self.transceiver.create_signature(None, {"data": b"payload"}, "test")

    def test_verify_signature_serialize_error(self):
        """Test verify_signature with serialization error."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        # Patch the name bound in the transceiver module (imported at module top level)
        with patch(
            "bsv.wallet.substrates.wallet_wire_transceiver.serialize_verify_signature_args",
            side_effect=RuntimeError("Verify sig serialize failed"),
        ):
            with pytest.raises(RuntimeError, match="Verify sig serialize failed"):
                self.transceiver.verify_signature(None, {}, "test")

    def test_key_linkage_serialize_errors(self):
        """Test key linkage methods with serialization errors."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        # Test reveal_counterparty_key_linkage
        # Patch the name bound in the transceiver module (imported at module top level)
        with patch(
            "bsv.wallet.substrates.wallet_wire_transceiver.serialize_reveal_counterparty_key_linkage_args",
            side_effect=RuntimeError("Counterparty linkage failed"),
        ):
            with pytest.raises(RuntimeError, match="Counterparty linkage failed"):
                self.transceiver.reveal_counterparty_key_linkage(None, {"counterparty": b"\x02" * 33}, "test")

        # Test reveal_specific_key_linkage
        with patch(
            "bsv.wallet.substrates.wallet_wire_transceiver.serialize_reveal_specific_key_linkage_args",
            side_effect=RuntimeError("Specific linkage failed"),
        ):
            with pytest.raises(RuntimeError, match="Specific linkage failed"):
                self.transceiver.reveal_specific_key_linkage(
                    None, {"protocolID": {"securityLevel": 0, "protocol": "test proto"}}, "test"
                )

    def test_network_operations_serialize_errors(self):
        """Test network-related operations with serialization errors."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        # Test get_header_for_height
        # Patch the names bound in the transceiver module (imported at module top level)
        with patch(
            "bsv.wallet.substrates.wallet_wire_transceiver.serialize_get_header_args",
            side_effect=RuntimeError("Header serialize failed"),
        ):
            with pytest.raises(RuntimeError, match="Header serialize failed"):
                self.transceiver.get_header_for_height(None, {}, "test")

        # Test get_network
        with patch(
            "bsv.wallet.substrates.wallet_wire_transceiver.serialize_get_network_args",
            side_effect=RuntimeError("Network serialize failed"),
        ):
            with pytest.raises(RuntimeError, match="Network serialize failed"):
                self.transceiver.get_network(None, {}, "test")

        # Test get_version
        with patch(
            "bsv.wallet.substrates.wallet_wire_transceiver.serialize_get_version_args",
            side_effect=RuntimeError("Version serialize failed"),
        ):
            with pytest.raises(RuntimeError, match="Version serialize failed"):
                self.transceiver.get_version(None, {}, "test")

        # Test get_height
        with patch(
            "bsv.wallet.substrates.wallet_wire_transceiver.serialize_get_height_args",
            side_effect=RuntimeError("Height serialize failed"),
        ):
            with pytest.raises(RuntimeError, match="Height serialize failed"):
                self.transceiver.get_height(None, {"header": b"\x01"}, "test")

    def test_acquire_certificate_serialize_error(self):
        """Test acquire_certificate with serialization error."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        # Patch the name bound in the transceiver module (imported at module top level)
        with patch(
            "bsv.wallet.substrates.wallet_wire_transceiver.serialize_acquire_certificate_args",
            side_effect=RuntimeError("Acquire cert serialize failed"),
        ):
            with pytest.raises(RuntimeError, match="Acquire cert serialize failed"):
                self.transceiver.acquire_certificate(None, {}, "test")

    def test_prove_certificate_serialize_error(self):
        """Test prove_certificate with serialization error."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        # Patch the name bound in the transceiver module (imported at module top level)
        with patch(
            "bsv.wallet.substrates.wallet_wire_transceiver.serialize_prove_certificate_args",
            side_effect=RuntimeError("Prove cert serialize failed"),
        ):
            with pytest.raises(RuntimeError, match="Prove cert serialize failed"):
                self.transceiver.prove_certificate(None, {"verifier": b"\x02" * 33}, "test")

    def test_encrypt_serialize_error(self):
        """Test encrypt with serialization error."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        # Patch the name bound in the transceiver module (imported at module top level)
        with patch(
            "bsv.wallet.substrates.wallet_wire_transceiver.serialize_encrypt_args",
            side_effect=RuntimeError("Encrypt serialize failed"),
        ):
            with pytest.raises(RuntimeError, match="Encrypt serialize failed"):
                self.transceiver.encrypt(None, {}, "test")

    def test_decrypt_serialize_error(self):
        """Test decrypt with serialization error."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        # Patch the name bound in the transceiver module (imported at module top level)
        with patch(
            "bsv.wallet.substrates.wallet_wire_transceiver.serialize_decrypt_args",
            side_effect=RuntimeError("Decrypt serialize failed"),
        ):
            with pytest.raises(RuntimeError, match="Decrypt serialize failed"):
                self.transceiver.decrypt(None, {}, "test")

    def test_transceiver_with_invalid_wire(self):
        """Test transceiver initialization with invalid wire."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        # Test with None wire (the constructor accepts it without validation)
        from bsv.wallet.substrates.wallet_wire_transceiver import WalletWireTransceiver

        transceiver_none = WalletWireTransceiver(None)
        # Should not crash on init, but may fail on first use
        assert transceiver_none.wire is None

    def test_all_methods_with_transmission_errors(self):
        """Test that all transceiver methods properly handle transmission errors."""
        if self.transceiver is None:
            pytest.skip("WalletWireTransceiver not available")

        # Set up wire to fail on transmission
        self.mock_wire.transmit_to_wallet.side_effect = Exception("Network transmission failed")

        # Test a few key methods to ensure they all propagate errors
        methods_to_test = [
            ("create_action", {}),
            ("sign_action", {}),
            ("abort_action", {}),
            ("list_actions", {}),
        ]

        for method_name, args in methods_to_test:
            method = getattr(self.transceiver, method_name)
            with pytest.raises(Exception, match="Network transmission failed"):
                method(None, args, "test")
