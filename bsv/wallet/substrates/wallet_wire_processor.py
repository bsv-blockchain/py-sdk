from typing import Any
from ..wallet_interface import WalletInterface
from .wallet_wire import WalletWire
from .wallet_wire_calls import WalletWireCall
from .serializer import (
    Reader,
    serialize_encrypt_result,
    serialize_decrypt_result,
    deserialize_encrypt_args,
    deserialize_decrypt_args,
)
from bsv.wallet.serializer.frame import write_result_frame
from bsv.wallet.serializer.create_action_args import (
    serialize_create_action_args,
    deserialize_create_action_args,
)
from bsv.wallet.serializer.create_action_result import (
    serialize_create_action_result,
    deserialize_create_action_result,
)
from bsv.wallet.serializer.sign_action_args import (
    serialize_sign_action_args,
    deserialize_sign_action_args,
)
from bsv.wallet.serializer.sign_action_result import (
    serialize_sign_action_result,
    deserialize_sign_action_result,
)
from bsv.wallet.serializer.list_actions import (
    serialize_list_actions_args,
    deserialize_list_actions_args,
    serialize_list_actions_result,
    deserialize_list_actions_result,
)
from bsv.wallet.serializer.internalize_action import (
    serialize_internalize_action_args,
    deserialize_internalize_action_args,
    serialize_internalize_action_result,
    deserialize_internalize_action_result,
)
from bsv.wallet.serializer.list_certificates import (
    serialize_list_certificates_args,
    deserialize_list_certificates_args,
    serialize_list_certificates_result,
    deserialize_list_certificates_result,
)
from bsv.wallet.serializer.prove_certificate import (
    serialize_prove_certificate_args,
    deserialize_prove_certificate_args,
    serialize_prove_certificate_result,
    deserialize_prove_certificate_result,
)
from bsv.wallet.serializer.relinquish_certificate import (
    serialize_relinquish_certificate_args,
    deserialize_relinquish_certificate_args,
    serialize_relinquish_certificate_result,
    deserialize_relinquish_certificate_result,
)
from bsv.wallet.serializer.discover_by_identity_key import (
    serialize_discover_by_identity_key_args,
    deserialize_discover_by_identity_key_args,
    serialize_discover_certificates_result as serialize_discover_certificates_result_by_identity,
    deserialize_discover_certificates_result as deserialize_discover_certificates_result_by_identity,
)
from bsv.wallet.serializer.discover_by_attributes import (
    serialize_discover_by_attributes_args,
    deserialize_discover_by_attributes_args,
    serialize_discover_certificates_result as serialize_discover_certificates_result_by_attr,
    deserialize_discover_certificates_result as deserialize_discover_certificates_result_by_attr,
)
from bsv.wallet.serializer.acquire_certificate import (
    serialize_acquire_certificate_args,
    deserialize_acquire_certificate_args,
)
from bsv.wallet.serializer.create_hmac import (
    serialize_create_hmac_args,
    deserialize_create_hmac_args,
    serialize_create_hmac_result,
)
from bsv.wallet.serializer.verify_hmac import (
    serialize_verify_hmac_args,
    deserialize_verify_hmac_args,
    serialize_verify_hmac_result,
)
from bsv.wallet.serializer.create_signature import (
    serialize_create_signature_args,
    deserialize_create_signature_args,
    serialize_create_signature_result,
)
from bsv.wallet.serializer.verify_signature import (
    serialize_verify_signature_args,
    deserialize_verify_signature_args,
    serialize_verify_signature_result,
)
from bsv.wallet.serializer.list_outputs import (
    serialize_list_outputs_args,
    deserialize_list_outputs_args,
    serialize_list_outputs_result,
    deserialize_list_outputs_result,
)
from bsv.wallet.serializer.relinquish_output import (
    serialize_relinquish_output_args,
    deserialize_relinquish_output_args,
    serialize_relinquish_output_result,
    deserialize_relinquish_output_result,
)
from bsv.wallet.serializer.get_network import (
    serialize_get_header_args,
    deserialize_get_header_result,
    deserialize_get_network_result,
    deserialize_get_version_result,
    deserialize_get_height_result,
)
from bsv.wallet.serializer.get_public_key import (
    serialize_get_public_key_args,
    deserialize_get_public_key_args,
    serialize_get_public_key_result,
)
from bsv.wallet.serializer.key_linkage import (
    serialize_reveal_counterparty_key_linkage_args,
    deserialize_reveal_counterparty_key_linkage_args,
    serialize_reveal_specific_key_linkage_args,
    deserialize_reveal_specific_key_linkage_args,
    serialize_key_linkage_result,
)

class WalletWireProcessor(WalletWire):
    def __init__(self, wallet: WalletInterface):
        self.wallet = wallet
        self._call_handlers = self._initialize_call_handlers()
    
    def _initialize_call_handlers(self):
        """Initialize dispatch table for wallet wire calls."""
        return {
            WalletWireCall.ENCRYPT: self._handle_encrypt,
            WalletWireCall.DECRYPT: self._handle_decrypt,
            WalletWireCall.CREATE_ACTION: self._handle_create_action,
            WalletWireCall.SIGN_ACTION: self._handle_sign_action,
            WalletWireCall.LIST_ACTIONS: self._handle_list_actions,
            WalletWireCall.INTERNALIZE_ACTION: self._handle_internalize_action,
            WalletWireCall.ABORT_ACTION: self._handle_abort_action,
            WalletWireCall.LIST_CERTIFICATES: self._handle_list_certificates,
            WalletWireCall.PROVE_CERTIFICATE: self._handle_prove_certificate,
            WalletWireCall.RELINQUISH_CERTIFICATE: self._handle_relinquish_certificate,
            WalletWireCall.DISCOVER_BY_IDENTITY_KEY: self._handle_discover_by_identity_key,
            WalletWireCall.DISCOVER_BY_ATTRIBUTES: self._handle_discover_by_attributes,
            WalletWireCall.ACQUIRE_CERTIFICATE: self._handle_acquire_certificate,
            WalletWireCall.CREATE_HMAC: self._handle_create_hmac,
            WalletWireCall.VERIFY_HMAC: self._handle_verify_hmac,
            WalletWireCall.CREATE_SIGNATURE: self._handle_create_signature,
            WalletWireCall.VERIFY_SIGNATURE: self._handle_verify_signature,
            WalletWireCall.LIST_OUTPUTS: self._handle_list_outputs,
            WalletWireCall.RELINQUISH_OUTPUT: self._handle_relinquish_output,
            WalletWireCall.GET_HEADER_FOR_HEIGHT: self._handle_get_header_for_height,
            WalletWireCall.GET_NETWORK: self._handle_get_network,
            WalletWireCall.GET_VERSION: self._handle_get_version,
            WalletWireCall.GET_HEIGHT: self._handle_get_height,
            WalletWireCall.GET_PUBLIC_KEY: self._handle_get_public_key,
            WalletWireCall.REVEAL_COUNTERPARTY_KEY_LINKAGE: self._handle_reveal_counterparty_key_linkage,
            WalletWireCall.REVEAL_SPECIFIC_KEY_LINKAGE: self._handle_reveal_specific_key_linkage,
            WalletWireCall.IS_AUTHENTICATED: self._handle_is_authenticated,
            WalletWireCall.WAIT_FOR_AUTHENTICATION: self._handle_wait_for_authentication,
        }

    def transmit_to_wallet(self, ctx: Any, message: bytes) -> bytes:
        """Route wallet wire calls to appropriate handlers."""
        try:
            call, originator, params = self._parse_message(message)
            handler = self._call_handlers.get(call)
            
            if handler:
                return handler(ctx, params, originator)
            
            # Default: return params as-is
            return write_result_frame(params)
        except Exception as e:
            return write_result_frame(None, error=str(e))
    
    def _parse_message(self, message: bytes):
        """Parse wallet wire message header."""
        reader = Reader(message)
        call_code = reader.read_byte()
        call = WalletWireCall(call_code)
        originator_len = reader.read_byte()
        originator = reader.read_bytes(originator_len).decode('utf-8') if originator_len > 0 else ''
        params = reader.read_bytes(len(message) - reader.pos) if reader.pos < len(message) else b''
        return call, originator, params
    
    # Handler methods for each call type
    def _handle_encrypt(self, ctx, params, originator):
        enc_args = deserialize_encrypt_args(params)
        result_dict = self.wallet.encrypt(ctx, enc_args, originator)
        return write_result_frame(serialize_encrypt_result(result_dict))
    
    def _handle_decrypt(self, ctx, params, originator):
        dec_args = deserialize_decrypt_args(params)
        result_dict = self.wallet.decrypt(ctx, dec_args, originator)
        return write_result_frame(serialize_decrypt_result(result_dict))
    
    def _handle_create_action(self, ctx, params, originator):
        c_args = deserialize_create_action_args(params)
        result = self.wallet.create_action(ctx, c_args, originator) or {}
        return write_result_frame(serialize_create_action_result(result or {}))
    
    def _handle_sign_action(self, ctx, params, originator):
        s_args = deserialize_sign_action_args(params)
        result = self.wallet.sign_action(ctx, s_args, originator) or {}
        return write_result_frame(serialize_sign_action_result(result))
    
    def _handle_list_actions(self, ctx, params, originator):
        la_args = deserialize_list_actions_args(params)
        result = self.wallet.list_actions(ctx, la_args, originator)
        return write_result_frame(serialize_list_actions_result(result or {}))
    
    def _handle_internalize_action(self, ctx, params, originator):
        ia_args = deserialize_internalize_action_args(params)
        result = self.wallet.internalize_action(ctx, ia_args, originator)
        return write_result_frame(serialize_internalize_action_result(result or {}))
    
    def _handle_abort_action(self, ctx, params, originator):
        from bsv.wallet.serializer.abort_action import serialize_abort_action_result, deserialize_abort_action_args
        aa_args = deserialize_abort_action_args(params)
        result = self.wallet.abort_action(ctx, aa_args, originator)
        return write_result_frame(serialize_abort_action_result(result or {}))
    
    def _handle_list_certificates(self, ctx, params, originator):
        lc_args = deserialize_list_certificates_args(params)
        result = self.wallet.list_certificates(ctx, lc_args, originator)
        return write_result_frame(serialize_list_certificates_result(result or {}))
    
    def _handle_prove_certificate(self, ctx, params, originator):
        pc_args = deserialize_prove_certificate_args(params)
        result = self.wallet.prove_certificate(ctx, pc_args, originator)
        return write_result_frame(serialize_prove_certificate_result(result or {}))
    
    def _handle_relinquish_certificate(self, ctx, params, originator):
        rc_args = deserialize_relinquish_certificate_args(params)
        result = self.wallet.relinquish_certificate(ctx, rc_args, originator)
        return write_result_frame(serialize_relinquish_certificate_result(result or {}))
    
    def _handle_discover_by_identity_key(self, ctx, params, originator):
        di_args = deserialize_discover_by_identity_key_args(params)
        result = self.wallet.discover_by_identity_key(ctx, di_args, originator)
        return write_result_frame(serialize_discover_certificates_result_by_identity(result or {}))
    
    def _handle_discover_by_attributes(self, ctx, params, originator):
        da_args = deserialize_discover_by_attributes_args(params)
        result = self.wallet.discover_by_attributes(ctx, da_args, originator)
        return write_result_frame(serialize_discover_certificates_result_by_attr(result or {}))
    
    def _handle_acquire_certificate(self, ctx, params, originator):
        ac_args = deserialize_acquire_certificate_args(params)
        _ = self.wallet.acquire_certificate(ctx, ac_args, originator)
        return write_result_frame(b"")  # No specific result payload
    
    def _handle_create_hmac(self, ctx, params, originator):
        h_args = deserialize_create_hmac_args(params)
        result = self.wallet.create_hmac(ctx, h_args, originator)
        return write_result_frame(serialize_create_hmac_result(result))
    
    def _handle_verify_hmac(self, ctx, params, originator):
        vh_args = deserialize_verify_hmac_args(params)
        result = self.wallet.verify_hmac(ctx, vh_args, originator)
        return write_result_frame(serialize_verify_hmac_result(result))
    
    def _handle_create_signature(self, ctx, params, originator):
        cs_args = deserialize_create_signature_args(params)
        result = self.wallet.create_signature(ctx, cs_args, originator)
        return write_result_frame(serialize_create_signature_result(result))
    
    def _handle_verify_signature(self, ctx, params, originator):
        vs_args = deserialize_verify_signature_args(params)
        result = self.wallet.verify_signature(ctx, vs_args, originator)
        return write_result_frame(serialize_verify_signature_result(result))
    
    def _handle_list_outputs(self, ctx, params, originator):
        lo_args = deserialize_list_outputs_args(params)
        result = self.wallet.list_outputs(ctx, lo_args, originator)
        return write_result_frame(serialize_list_outputs_result(result or {}))
    
    def _handle_relinquish_output(self, ctx, params, originator):
        ro_args = deserialize_relinquish_output_args(params)
        result = self.wallet.relinquish_output(ctx, ro_args, originator)
        return write_result_frame(serialize_relinquish_output_result(result or {}))
    
    def _handle_get_header_for_height(self, ctx, params, originator):
        from bsv.wallet.serializer.get_network import deserialize_get_header_args, serialize_get_header_result
        gha = deserialize_get_header_args(params)
        result = self.wallet.get_header_for_height(ctx, gha, originator) or {}
        return write_result_frame(serialize_get_header_result(result))
    
    def _handle_get_network(self, ctx, params, originator):
        from bsv.wallet.serializer.get_network import serialize_get_network_result
        result = self.wallet.get_network(ctx, {}, originator) or {}
        return write_result_frame(serialize_get_network_result(result))
    
    def _handle_get_version(self, ctx, params, originator):
        from bsv.wallet.serializer.get_network import serialize_get_version_result
        result = self.wallet.get_version(ctx, {}, originator) or {}
        return write_result_frame(serialize_get_version_result(result))
    
    def _handle_get_height(self, ctx, params, originator):
        from bsv.wallet.serializer.get_network import serialize_get_height_result
        result = self.wallet.get_height(ctx, {}, originator) or {}
        return write_result_frame(serialize_get_height_result(result))
    
    def _handle_get_public_key(self, ctx, params, originator):
        gp_args = deserialize_get_public_key_args(params)
        result = self.wallet.get_public_key(ctx, gp_args, originator)
        if isinstance(result, dict) and result.get("error"):
            return write_result_frame(None, error=str(result.get("error")))
        return write_result_frame(serialize_get_public_key_result(result or {}))
    
    def _handle_reveal_counterparty_key_linkage(self, ctx, params, originator):
        r_args = deserialize_reveal_counterparty_key_linkage_args(params)
        result = self.wallet.reveal_counterparty_key_linkage(ctx, r_args, originator)
        if isinstance(result, dict) and result.get("error"):
            return write_result_frame(None, error=str(result.get("error")))
        return write_result_frame(serialize_key_linkage_result(result or {}))
    
    def _handle_reveal_specific_key_linkage(self, ctx, params, originator):
        rs_args = deserialize_reveal_specific_key_linkage_args(params)
        result = self.wallet.reveal_specific_key_linkage(ctx, rs_args, originator)
        if isinstance(result, dict) and result.get("error"):
            return write_result_frame(None, error=str(result.get("error")))
        return write_result_frame(serialize_key_linkage_result(result or {}))
    
    def _handle_is_authenticated(self, ctx, params, originator):
        result = self.wallet.is_authenticated(ctx, None, originator) or {}
        # encode a single-byte boolean per Go serializer
        return write_result_frame(bytes([1]) if bool(result.get("authenticated")) else bytes([0]))
    
    def _handle_wait_for_authentication(self, ctx, params, originator):
        _ = self.wallet.wait_for_authentication(ctx, None, originator)
        return write_result_frame(bytes([1]))
