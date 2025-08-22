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

    def transmit_to_wallet(self, ctx: Any, message: bytes) -> bytes:
        reader = Reader(message)
        try:
            call_code = reader.read_byte()
            call = WalletWireCall(call_code)
            originator_len = reader.read_byte()
            originator = reader.read_bytes(originator_len).decode('utf-8') if originator_len > 0 else ''
            params = reader.read_bytes(len(message) - reader.pos) if reader.pos < len(message) else b''

            # ENCRYPT
            if call == WalletWireCall.ENCRYPT:
                enc_args = deserialize_encrypt_args(params)
                result_dict = self.wallet.encrypt(ctx, enc_args, originator)
                return write_result_frame(serialize_encrypt_result(result_dict))

            # DECRYPT
            if call == WalletWireCall.DECRYPT:
                dec_args = deserialize_decrypt_args(params)
                result_dict = self.wallet.decrypt(ctx, dec_args, originator)
                return write_result_frame(serialize_decrypt_result(result_dict))

            # CREATE_ACTION
            if call == WalletWireCall.CREATE_ACTION:
                c_args = deserialize_create_action_args(params)
                result = self.wallet.create_action(ctx, c_args, originator) or {}
                return write_result_frame(serialize_create_action_result(result or {}))

            # SIGN_ACTION
            if call == WalletWireCall.SIGN_ACTION:
                s_args = deserialize_sign_action_args(params)
                result = self.wallet.sign_action(ctx, s_args, originator) or {}
                return write_result_frame(serialize_sign_action_result(result))

            # LIST_ACTIONS
            if call == WalletWireCall.LIST_ACTIONS:
                la_args = deserialize_list_actions_args(params)
                result = self.wallet.list_actions(ctx, la_args, originator)
                return write_result_frame(serialize_list_actions_result(result or {}))

            # INTERNALIZE_ACTION
            if call == WalletWireCall.INTERNALIZE_ACTION:
                ia_args = deserialize_internalize_action_args(params)
                result = self.wallet.internalize_action(ctx, ia_args, originator)
                return write_result_frame(serialize_internalize_action_result(result or {}))

            # ABORT_ACTION
            if call == WalletWireCall.ABORT_ACTION:
                from bsv.wallet.serializer.abort_action import serialize_abort_action_result, deserialize_abort_action_args
                aa_args = deserialize_abort_action_args(params)
                result = self.wallet.abort_action(ctx, aa_args, originator)
                return write_result_frame(serialize_abort_action_result(result or {}))

            # LIST_CERTIFICATES
            if call == WalletWireCall.LIST_CERTIFICATES:
                lc_args = deserialize_list_certificates_args(params)
                result = self.wallet.list_certificates(ctx, lc_args, originator)
                return write_result_frame(serialize_list_certificates_result(result or {}))

            # PROVE_CERTIFICATE
            if call == WalletWireCall.PROVE_CERTIFICATE:
                pc_args = deserialize_prove_certificate_args(params)
                result = self.wallet.prove_certificate(ctx, pc_args, originator)
                return write_result_frame(serialize_prove_certificate_result(result or {}))

            # RELINQUISH_CERTIFICATE
            if call == WalletWireCall.RELINQUISH_CERTIFICATE:
                rc_args = deserialize_relinquish_certificate_args(params)
                result = self.wallet.relinquish_certificate(ctx, rc_args, originator)
                return write_result_frame(serialize_relinquish_certificate_result(result or {}))

            # DISCOVER_BY_IDENTITY_KEY
            if call == WalletWireCall.DISCOVER_BY_IDENTITY_KEY:
                di_args = deserialize_discover_by_identity_key_args(params)
                result = self.wallet.discover_by_identity_key(ctx, di_args, originator)
                return write_result_frame(serialize_discover_certificates_result_by_identity(result or {}))

            # DISCOVER_BY_ATTRIBUTES
            if call == WalletWireCall.DISCOVER_BY_ATTRIBUTES:
                da_args = deserialize_discover_by_attributes_args(params)
                result = self.wallet.discover_by_attributes(ctx, da_args, originator)
                return write_result_frame(serialize_discover_certificates_result_by_attr(result or {}))

            # ACQUIRE_CERTIFICATE
            if call == WalletWireCall.ACQUIRE_CERTIFICATE:
                ac_args = deserialize_acquire_certificate_args(params)
                result = self.wallet.acquire_certificate(ctx, ac_args, originator)
                # No specific result payload defined here; return empty
                return write_result_frame(b"")

            # CREATE_HMAC
            if call == WalletWireCall.CREATE_HMAC:
                h_args = deserialize_create_hmac_args(params)
                result = self.wallet.create_hmac(ctx, h_args, originator)
                return write_result_frame(serialize_create_hmac_result(result))

            # VERIFY_HMAC
            if call == WalletWireCall.VERIFY_HMAC:
                vh_args = deserialize_verify_hmac_args(params)
                result = self.wallet.verify_hmac(ctx, vh_args, originator)
                return write_result_frame(serialize_verify_hmac_result(result))

            # CREATE_SIGNATURE
            if call == WalletWireCall.CREATE_SIGNATURE:
                cs_args = deserialize_create_signature_args(params)
                result = self.wallet.create_signature(ctx, cs_args, originator)
                return write_result_frame(serialize_create_signature_result(result))

            # VERIFY_SIGNATURE
            if call == WalletWireCall.VERIFY_SIGNATURE:
                vs_args = deserialize_verify_signature_args(params)
                result = self.wallet.verify_signature(ctx, vs_args, originator)
                return write_result_frame(serialize_verify_signature_result(result))

            # LIST_OUTPUTS
            if call == WalletWireCall.LIST_OUTPUTS:
                lo_args = deserialize_list_outputs_args(params)
                result = self.wallet.list_outputs(ctx, lo_args, originator)
                return write_result_frame(serialize_list_outputs_result(result or {}))

            # RELINQUISH_OUTPUT
            if call == WalletWireCall.RELINQUISH_OUTPUT:
                ro_args = deserialize_relinquish_output_args(params)
                result = self.wallet.relinquish_output(ctx, ro_args, originator)
                return write_result_frame(serialize_relinquish_output_result(result or {}))

            # GET_HEADER_FOR_HEIGHT
            if call == WalletWireCall.GET_HEADER_FOR_HEIGHT:
                from bsv.wallet.serializer.get_network import deserialize_get_header_args, serialize_get_header_result
                gha = deserialize_get_header_args(params)
                result = self.wallet.get_header_for_height(ctx, gha, originator) or {}
                return write_result_frame(serialize_get_header_result(result))

            # GET_NETWORK
            if call == WalletWireCall.GET_NETWORK:
                from bsv.wallet.serializer.get_network import serialize_get_network_result
                result = self.wallet.get_network(ctx, {}, originator) or {}
                return write_result_frame(serialize_get_network_result(result))

            # GET_VERSION
            if call == WalletWireCall.GET_VERSION:
                from bsv.wallet.serializer.get_network import serialize_get_version_result
                result = self.wallet.get_version(ctx, {}, originator) or {}
                return write_result_frame(serialize_get_version_result(result))

            # GET_HEIGHT
            if call == WalletWireCall.GET_HEIGHT:
                from bsv.wallet.serializer.get_network import serialize_get_height_result
                result = self.wallet.get_height(ctx, {}, originator) or {}
                return write_result_frame(serialize_get_height_result(result))

            # GET_PUBLIC_KEY
            if call == WalletWireCall.GET_PUBLIC_KEY:
                gp_args = deserialize_get_public_key_args(params)
                result = self.wallet.get_public_key(ctx, gp_args, originator)
                if isinstance(result, dict) and result.get("error"):
                    return write_result_frame(None, error=str(result.get("error")))
                return write_result_frame(serialize_get_public_key_result(result or {}))

            # REVEAL_COUNTERPARTY_KEY_LINKAGE
            if call == WalletWireCall.REVEAL_COUNTERPARTY_KEY_LINKAGE:
                r_args = deserialize_reveal_counterparty_key_linkage_args(params)
                result = self.wallet.reveal_counterparty_key_linkage(ctx, r_args, originator)
                if isinstance(result, dict) and result.get("error"):
                    return write_result_frame(None, error=str(result.get("error")))
                return write_result_frame(serialize_key_linkage_result(result or {}))

            # REVEAL_SPECIFIC_KEY_LINKAGE
            if call == WalletWireCall.REVEAL_SPECIFIC_KEY_LINKAGE:
                rs_args = deserialize_reveal_specific_key_linkage_args(params)
                result = self.wallet.reveal_specific_key_linkage(ctx, rs_args, originator)
                if isinstance(result, dict) and result.get("error"):
                    return write_result_frame(None, error=str(result.get("error")))
                return write_result_frame(serialize_key_linkage_result(result or {}))

            # IS_AUTHENTICATED
            if call == WalletWireCall.IS_AUTHENTICATED:
                result = self.wallet.is_authenticated(ctx, None, originator) or {}
                # encode a single-byte boolean per Go serializer
                return write_result_frame(bytes([1]) if bool(result.get("authenticated")) else bytes([0]))

            # WAIT_FOR_AUTHENTICATION
            if call == WalletWireCall.WAIT_FOR_AUTHENTICATION:
                _ = self.wallet.wait_for_authentication(ctx, None, originator)
                return write_result_frame(bytes([1]))

            # デフォルト: そのまま返す（ダミー）
            return write_result_frame(params)
        except Exception as e:
            return write_result_frame(None, error=str(e))
