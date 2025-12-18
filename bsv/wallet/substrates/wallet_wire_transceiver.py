from typing import Any
from .wallet_wire import WalletWire
from .wallet_wire_calls import WalletWireCall
from .serializer import (
    Writer,
    serialize_encrypt_args,
    serialize_decrypt_args,
)
from bsv.wallet.serializer.frame import write_request_frame, read_result_frame
from bsv.wallet.serializer.list_actions import serialize_list_actions_args
from bsv.wallet.serializer.internalize_action import serialize_internalize_action_args
from bsv.wallet.serializer.list_certificates import serialize_list_certificates_args
from bsv.wallet.serializer.list_outputs import serialize_list_outputs_args
from bsv.wallet.serializer.relinquish_output import serialize_relinquish_output_args
from bsv.wallet.serializer.create_hmac import serialize_create_hmac_args
from bsv.wallet.serializer.verify_hmac import serialize_verify_hmac_args
from bsv.wallet.serializer.create_signature import serialize_create_signature_args
from bsv.wallet.serializer.verify_signature import serialize_verify_signature_args
from bsv.wallet.serializer.common import encode_privileged_params, encode_outpoint
from bsv.wallet.serializer.acquire_certificate import serialize_acquire_certificate_args
from bsv.wallet.serializer.prove_certificate import serialize_prove_certificate_args
from bsv.wallet.serializer.get_network import (
    serialize_get_header_args,
    serialize_get_network_args,
    serialize_get_version_args,
    serialize_get_height_args,
)
from bsv.wallet.serializer.get_public_key import serialize_get_public_key_args
from bsv.wallet.serializer.key_linkage import (
    serialize_reveal_counterparty_key_linkage_args,
    serialize_reveal_specific_key_linkage_args,
)

class WalletWireTransceiver:
    def __init__(self, wire: WalletWire):
        self.wire = wire

    def transmit(self, ctx: Any, call: WalletWireCall, originator: str, params: bytes) -> bytes:
        frame = write_request_frame(call.value, originator, params)
        response = self.wire.transmit_to_wallet(ctx, frame)
        return read_result_frame(response)

    def create_action(self, ctx: Any, args: dict, originator: str) -> dict:
        # Use dedicated serializer
        from bsv.wallet.serializer.create_action_args import serialize_create_action_args
        params = serialize_create_action_args(args)
        resp = self.transmit(ctx, WalletWireCall.CREATE_ACTION, originator, params)
        from bsv.wallet.serializer.create_action_result import (
            deserialize_create_action_result,
        )
        return deserialize_create_action_result(resp)

    # Decoded (structured) results helpers
    def create_action_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.create_action(ctx, args, originator)
        from bsv.wallet.serializer.create_action_result import (
            deserialize_create_action_result,
        )
        return deserialize_create_action_result(resp)

    # --- 以下、各wallet操作メソッドのスケルトン ---
    def sign_action(self, ctx: Any, args: dict, originator: str) -> dict:
        from bsv.wallet.serializer.sign_action_args import serialize_sign_action_args
        params = serialize_sign_action_args(args)
        resp = self.transmit(ctx, WalletWireCall.SIGN_ACTION, originator, params)
        from bsv.wallet.serializer.sign_action_result import (
            deserialize_sign_action_result,
        )
        return deserialize_sign_action_result(resp)

    def sign_action_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.sign_action(ctx, args, originator)
        from bsv.wallet.serializer.sign_action_result import (
            deserialize_sign_action_result,
        )
        return deserialize_sign_action_result(resp)

    def abort_action(self, ctx: Any, args: dict, originator: str) -> dict:
        from bsv.wallet.serializer.abort_action import serialize_abort_action_args
        params = serialize_abort_action_args(args)
        resp = self.transmit(ctx, WalletWireCall.ABORT_ACTION, originator, params)
        from bsv.wallet.serializer.abort_action import deserialize_abort_action_result
        return deserialize_abort_action_result(resp)

    def abort_action_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.abort_action(ctx, args, originator)
        from bsv.wallet.serializer.abort_action import deserialize_abort_action_result
        return deserialize_abort_action_result(resp)

    def list_actions(self, ctx: Any, args: dict, originator: str) -> dict:
        params = serialize_list_actions_args(args)
        resp = self.transmit(ctx, WalletWireCall.LIST_ACTIONS, originator, params)
        from bsv.wallet.serializer.list_actions import deserialize_list_actions_result
        return deserialize_list_actions_result(resp)

    def list_actions_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.list_actions(ctx, args, originator)
        from bsv.wallet.serializer.list_actions import deserialize_list_actions_result
        return deserialize_list_actions_result(resp)

    def internalize_action(self, ctx: Any, args: dict, originator: str) -> dict:
        if "tx" not in args:
            raise ValueError("Missing required argument: tx")
        params = serialize_internalize_action_args(args)
        resp = self.transmit(ctx, WalletWireCall.INTERNALIZE_ACTION, originator, params)
        from bsv.wallet.serializer.internalize_action import (
            deserialize_internalize_action_result,
        )
        return deserialize_internalize_action_result(resp)

    def internalize_action_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.internalize_action(ctx, args, originator)
        from bsv.wallet.serializer.internalize_action import (
            deserialize_internalize_action_result,
        )
        return deserialize_internalize_action_result(resp)

    def list_outputs(self, ctx: Any, args: dict, originator: str) -> dict:
        params = serialize_list_outputs_args(args)
        resp = self.transmit(ctx, WalletWireCall.LIST_OUTPUTS, originator, params)
        from bsv.wallet.serializer.list_outputs import deserialize_list_outputs_result
        return deserialize_list_outputs_result(resp)

    def list_outputs_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.list_outputs(ctx, args, originator)
        from bsv.wallet.serializer.list_outputs import deserialize_list_outputs_result
        return deserialize_list_outputs_result(resp)

    def relinquish_output(self, ctx: Any, args: dict, originator: str) -> dict:
        if not args.get("outpoint"):
            raise ValueError("Missing required argument: outpoint")
        # Basic validation for outpoint format (should be txid:vout)
        outpoint = args["outpoint"]
        if not isinstance(outpoint, str) or ":" not in outpoint:
            raise ValueError("Invalid outpoint format")
        params = serialize_relinquish_output_args(args)
        resp = self.transmit(ctx, WalletWireCall.RELINQUISH_OUTPUT, originator, params)
        from bsv.wallet.serializer.relinquish_output import (
            deserialize_relinquish_output_result,
        )
        return deserialize_relinquish_output_result(resp)

    def relinquish_output_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.relinquish_output(ctx, args, originator)
        from bsv.wallet.serializer.relinquish_output import (
            deserialize_relinquish_output_result,
        )
        return deserialize_relinquish_output_result(resp)

    def get_public_key(self, ctx: Any, args: dict, originator: str) -> dict:
        params = serialize_get_public_key_args(args)
        resp = self.transmit(ctx, WalletWireCall.GET_PUBLIC_KEY, originator, params)
        from bsv.wallet.serializer.get_public_key import (
            deserialize_get_public_key_result,
        )
        return deserialize_get_public_key_result(resp)

    def get_public_key_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.get_public_key(ctx, args, originator)
        from bsv.wallet.serializer.get_public_key import (
            deserialize_get_public_key_result,
        )
        return deserialize_get_public_key_result(resp)

    def reveal_counterparty_key_linkage(self, ctx: Any, args: dict, originator: str) -> dict:
        if not args.get('counterparty'):
            raise ValueError("Missing required argument: counterparty")
        params = serialize_reveal_counterparty_key_linkage_args(args)
        resp = self.transmit(ctx, WalletWireCall.REVEAL_COUNTERPARTY_KEY_LINKAGE, originator, params)
        from bsv.wallet.serializer.key_linkage import deserialize_key_linkage_result
        return deserialize_key_linkage_result(resp)

    def reveal_counterparty_key_linkage_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.reveal_counterparty_key_linkage(ctx, args, originator)
        from bsv.wallet.serializer.key_linkage import deserialize_key_linkage_result
        return deserialize_key_linkage_result(resp)

    def reveal_specific_key_linkage(self, ctx: Any, args: dict, originator: str) -> dict:
        if not args.get('protocolID'):
            raise ValueError("Missing required argument: protocolID")
        params = serialize_reveal_specific_key_linkage_args(args)
        resp = self.transmit(ctx, WalletWireCall.REVEAL_SPECIFIC_KEY_LINKAGE, originator, params)
        from bsv.wallet.serializer.key_linkage import deserialize_key_linkage_result
        return deserialize_key_linkage_result(resp)

    def reveal_specific_key_linkage_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.reveal_specific_key_linkage(ctx, args, originator)
        from bsv.wallet.serializer.key_linkage import deserialize_key_linkage_result
        return deserialize_key_linkage_result(resp)

    def encrypt(self, ctx: Any, args: dict, originator: str) -> dict:
        # Ensure forSelf flag (encrypting party -> forSelf=False)
        if 'encryption_args' in args:
            args['encryption_args']['forSelf'] = False
        params = serialize_encrypt_args(args)
        resp = self.transmit(ctx, WalletWireCall.ENCRYPT, originator, params)
        from bsv.wallet.serializer.encrypt import deserialize_encrypt_result
        return deserialize_encrypt_result(resp)

    def encrypt_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.encrypt(ctx, args, originator)
        from bsv.wallet.serializer.encrypt import deserialize_encrypt_result
        return deserialize_encrypt_result(resp)

    def decrypt(self, ctx: Any, args: dict, originator: str) -> dict:
        if 'encryption_args' in args:
            args['encryption_args']['forSelf'] = False
        params = serialize_decrypt_args(args)
        resp = self.transmit(ctx, WalletWireCall.DECRYPT, originator, params)
        from bsv.wallet.serializer.decrypt import deserialize_decrypt_result
        return deserialize_decrypt_result(resp)

    def decrypt_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.decrypt(ctx, args, originator)
        from bsv.wallet.serializer.decrypt import deserialize_decrypt_result
        return deserialize_decrypt_result(resp)

    def create_hmac(self, ctx: Any, args: dict, originator: str) -> dict:
        if not args.get('data'):
            raise ValueError("Missing required argument: data")
        enc = args.get('encryption_args', {})
        proto = enc.get('protocolID') or {}
        key_id = enc.get('keyID') or ''
        counterparty = enc.get('counterparty')
        cp_dict = None
        if isinstance(counterparty, (bytes, bytearray)):
            cp_dict = {'type': 13, 'counterparty': bytes(counterparty)}
        elif isinstance(counterparty, str):
            try:
                cp_dict = {'type': 13, 'counterparty': bytes.fromhex(counterparty)}
            except Exception:
                cp_dict = {'type': 0}
        elif isinstance(counterparty, dict):
            cp_dict = counterparty
        else:
            cp_dict = {'type': 0}
        flat_args = {
            'protocolID': {'securityLevel': int(proto.get('securityLevel', 0)), 'protocol': proto.get('protocol', '')} if isinstance(proto, dict) else proto,
            'keyID': key_id,
            'counterparty': cp_dict,
            'privileged': enc.get('privileged'),
            'privilegedReason': enc.get('privilegedReason', ''),
            'data': args.get('data', b''),
            'seekPermission': args.get('seekPermission'),
        }
        params = serialize_create_hmac_args(flat_args)
        resp = self.transmit(ctx, WalletWireCall.CREATE_HMAC, originator, params)
        return {"hmac": resp}

    def create_hmac_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.create_hmac(ctx, args, originator)
        return {"hmac": resp}

    def verify_hmac(self, ctx: Any, args: dict, originator: str) -> dict:
        if not args.get('hmac'):
            raise ValueError("Missing required argument: hmac")
        enc = args.get('encryption_args', {})
        proto = enc.get('protocolID') or {}
        key_id = enc.get('keyID') or ''
        counterparty = enc.get('counterparty')
        cp_dict = None
        if isinstance(counterparty, (bytes, bytearray)):
            cp_dict = {'type': 13, 'counterparty': bytes(counterparty)}
        elif isinstance(counterparty, str):
            try:
                cp_dict = {'type': 13, 'counterparty': bytes.fromhex(counterparty)}
            except Exception:
                cp_dict = {'type': 0}
        elif isinstance(counterparty, dict):
            cp_dict = counterparty
        else:
            cp_dict = {'type': 0}
        flat_args = {
            'protocolID': {'securityLevel': int(proto.get('securityLevel', 0)), 'protocol': proto.get('protocol', '')} if isinstance(proto, dict) else proto,
            'keyID': key_id,
            'counterparty': cp_dict,
            'privileged': enc.get('privileged'),
            'privilegedReason': enc.get('privilegedReason', ''),
            'hmac': args.get('hmac', b''),
            'data': args.get('data', b''),
            'seekPermission': args.get('seekPermission'),
        }
        params = serialize_verify_hmac_args(flat_args)
        resp = self.transmit(ctx, WalletWireCall.VERIFY_HMAC, originator, params)
        return {"valid": bool(resp and len(resp) > 0 and resp[0] == 1)}

    def verify_hmac_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.verify_hmac(ctx, args, originator)
        return {"valid": bool(resp and len(resp) > 0 and resp[0] == 1)}

    def create_signature(self, ctx: Any, args: dict, originator: str) -> dict:
        if not args.get('data') and not args.get('hashToDirectlySign'):
            raise ValueError("Missing required argument: data or hashToDirectlySign")
        enc = args.get('encryption_args', {})
        proto = enc.get('protocolID') or {}
        key_id = enc.get('keyID') or ''
        counterparty = enc.get('counterparty')
        cp_dict = None
        if isinstance(counterparty, (bytes, bytearray)):
            cp_dict = {'type': 13, 'counterparty': bytes(counterparty)}
        elif isinstance(counterparty, str):
            try:
                cp_dict = {'type': 13, 'counterparty': bytes.fromhex(counterparty)}
            except Exception:
                cp_dict = {'type': 0}
        elif isinstance(counterparty, dict):
            cp_dict = counterparty
        else:
            cp_dict = {'type': 0}
        flat_args = {
            'protocolID': {'securityLevel': int(proto.get('securityLevel', 0)), 'protocol': proto.get('protocol', '')} if isinstance(proto, dict) else proto,
            'keyID': key_id,
            'counterparty': cp_dict,
            'privileged': enc.get('privileged'),
            'privilegedReason': enc.get('privilegedReason', ''),
            'data': args.get('data'),
            'hashToDirectlySign': args.get('hashToDirectlySign'),
            'seekPermission': args.get('seekPermission'),
        }
        params = serialize_create_signature_args(flat_args)
        resp = self.transmit(ctx, WalletWireCall.CREATE_SIGNATURE, originator, params)
        return {"signature": resp}

    def create_signature_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.create_signature(ctx, args, originator)
        return {"signature": resp}

    def verify_signature(self, ctx: Any, args: dict, originator: str) -> dict:
        enc = args.get('encryption_args', {})
        proto = enc.get('protocolID') or {}
        key_id = enc.get('keyID') or ''
        counterparty = enc.get('counterparty')
        cp_dict = None
        if isinstance(counterparty, (bytes, bytearray)):
            cp_dict = {'type': 13, 'counterparty': bytes(counterparty)}
        elif isinstance(counterparty, str):
            try:
                cp_dict = {'type': 13, 'counterparty': bytes.fromhex(counterparty)}
            except Exception:
                cp_dict = {'type': 0}
        elif isinstance(counterparty, dict):
            cp_dict = counterparty
        else:
            cp_dict = {'type': 0}
        flat_args = {
            'protocolID': {'securityLevel': int(proto.get('securityLevel', 0)), 'protocol': proto.get('protocol', '')} if isinstance(proto, dict) else proto,
            'keyID': key_id,
            'counterparty': cp_dict,
            'privileged': enc.get('privileged'),
            'privilegedReason': enc.get('privilegedReason', ''),
            'forSelf': enc.get('forSelf'),
            'signature': args.get('signature', b''),
            'data': args.get('data'),
            'hashToDirectlyVerify': args.get('hashToDirectlyVerify'),
            'seekPermission': args.get('seekPermission'),
        }
        params = serialize_verify_signature_args(flat_args)
        resp = self.transmit(ctx, WalletWireCall.VERIFY_SIGNATURE, originator, params)
        return {"valid": bool(resp and len(resp) > 0 and resp[0] == 1)}

    def verify_signature_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.verify_signature(ctx, args, originator)
        return {"valid": bool(resp and len(resp) > 0 and resp[0] == 1)}

    def acquire_certificate(self, ctx: Any, args: dict, originator: str) -> dict:
        params = serialize_acquire_certificate_args(args)
        _ = self.transmit(ctx, WalletWireCall.ACQUIRE_CERTIFICATE, originator, params)
        return {}

    def acquire_certificate_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        # Current processor does not return payload for acquire; return empty structure
        _ = self.acquire_certificate(ctx, args, originator)
        return {}

    def list_certificates(self, ctx: Any, args: dict, originator: str) -> dict:
        params = serialize_list_certificates_args(args)
        resp = self.transmit(ctx, WalletWireCall.LIST_CERTIFICATES, originator, params)
        from bsv.wallet.serializer.list_certificates import (
            deserialize_list_certificates_result,
        )
        return deserialize_list_certificates_result(resp)

    def list_certificates_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.list_certificates(ctx, args, originator)
        from bsv.wallet.serializer.list_certificates import (
            deserialize_list_certificates_result,
        )
        return deserialize_list_certificates_result(resp)

    def prove_certificate(self, ctx: Any, args: dict, originator: str) -> dict:
        if not args.get('verifier'):
            raise ValueError("Missing required argument: verifier")
        params = serialize_prove_certificate_args(args)
        resp = self.transmit(ctx, WalletWireCall.PROVE_CERTIFICATE, originator, params)
        from bsv.wallet.serializer.prove_certificate import (
            deserialize_prove_certificate_result,
        )
        return deserialize_prove_certificate_result(resp)

    def prove_certificate_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.prove_certificate(ctx, args, originator)
        from bsv.wallet.serializer.prove_certificate import (
            deserialize_prove_certificate_result,
        )
        return deserialize_prove_certificate_result(resp)

    def relinquish_certificate(self, ctx: Any, args: dict, originator: str) -> dict:
        w = Writer()
        # Type: bytes (32 bytes)
        w.write_bytes(args.get('type', b''))
        # SerialNumber: bytes (32 bytes)
        w.write_bytes(args.get('serialNumber', b''))
        # Certifier: bytes (compressed pubkey, 33 bytes)
        w.write_bytes(args.get('certifier', b''))
        params = w.to_bytes()
        resp = self.transmit(ctx, WalletWireCall.RELINQUISH_CERTIFICATE, originator, params)
        from bsv.wallet.serializer.relinquish_certificate import (
            deserialize_relinquish_certificate_result,
        )
        return deserialize_relinquish_certificate_result(resp)

    def relinquish_certificate_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.relinquish_certificate(ctx, args, originator)
        from bsv.wallet.serializer.relinquish_certificate import (
            deserialize_relinquish_certificate_result,
        )
        return deserialize_relinquish_certificate_result(resp)

    def discover_by_identity_key(self, ctx: Any, args: dict, originator: str) -> dict:
        w = Writer()
        # identityKey: bytes (compressed pubkey, 33 bytes)
        w.write_bytes(args.get('identityKey', b''))
        # limit: optional uint32
        w.write_optional_uint32(args.get('limit'))
        # offset: optional uint32
        w.write_optional_uint32(args.get('offset'))
        # seekPermission: optional bool
        seek = args.get('seekPermission')
        if seek is not None:
            w.write_byte(1 if seek else 0)
        else:
            w.write_negative_one_byte()
        params = w.to_bytes()
        resp = self.transmit(ctx, WalletWireCall.DISCOVER_BY_IDENTITY_KEY, originator, params)
        from bsv.wallet.serializer.discover_by_identity_key import (
            deserialize_discover_certificates_result,
        )
        return deserialize_discover_certificates_result(resp)

    def discover_by_identity_key_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.discover_by_identity_key(ctx, args, originator)
        from bsv.wallet.serializer.discover_by_identity_key import (
            deserialize_discover_certificates_result,
        )
        return deserialize_discover_certificates_result(resp)

    def discover_by_attributes(self, ctx: Any, args: dict, originator: str) -> dict:
        w = Writer()
        # attributes: dict[str, str] (sorted by key)
        attributes = args.get('attributes', {})
        keys = sorted(attributes.keys())
        w.write_varint(len(keys))
        for k in keys:
            w.write_int_bytes(k.encode())
            w.write_int_bytes(attributes[k].encode())
        # limit: optional uint32
        w.write_optional_uint32(args.get('limit'))
        # offset: optional uint32
        w.write_optional_uint32(args.get('offset'))
        # seekPermission: optional bool
        seek = args.get('seekPermission')
        if seek is not None:
            w.write_byte(1 if seek else 0)
        else:
            w.write_negative_one_byte()
        params = w.to_bytes()
        resp = self.transmit(ctx, WalletWireCall.DISCOVER_BY_ATTRIBUTES, originator, params)
        from bsv.wallet.serializer.discover_by_attributes import (
            deserialize_discover_certificates_result,
        )
        return deserialize_discover_certificates_result(resp)

    def discover_by_attributes_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.discover_by_attributes(ctx, args, originator)
        from bsv.wallet.serializer.discover_by_attributes import (
            deserialize_discover_certificates_result,
        )
        return deserialize_discover_certificates_result(resp)

    def is_authenticated(self, ctx: Any = None, originator: str = None) -> dict:
        resp = self.transmit(ctx, WalletWireCall.IS_AUTHENTICATED, originator, b'')
        if not resp:
            return {}
        return {"authenticated": bool(resp[0] == 1)}

    def is_authenticated_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.is_authenticated(ctx, originator)
        if not resp:
            # No payload provided currently by processor; unknown state
            return {}
        return {"authenticated": bool(resp[0] == 1)}

    def wait_for_authentication(self, ctx: Any = None, originator: str = None) -> dict:
        _ = self.transmit(ctx, WalletWireCall.WAIT_FOR_AUTHENTICATION, originator, b'')
        return {"authenticated": True}

    def wait_for_authentication_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.wait_for_authentication(ctx, originator)
        # Go's DeserializeWaitAuthenticatedResult returns Authenticated=true regardless of payload
        if resp is None:
            return {"authenticated": True}
        return {"authenticated": True}

    def get_height(self, ctx: Any, args: dict, originator: str) -> dict:
        if not args.get('header'):
            raise ValueError("Missing required argument: header")
        params = serialize_get_height_args(args)
        resp = self.transmit(ctx, WalletWireCall.GET_HEIGHT, originator, params)
        from bsv.wallet.serializer.get_network import deserialize_get_height_result
        return deserialize_get_height_result(resp)

    def get_height_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.get_height(ctx, args, originator)
        from bsv.wallet.serializer.get_network import deserialize_get_height_result
        return deserialize_get_height_result(resp)

    def get_header_for_height(self, ctx: Any, args: dict, originator: str) -> dict:
        params = serialize_get_header_args(args)
        resp = self.transmit(ctx, WalletWireCall.GET_HEADER_FOR_HEIGHT, originator, params)
        from bsv.wallet.serializer.get_network import deserialize_get_header_result
        return deserialize_get_header_result(resp)

    def get_header_for_height_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.get_header_for_height(ctx, args, originator)
        from bsv.wallet.serializer.get_network import deserialize_get_header_result
        return deserialize_get_header_result(resp)

    def get_network(self, ctx: Any, args: dict, originator: str) -> dict:
        params = serialize_get_network_args(args)
        resp = self.transmit(ctx, WalletWireCall.GET_NETWORK, originator, params)
        from bsv.wallet.serializer.get_network import deserialize_get_network_result
        return deserialize_get_network_result(resp)

    def get_network_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.get_network(ctx, args, originator)
        from bsv.wallet.serializer.get_network import deserialize_get_network_result
        return deserialize_get_network_result(resp)

    def get_version(self, ctx: Any, args: dict, originator: str) -> dict:
        params = serialize_get_version_args(args)
        resp = self.transmit(ctx, WalletWireCall.GET_VERSION, originator, params)
        from bsv.wallet.serializer.get_network import deserialize_get_version_result
        return deserialize_get_version_result(resp)

    def get_version_decoded(self, ctx: Any, args: dict, originator: str) -> dict:
        resp = self.get_version(ctx, args, originator)
        from bsv.wallet.serializer.get_network import deserialize_get_version_result
        return deserialize_get_version_result(resp)
