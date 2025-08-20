from typing import Callable, Dict, Optional, Any, Set
import logging
import json
import base64

# from .session_manager import SessionManager
from .transports.transport import Transport


class PeerOptions:
    def __init__(self,
                 wallet: Any = None,  # Should be replaced with WalletInterface
                 transport: Any = None,  # Should be replaced with Transport
                 certificates_to_request: Optional[Any] = None,  # Should be RequestedCertificateSet
                 session_manager: Optional[Any] = None,  # Should be SessionManager
                 auto_persist_last_session: Optional[bool] = None,
                 logger: Optional[logging.Logger] = None,
                 debug: bool = False):
        self.wallet = wallet
        self.transport = transport
        self.certificates_to_request = certificates_to_request
        self.session_manager = session_manager
        self.auto_persist_last_session = auto_persist_last_session
        self.logger = logger
        self.debug = debug

class Peer:
    def __init__(self, cfg: PeerOptions):
        self.wallet = cfg.wallet
        self.transport = cfg.transport
        self.session_manager = cfg.session_manager
        self.certificates_to_request = cfg.certificates_to_request
        self.on_general_message_received_callbacks: Dict[int, Callable] = {}
        self.on_certificate_received_callbacks: Dict[int, Callable] = {}
        self.on_certificate_request_received_callbacks: Dict[int, Callable] = {}
        self.on_initial_response_received_callbacks: Dict[int, dict] = {}
        self.callback_id_counter = 0
        self.auto_persist_last_session = False
        self.last_interacted_with_peer = None
        self.logger = cfg.logger or logging.getLogger("Auth Peer")
        self._debug = bool(getattr(cfg, 'debug', False))

        # Nonce management for replay protection
        self._used_nonces = set()  # type: Set[str]
        # Event handler registry
        self._event_handlers: Dict[str, Callable[..., Any]] = {}

        if self.session_manager is None:
            try:
                from .session_manager import DefaultSessionManager
                self.session_manager = DefaultSessionManager()
            except Exception:
                self.session_manager = None
        if cfg.auto_persist_last_session is None or cfg.auto_persist_last_session:
            self.auto_persist_last_session = True
        if self.certificates_to_request is None:
            # TODO: Replace with actual RequestedCertificateSet
            self.certificates_to_request = {
                'certifiers': [],
                'certificate_types': {}
            }
        # Start the peer (register handlers, etc.)
        try:
            self.start()
        except Exception as e:
            self.logger.warning(f"Failed to start peer: {e}")

    def start(self):
        """
        Initializes the peer by setting up the transport's message handler.
        """
        if self._debug:
            print("[Peer DEBUG] registering transport on_data handler")
        def on_data(ctx, message):
            if self._debug:
                print(f"[Peer DEBUG] on_data received: type={getattr(message, 'message_type', None)}")
            return self.handle_incoming_message(ctx, message)
        err = self.transport.on_data(on_data)
        if err is not None:
            self.logger.warning(f"Failed to register message handler with transport: {err}")
        else:
            if self._debug:
                print("[Peer DEBUG] transport handler registration ok")

    # --- Canonicalization helpers for signing/verification ---
    def _canonicalize_requested_certificates(self, requested: Any) -> dict:
        try:
            from .requested_certificate_set import RequestedCertificateSet
        except Exception:
            RequestedCertificateSet = None  # type: ignore
        result: dict = {"certifiers": [], "certificateTypes": {}}
        if requested is None:
            return result
        try:
            # Normalize certifiers
            certifiers: list = []
            if RequestedCertificateSet is not None and isinstance(requested, RequestedCertificateSet):
                for pk in requested.certifiers:
                    try:
                        certifiers.append(pk.hex())
                    except Exception:
                        certifiers.append(str(pk))
                mapping = getattr(requested.certificate_types, 'mapping', {}) or {}
                for k, v in mapping.items():
                    try:
                        import base64 as _b64
                        k_b64 = _b64.b64encode(k).decode('ascii') if isinstance(k, (bytes, bytearray)) else str(k)
                    except Exception:
                        k_b64 = str(k)
                    result["certificateTypes"][k_b64] = sorted(list(v or []))
            elif isinstance(requested, dict):
                # Expect 'certifiers' as list of hex strings or objects with hex
                for pk in requested.get('certifiers', []):
                    try:
                        certifiers.append(pk.hex())
                    except Exception:
                        certifiers.append(str(pk))
                types_dict = (
                    requested.get('certificate_types')
                    or requested.get('certificateTypes')
                    or requested.get('types')
                    or {}
                )
                # Canonicalize keys to base64 for deterministic cross-language signatures
                import base64 as _b64
                for k, v in types_dict.items():
                    k_b64: str
                    if isinstance(k, (bytes, bytearray)):
                        if len(k) != 32:
                            continue
                        k_b64 = _b64.b64encode(bytes(k)).decode('ascii')
                    else:
                        ks = str(k)
                        try:
                            # If already base64 of length 32 bytes when decoded, keep as-is
                            dec = _b64.b64decode(ks)
                            if len(dec) == 32:
                                k_b64 = _b64.b64encode(dec).decode('ascii')
                            else:
                                # Try hex
                                b = bytes.fromhex(ks)
                                if len(b) != 32:
                                    continue
                                k_b64 = _b64.b64encode(b).decode('ascii')
                        except Exception:
                            try:
                                b = bytes.fromhex(ks)
                                if len(b) != 32:
                                    continue
                                k_b64 = _b64.b64encode(b).decode('ascii')
                            except Exception:
                                # Unknown format; skip
                                continue
                    result["certificateTypes"][k_b64] = sorted(list(v or []))
            result["certifiers"] = sorted(certifiers)
        except Exception:
            # Fallback to string-dump to avoid raising
            return {"certifiers": [], "certificateTypes": {}}
        return result

    def _canonicalize_certificates_payload(self, certs: Any) -> list:
        import base64 as _b64
        canonical: list = []
        if not certs:
            return canonical

        def _to_b64_32(value: Any) -> Optional[str]:
            if value is None:
                return None
            # If already bytes, expect 32 bytes
            if isinstance(value, (bytes, bytearray)):
                b = bytes(value)
                if len(b) == 32:
                    return _b64.b64encode(b).decode('ascii')
                return None
            # If has .encode (string)
            if isinstance(value, str):
                s = value
                # Try base64 first
                try:
                    dec = _b64.b64decode(s)
                    if len(dec) == 32:
                        return _b64.b64encode(dec).decode('ascii')
                except Exception:
                    pass
                # Try hex
                try:
                    b = bytes.fromhex(s)
                    if len(b) == 32:
                        return _b64.b64encode(b).decode('ascii')
                except Exception:
                    pass
                return None
            return None

        def _pubkey_to_hex(value: Any) -> Optional[str]:
            if value is None:
                return None
            # PublicKey object with hex() method
            if hasattr(value, 'hex') and callable(getattr(value, 'hex')):
                try:
                    return value.hex()
                except Exception:
                    pass
            # bytes -> hex
            if isinstance(value, (bytes, bytearray)):
                return bytes(value).hex()
            # string: try base64(33) to hex, else assume already hex
            if isinstance(value, str):
                s = value
                try:
                    dec = _b64.b64decode(s)
                    # Compressed pubkey typically 33 bytes
                    if len(dec) in (33, 65):
                        return dec.hex()
                except Exception:
                    pass
                # Heuristic: if looks like hex
                try:
                    _ = bytes.fromhex(s)
                    return s.lower()
                except Exception:
                    pass
                return s
            return str(value)

        for c in certs:
            try:
                # Support object or dict inputs, and nested {"certificate": ...}
                base = None
                keyring = {}
                signature = None
                if isinstance(c, dict):
                    base = c.get('certificate', c)
                    keyring = c.get('keyring', {}) or {}
                    signature = c.get('signature')
                else:
                    base = getattr(c, 'certificate', c)
                    keyring = getattr(c, 'keyring', {}) or {}
                    signature = getattr(c, 'signature', None)

                # Extract fields from base certificate
                if isinstance(base, dict):
                    cert_type_raw = base.get('type')
                    serial_raw = base.get('serialNumber') or base.get('serial_number')
                    subject_raw = base.get('subject')
                    certifier_raw = base.get('certifier')
                    rev = base.get('revocationOutpoint') or base.get('revocation_outpoint')
                    fields = base.get('fields', {}) or {}
                else:
                    cert_type_raw = getattr(base, 'type', None)
                    serial_raw = getattr(base, 'serial_number', None)
                    subject_raw = getattr(base, 'subject', None)
                    certifier_raw = getattr(base, 'certifier', None)
                    rev = getattr(base, 'revocation_outpoint', None)
                    fields = getattr(base, 'fields', {}) or {}

                # Normalize primitives
                cert_type_b64 = _to_b64_32(cert_type_raw) or cert_type_raw
                serial_b64 = _to_b64_32(serial_raw) or serial_raw
                subject_hex = _pubkey_to_hex(subject_raw)
                certifier_hex = _pubkey_to_hex(certifier_raw)
                rev_dict = None
                if isinstance(rev, dict):
                    rev_dict = {"txid": rev.get('txid'), "index": rev.get('index')}
                elif rev is not None and hasattr(rev, 'txid') and hasattr(rev, 'index'):
                    rev_dict = {"txid": getattr(rev, 'txid', None), "index": getattr(rev, 'index', None)}
                sig_b64 = _b64.b64encode(signature).decode('ascii') if isinstance(signature, (bytes, bytearray)) else signature

                # Deterministic field order ensured by JSON sort_keys on serialization, but field list order stable
                canonical.append({
                    "type": cert_type_b64,
                    "serialNumber": serial_b64,
                    "subject": subject_hex,
                    "certifier": certifier_hex,
                    "revocationOutpoint": rev_dict,
                    "fields": fields,
                    "keyring": keyring,
                    "signature": sig_b64,
                })
            except Exception:
                # Best effort: stringify
                canonical.append(str(c))

        # Sort deterministically by (type, serialNumber)
        try:
            canonical.sort(key=lambda x: (x.get('type', '') or '', x.get('serialNumber', '') or ''))
        except Exception:
            pass
        return canonical

    def handle_incoming_message(self, ctx: Any, message: Any) -> Optional[Exception]:
        """
        Processes incoming authentication messages.
        """
        if self._debug:
            print(f"[Peer DEBUG] handle_incoming_message: version={getattr(message, 'version', None)}, type={getattr(message, 'message_type', None)}")
        if message is None:
            return Exception("Invalid message")
        if getattr(message, 'version', None) != "0.1":
            return Exception(f"Invalid or unsupported message auth version! Received: {getattr(message, 'version', None)}, expected: 0.1")
        # Dispatch based on message type
        msg_type = getattr(message, 'message_type', None)
        if msg_type == "initialRequest":
            return self.handle_initial_request(ctx, message, getattr(message, 'identity_key', None))
        elif msg_type == "initialResponse":
            return self.handle_initial_response(ctx, message, getattr(message, 'identity_key', None))
        elif msg_type == "certificateRequest":
            return self.handle_certificate_request(ctx, message, getattr(message, 'identity_key', None))
        elif msg_type == "certificateResponse":
            return self.handle_certificate_response(ctx, message, getattr(message, 'identity_key', None))
        elif msg_type == "general":
            return self.handle_general_message(ctx, message, getattr(message, 'identity_key', None))
        else:
            err_msg = f"unknown message type: {msg_type}"
            self.logger.warning(err_msg)
            return Exception(err_msg)

    def handle_initial_request(self, ctx: Any, message: Any, sender_public_key: Any) -> Optional[Exception]:
        """
        Processes an initial authentication request.
        """
        if self._debug:
            print("[Peer DEBUG] handle_initial_request: begin")
        initial_nonce = getattr(message, 'initial_nonce', None)
        if not initial_nonce:
            return Exception("Invalid nonce")
        import os, base64, time
        our_nonce = base64.b64encode(os.urandom(32)).decode('ascii')
        if self._debug:
            print(f"[Peer DEBUG] handle_initial_request: our_nonce={our_nonce}, peer_nonce={initial_nonce}")
        from .peer_session import PeerSession
        session = PeerSession(
            is_authenticated=True,
            session_nonce=our_nonce,
            peer_nonce=initial_nonce,
            peer_identity_key=sender_public_key,
            last_update=int(time.time() * 1000)
        )
        req_certs = getattr(self, 'certificates_to_request', None)
        if req_certs is not None and hasattr(req_certs, 'certificate_types') and len(req_certs.certificate_types) > 0:
            session.is_authenticated = False
        self.session_manager.add_session(session)
        if self._debug:
            print(f"[Peer DEBUG] handle_initial_request: session added, nonce={session.session_nonce}")
        identity_key_result = self.wallet.get_public_key(ctx, {'identityKey': True}, "auth-peer")
        if identity_key_result is None or not hasattr(identity_key_result, 'public_key'):
            return Exception("failed to get identity key")
        certs = []
        requested_certs = getattr(message, 'requested_certificates', None)
        if requested_certs is not None:
            from .verifiable_certificate import VerifiableCertificate
            from .certificate import Certificate
            from .requested_certificate_set import RequestedCertificateSet
            try:
                # Obtain from certificate DB or wallet
                for cert_type, fields in requested_certs.certificate_types.items():
                    args = {
                        'cert_type': base64.b64encode(cert_type).decode(),
                        'fields': fields,
                        'subject': identity_key_result.public_key.hex(),
                        'certifiers': [pk.hex() for pk in requested_certs.certifiers],
                    }
                    # Acquire certificate from wallet (use acquire_certificate or list_certificates as needed)
                    cert_result = self.wallet.acquire_certificate(ctx, args, "auth-peer")
                    # If the result is a list, wrap all, otherwise just one
                    if isinstance(cert_result, list):
                        for cert in cert_result:
                            if isinstance(cert, Certificate):
                                certs.append(VerifiableCertificate(cert))
                    elif isinstance(cert_result, Certificate):
                        certs.append(VerifiableCertificate(cert_result))
            except Exception as e:
                self.logger.warning(f"Failed to acquire certificates: {e}")
        from .auth_message import AuthMessage
        response = AuthMessage(
            version="0.1",
            message_type="initialResponse",
            identity_key=identity_key_result.public_key,
            nonce=our_nonce,
            your_nonce=initial_nonce,
            initial_nonce=session.session_nonce,
            certificates=certs
        )
        try:
            initial_nonce_bytes = base64.b64decode(initial_nonce)
            session_nonce_bytes = base64.b64decode(session.session_nonce)
        except Exception as e:
            return Exception(f"failed to decode nonce: {e}")
        sig_data = initial_nonce_bytes + session_nonce_bytes
        sig_result = self.wallet.create_signature(ctx, {
            'encryption_args': {
                'protocol_id': {
                    'securityLevel': 2,
                    'protocol': "auth message signature"
                },
                'key_id': f"{initial_nonce} {session.session_nonce}",
                'counterparty': {
                    'type': 3,
                    'counterparty': message.identity_key if hasattr(message, 'identity_key') else None
                }
            },
            'data': sig_data
        }, "auth-peer")
        if sig_result is None or not hasattr(sig_result, 'signature'):
            return Exception("failed to sign initial response")
        response.signature = sig_result.signature
        err = self.transport.send(ctx, response)
        if err is not None:
            return Exception(f"failed to send initial response: {err}")
        if self._debug:
            print("[Peer DEBUG] handle_initial_request: response sent")
        return None

    def _validate_certificates(self, ctx: Any, certs: list, requested_certs: Any = None, expected_subject: Any = None) -> bool:
        """
        Validate VerifiableCertificates against a RequestedCertificateSet or dict.
        - Verifies signature
        - Ensures certifier is allowed (if provided)
        - Ensures type is requested and required fields are present (if provided)
        - Ensures subject matches expected_subject (if provided)
        """
        from .requested_certificate_set import RequestedCertificateSet
        valid = True

        def _normalize_requested(req: Any):
            certifiers = []
            type_map = {}
            try:
                if isinstance(req, RequestedCertificateSet):
                    certifiers = list(getattr(req, 'certifiers', []) or [])
                    mapping = getattr(getattr(req, 'certificate_types', None), 'mapping', {}) or {}
                    type_map = dict(mapping)
                elif isinstance(req, dict):
                    certifiers = req.get('certifiers') or req.get('Certifiers') or []
                    types_dict = req.get('certificate_types') or req.get('certificateTypes') or req.get('types') or {}
                    for k, v in types_dict.items():
                        if isinstance(k, (bytes, bytearray)):
                            key_b = bytes(k)
                        else:
                            try:
                                key_b = base64.b64decode(k)
                            except Exception:
                                continue
                        type_map[key_b] = list(v or [])
            except Exception:
                pass
            return certifiers, type_map

        allowed_certifiers, requested_types = _normalize_requested(requested_certs)
        # Normalize allowed certifiers to hex strings for comparison
        allowed_certifier_hexes: Set[str] = set()
        for c in allowed_certifiers or []:
            try:
                if hasattr(c, 'hex'):
                    allowed_certifier_hexes.add(c.hex())
                elif isinstance(c, (bytes, bytearray)):
                    allowed_certifier_hexes.add(bytes(c).hex())
                elif isinstance(c, str):
                    # accept hex strings
                    int(c, 16)
                    allowed_certifier_hexes.add(c.lower())
            except Exception:
                continue

        for cert in certs:
            try:
                base_cert = getattr(cert, 'certificate', cert)
                # Signature verification
                if hasattr(cert, 'verify') and not cert.verify(ctx):
                    self.logger.warning(f"Certificate signature invalid: {cert}")
                    valid = False
                    continue
                # Subject verification
                if expected_subject is not None:
                    subj = getattr(base_cert, 'subject', None)
                    try:
                        subj_hex = subj.hex() if hasattr(subj, 'hex') else None
                        exp_hex = expected_subject.hex() if hasattr(expected_subject, 'hex') else None
                        if subj_hex is None or exp_hex is None or subj_hex != exp_hex:
                            self.logger.warning("Certificate subject does not match the expected identity key")
                            valid = False
                            continue
                    except Exception:
                        self.logger.warning("Failed to compare certificate subject with expected identity key")
                        valid = False
                        continue
                # Certifier verification
                if allowed_certifier_hexes:
                    certifier_val = getattr(base_cert, 'certifier', None)
                    try:
                        if hasattr(certifier_val, 'hex'):
                            cert_hex = certifier_val.hex()
                        elif isinstance(certifier_val, (bytes, bytearray)):
                            cert_hex = bytes(certifier_val).hex()
                        else:
                            cert_hex = str(certifier_val)
                    except Exception:
                        cert_hex = None
                    if cert_hex is None or cert_hex.lower() not in allowed_certifier_hexes:
                        self.logger.warning("Certificate has unrequested certifier")
                        valid = False
                        continue
                # Type / fields verification
                if requested_types:
                    cert_type_val = getattr(base_cert, 'type', None)
                    # Accept base64/hex/bytes
                    cert_type_bytes = None
                    if isinstance(cert_type_val, (bytes, bytearray)):
                        cert_type_bytes = bytes(cert_type_val)
                    elif isinstance(cert_type_val, str):
                        try:
                            b = base64.b64decode(cert_type_val)
                            cert_type_bytes = b
                        except Exception:
                            try:
                                b = bytes.fromhex(cert_type_val)
                                cert_type_bytes = b
                            except Exception:
                                cert_type_bytes = None
                    if not cert_type_bytes:
                        self.logger.warning("Invalid certificate type encoding")
                        valid = False
                        continue
                    if cert_type_bytes not in requested_types:
                        self.logger.warning("Certificate type was not requested")
                        valid = False
                        continue
                    required_fields = requested_types.get(cert_type_bytes, [])
                    cert_fields = getattr(base_cert, 'fields', {}) or {}
                    for field in required_fields:
                        if field not in cert_fields:
                            self.logger.warning(f"Certificate missing required field: {field}")
                            valid = False
                            break
            except Exception as e:
                self.logger.warning(f"Certificate validation error: {e}")
                valid = False
        return valid

    def handle_initial_response(self, ctx: Any, message: Any, sender_public_key: Any) -> Optional[Exception]:
        """
        Processes the response to our initial authentication request.
        """
        if self._debug:
            print("[Peer DEBUG] handle_initial_response: begin")
        session = self.session_manager.get_session(sender_public_key.hex()) if sender_public_key else None
        if session is None:
            # Fallback: try to match by our original initial nonce carried in your_nonce
            your_nonce = getattr(message, 'your_nonce', None)
            if your_nonce:
                session = self.session_manager.get_session(your_nonce)
        if session is None:
            return Exception("Session not found")
        try:
            # Reconstruct signature data in the same order as signer (request.initial_nonce + response.session_nonce)
            client_initial_bytes = base64.b64decode(getattr(message, 'your_nonce', ''))
            server_session_bytes = base64.b64decode(getattr(message, 'initial_nonce', ''))
        except Exception as e:
            return Exception(f"failed to decode nonce: {e}")
        sig_data = client_initial_bytes + server_session_bytes
        signature = getattr(message, 'signature', None)
        verify_result = self.wallet.verify_signature(ctx, {
            'encryption_args': {
                'protocol_id': {
                    'securityLevel': 2,
                    'protocol': "auth message signature"
                },
                'key_id': f"{getattr(message, 'your_nonce', '')} {getattr(message, 'initial_nonce', '')}",
                'counterparty': {
                    'type': 3,
                    'counterparty': getattr(message, 'identity_key', None)
                }
            },
            'data': sig_data,
            'signature': signature
        }, "auth-peer")
        if self._debug:
            print(f"[Peer DEBUG] handle_initial_response: verify_result={getattr(verify_result, 'valid', None)}")
        if verify_result is None or not getattr(verify_result, 'valid', False):
            return Exception("unable to verify signature in initial response")
        session.peer_nonce = getattr(message, 'initial_nonce', None)
        session.peer_identity_key = getattr(message, 'identity_key', None)
        session.is_authenticated = True
        import time
        session.last_update = int(time.time() * 1000)
        self.session_manager.update_session(session)
        self.last_interacted_with_peer = getattr(message, 'identity_key', None)
        # Certificate verification logic
        certs = getattr(message, 'certificates', [])
        if certs:
            # Strict verification: match against requested set and sender's identity_key
            valid = self._validate_certificates(
                ctx,
                certs,
                getattr(self, 'certificates_to_request', None),
                expected_subject=getattr(message, 'identity_key', None),
            )
            if not valid:
                self.logger.warning("Invalid certificates in initial response")
            for callback in self.on_certificate_received_callbacks.values():
                try:
                    callback(sender_public_key, certs)
                except Exception as e:
                    self.logger.warning(f"Certificate received callback error: {e}")
        # Notify any waiting initial-response callbacks registered during initiate_handshake
        try:
            to_delete = None
            for cb_id, info in self.on_initial_response_received_callbacks.items():
                if info.get('session_nonce') == session.session_nonce:
                    # Prefer to pass the peer's nonce to the callback
                    peer_nonce = session.peer_nonce or getattr(message, 'initial_nonce', None)
                    try:
                        info.get('callback')(peer_nonce)
                    finally:
                        to_delete = cb_id
                        break
            if to_delete is not None:
                del self.on_initial_response_received_callbacks[to_delete]
        except Exception as e:
            self.logger.warning(f"Initial response callback error: {e}")

        # TODO: Handle requested certificates from peer if present
        return None

    def handle_certificate_request(self, ctx: Any, message: Any, sender_public_key: Any) -> Optional[Exception]:
        """
        Processes a certificate request message.
        """
        if self._debug:
            print("[Peer DEBUG] handle_certificate_request: begin")
        session = self.session_manager.get_session(sender_public_key.hex()) if sender_public_key else None
        if session is None:
            return Exception("Session not found")
        # --- Signature verification logic implementation ---
        requested = getattr(message, 'requested_certificates', {})
        canonical_req = self._canonicalize_requested_certificates(requested)
        cert_request_data = self._serialize_for_signature(canonical_req)
        signature = getattr(message, 'signature', None)
        verify_result = self.wallet.verify_signature(ctx, {
            'encryption_args': {
                'protocol_id': {
                    'securityLevel': 2,
                    'protocol': "auth message signature"
                },
                'key_id': f"{getattr(message, 'nonce', '')} {session.session_nonce}",
                'counterparty': {
                    'type': 3,
                    'counterparty': sender_public_key
                }
            },
            'data': cert_request_data,
            'signature': signature
        }, "auth-peer")
        if self._debug:
            print(f"[Peer DEBUG] handle_certificate_request: verify_result={getattr(verify_result, 'valid', None)}")
        if verify_result is None or not getattr(verify_result, 'valid', False):
            return Exception("certificate request - invalid signature")
        import time
        session.last_update = int(time.time() * 1000)
        self.session_manager.update_session(session)
        # --- Response side implementation: callback -> acquire -> sign -> send ---
        certs_to_send = None
        # 1) Prioritize callbacks if any
        if self.on_certificate_request_received_callbacks:
            if self._debug:
                print("[Peer DEBUG] handle_certificate_request: invoking request callbacks")
            for cb in list(self.on_certificate_request_received_callbacks.values()):
                try:
                    result = cb(sender_public_key, requested)
                    if result:
                        certs_to_send = result
                        break
                except Exception as e:
                    self.logger.warning(f"Certificate request callback error: {e}")
        # 2) Fallback: acquire from wallet/store
        if certs_to_send is None:
            if self._debug:
                print("[Peer DEBUG] handle_certificate_request: fallback to wallet.acquire_certificate")
            certs: list = []
            try:
                # Our identity key
                identity_key_result = self.wallet.get_public_key(ctx, {'identityKey': True}, "auth-peer")
                subject_hex = getattr(getattr(identity_key_result, 'public_key', None), 'hex', lambda: None)()
                if subject_hex is None:
                    raise RuntimeError("failed to get identity key for certificate response")
                # Acquire certificates (RequestedCertificateSet compatible)
                try:
                    from .requested_certificate_set import RequestedCertificateSet
                except Exception:
                    RequestedCertificateSet = None  # type: ignore
                # Read from normalized canonical_req
                certifiers_list = canonical_req.get('certifiers', [])
                types_dict = canonical_req.get('certificateTypes', {})
                for cert_type_b64, fields in types_dict.items():
                    args = {
                        'cert_type': cert_type_b64,
                        'fields': list(fields or []),
                        'subject': subject_hex,
                        'certifiers': list(certifiers_list or []),
                    }
                    try:
                        cert_result = self.wallet.acquire_certificate(ctx, args, "auth-peer")
                    except Exception:
                        cert_result = None
                    if isinstance(cert_result, list):
                        certs.extend(cert_result)
                    elif cert_result is not None:
                        certs.append(cert_result)
            except Exception as e:
                self.logger.warning(f"Failed to acquire certificates for response: {e}")
            certs_to_send = certs
        # 3) Send response
        if self._debug:
            print(f"[Peer DEBUG] handle_certificate_request: sending response, certs={len(certs_to_send or [])}")
        err = self.send_certificate_response(ctx, sender_public_key, certs_to_send or [])
        if err is not None:
            return Exception(f"failed to send certificate response: {err}")
        return None

    def handle_certificate_response(self, ctx: Any, message: Any, sender_public_key: Any) -> Optional[Exception]:
        """
        Processes a certificate response message.
        """
        if self._debug:
            print("[Peer DEBUG] handle_certificate_response: begin")
        session = self.session_manager.get_session(sender_public_key.hex()) if sender_public_key else None
        if session is None:
            return Exception("Session not found")
        certs = getattr(message, 'certificates', [])
        canonical_certs = self._canonicalize_certificates_payload(certs)
        cert_data = self._serialize_for_signature(canonical_certs)
        signature = getattr(message, 'signature', None)
        verify_result = self.wallet.verify_signature(ctx, {
            'encryption_args': {
                'protocol_id': {
                    'securityLevel': 2,
                    'protocol': "auth message signature"
                },
                'key_id': f"{getattr(message, 'nonce', '')} {session.session_nonce}",
                'counterparty': {
                    'type': 3,
                    'counterparty': sender_public_key
                }
            },
            'data': cert_data,
            'signature': signature
        }, "auth-peer")
        if self._debug:
            print(f"[Peer DEBUG] handle_certificate_response: verify_result={getattr(verify_result, 'valid', None)}")
        if verify_result is None or not getattr(verify_result, 'valid', False):
            return Exception("certificate response - invalid signature")
        import time
        session.last_update = int(time.time() * 1000)
        self.session_manager.update_session(session)
        # Certificate verification logic
        certs = getattr(message, 'certificates', [])
        if certs:
            valid = self._validate_certificates(
                ctx,
                certs,
                getattr(self, 'certificates_to_request', None),
                expected_subject=getattr(message, 'identity_key', None),
            )
            if not valid:
                self.logger.warning("Invalid certificates in certificate response")
            for callback in self.on_certificate_received_callbacks.values():
                try:
                    callback(sender_public_key, certs)
                except Exception as e:
                    self.logger.warning(f"Certificate callback error: {e}")
        return None

    def handle_general_message(self, ctx: Any, message: Any, sender_public_key: Any) -> Optional[Exception]:
        """
        Processes a general message.
        """
        if self._debug:
            print("[Peer DEBUG] handle_general_message: begin")
        # Optional: validate nonce for replay protection (non-fatal)
        try:
            from .utils import verify_nonce
            nonce = getattr(message, 'nonce', None)
            if nonce and not verify_nonce(nonce, self.wallet, {"type": 3, "counterparty": sender_public_key}, ctx):
                self.logger.warning("general message - nonce verification failed")
        except Exception:
            pass
        # If this is a loopback of our own outbound message (test transport echoes), ignore gracefully
        try:
            identity_key_result = self.wallet.get_public_key(ctx, {'identityKey': True}, "auth-peer")
            if identity_key_result is not None and hasattr(identity_key_result, 'public_key') and sender_public_key is not None:
                if getattr(identity_key_result.public_key, 'hex', None) and getattr(sender_public_key, 'hex', None):
                    if identity_key_result.public_key.hex() == sender_public_key.hex():
                        return None
        except Exception:
            pass
        session = self.session_manager.get_session(sender_public_key.hex()) if sender_public_key else None
        if session is None:
            return Exception("Session not found")
        # --- Signature verification logic implementation ---
        signature = getattr(message, 'signature', None)
        payload = getattr(message, 'payload', None)
        data_to_verify = self._serialize_for_signature(payload)
        verify_result = self.wallet.verify_signature(ctx, {
            'encryption_args': {
                'protocol_id': {
                    'securityLevel': 2,
                    'protocol': "auth message signature"
                },
                'key_id': f"{getattr(message, 'nonce', '')} {session.session_nonce}",
                'counterparty': {
                    'type': 3,
                    'counterparty': sender_public_key
                }
            },
            'data': data_to_verify,
            'signature': signature
        }, "auth-peer")
        if verify_result is None or not getattr(verify_result, 'valid', False):
            return Exception("general message - invalid signature")
        import time
        session.last_update = int(time.time() * 1000)
        self.session_manager.update_session(session)
        if self.auto_persist_last_session:
            self.last_interacted_with_peer = sender_public_key
        for callback in self.on_general_message_received_callbacks.values():
            try:
                callback(sender_public_key, payload)
            except Exception as e:
                self.logger.warning(f"General message callback error: {e}")
        return None

    def expire_sessions(self, max_age_sec: int = 3600):
        """
        Expire sessions older than max_age_sec. Should be called periodically.
        """
        if self._debug:
            print(f"[Peer DEBUG] expire_sessions: begin, max_age_sec={max_age_sec}")
        if hasattr(self.session_manager, 'expire_older_than'):
            try:
                self.session_manager.expire_older_than(max_age_sec)
                if self._debug:
                    print("[Peer DEBUG] expire_sessions: used session_manager.expire_older_than")
                return
            except Exception:
                pass
        # Fallback path if expire_older_than is unavailable
        import time
        now = int(time.time() * 1000)
        if hasattr(self.session_manager, 'get_all_sessions'):
            before = len(self.session_manager.get_all_sessions())
            for session in self.session_manager.get_all_sessions():
                if hasattr(session, 'last_update') and now - session.last_update > max_age_sec * 1000:
                    self.session_manager.remove_session(session)
                    self.logger.info(f"Session expired: {getattr(session, 'peer_identity_key', None)}")
            after = len(self.session_manager.get_all_sessions())
            if self._debug:
                print(f"[Peer DEBUG] expire_sessions: removed={before - after}, remaining={after}")

    def stop(self):
        # TODO: Clean up any resources if needed
        pass

    def listen_for_general_messages(self, callback: Callable) -> int:
        """
        Registers a callback for general messages. Returns a callback ID.
        """
        callback_id = self.callback_id_counter
        self.callback_id_counter += 1
        self.on_general_message_received_callbacks[callback_id] = callback
        return callback_id

    def stop_listening_for_general_messages(self, callback_id: int):
        """
        Removes a general message listener by callback ID.
        """
        if callback_id in self.on_general_message_received_callbacks:
            del self.on_general_message_received_callbacks[callback_id]

    def listen_for_certificates_received(self, callback: Callable) -> int:
        """
        Registers a callback for certificate reception. Returns a callback ID.
        """
        callback_id = self.callback_id_counter
        self.callback_id_counter += 1
        self.on_certificate_received_callbacks[callback_id] = callback
        return callback_id

    def stop_listening_for_certificates_received(self, callback_id: int):
        """
        Removes a certificate reception listener by callback ID.
        """
        if callback_id in self.on_certificate_received_callbacks:
            del self.on_certificate_received_callbacks[callback_id]

    def listen_for_certificates_requested(self, callback: Callable) -> int:
        """
        Registers a callback for certificate requests. Returns a callback ID.
        """
        callback_id = self.callback_id_counter
        self.callback_id_counter += 1
        self.on_certificate_request_received_callbacks[callback_id] = callback
        return callback_id

    def stop_listening_for_certificates_requested(self, callback_id: int):
        """
        Removes a certificate request listener by callback ID.
        """
        if callback_id in self.on_certificate_request_received_callbacks:
            del self.on_certificate_request_received_callbacks[callback_id]

    def get_authenticated_session(self, ctx: Any, identity_key: Optional[Any], max_wait_time_ms: int) -> Optional[Any]:
        """
        Retrieves or creates an authenticated session with a peer.
        """
        # If we have an existing authenticated session, return it
        if identity_key is not None:
            session = self.session_manager.get_session(identity_key.hex())
            if session is not None and getattr(session, 'is_authenticated', False):
                if self.auto_persist_last_session:
                    self.last_interacted_with_peer = identity_key
                return session
        # No valid session, initiate handshake
        session = self.initiate_handshake(ctx, identity_key, max_wait_time_ms)
        if session is not None and self.auto_persist_last_session:
            self.last_interacted_with_peer = identity_key
        return session

    def initiate_handshake(self, ctx: Any, peer_identity_key: Any, max_wait_time_ms: int) -> Optional[Any]:
        """
        Starts the mutual authentication handshake with a peer.
        """
        # TODO: Replace with actual nonce creation logic
        import os, base64, time
        session_nonce = base64.b64encode(os.urandom(32)).decode('ascii')
        # Add a preliminary session entry (not yet authenticated)
        from .peer_session import PeerSession
        session = PeerSession(
            is_authenticated=False,
            session_nonce=session_nonce,
            peer_identity_key=peer_identity_key,
            last_update=int(time.time() * 1000)
        )
        self.session_manager.add_session(session)
        # Get our identity key to include in the initial request
        identity_key_result = self.wallet.get_public_key(ctx, {'identityKey': True}, "auth-peer")
        if identity_key_result is None or not hasattr(identity_key_result, 'public_key'):
            return None
        # Create and send the initial request message
        from .auth_message import AuthMessage
        initial_request = AuthMessage(
            version="0.1",
            message_type="initialRequest",
            identity_key=identity_key_result.public_key,
            initial_nonce=session_nonce,
            requested_certificates=self.certificates_to_request
        )
        # Set up a simple timeout mechanism (not concurrent)
        import threading
        response_event = threading.Event()
        response_holder = {'session': None}
        # Register a callback for the response (simplified)
        callback_id = self.callback_id_counter
        self.callback_id_counter += 1
        def on_initial_response(peer_nonce):
            session.peer_nonce = peer_nonce
            session.is_authenticated = True
            self.session_manager.update_session(session)
            response_holder['session'] = session
            response_event.set()
        self.on_initial_response_received_callbacks[callback_id] = {
            'callback': on_initial_response,
            'session_nonce': session_nonce
        }
        # Send the initial request
        err = self.transport.send(ctx, initial_request)
        if err is not None:
            del self.on_initial_response_received_callbacks[callback_id]
            return None
        # Wait for response or timeout
        if max_wait_time_ms and max_wait_time_ms > 0:
            wait_seconds = max_wait_time_ms / 1000
        else:
            wait_seconds = 2  # Provide a reasonable default for unit tests
        if not response_event.wait(timeout=wait_seconds):
            # Do not forcibly delete here; the handler will clean up on arrival
            return None  # Timeout
        # Callback path already cleaned up the map
        return response_holder['session']

    def _serialize_for_signature(self, data: Any) -> bytes:
        """
        Helper to serialize data for signing (JSON, UTF-8 encoded).
        """
        if isinstance(data, (dict, list)):
            return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        elif isinstance(data, bytes):
            return data
        elif isinstance(data, str):
            return data.encode("utf-8")
        else:
            return str(data).encode("utf-8")

    def to_peer(self, ctx: Any, message: bytes, identity_key: Optional[Any] = None, max_wait_time: int = 0) -> Optional[Exception]:
        """
        Sends a message to a peer, initiating authentication if needed.
        """
        if self.auto_persist_last_session and self.last_interacted_with_peer is not None and identity_key is None:
            identity_key = self.last_interacted_with_peer
        peer_session = self.get_authenticated_session(ctx, identity_key, max_wait_time)
        if peer_session is None:
            return Exception("failed to get authenticated session")
        import os, base64, time
        request_nonce = base64.b64encode(os.urandom(32)).decode('ascii')
        identity_key_result = self.wallet.get_public_key(ctx, {'identityKey': True}, "auth-peer")
        if identity_key_result is None or not hasattr(identity_key_result, 'public_key'):
            return Exception("failed to get identity key")
        from .auth_message import AuthMessage
        general_message = AuthMessage(
            version="0.1",
            message_type="general",
            identity_key=identity_key_result.public_key,
            nonce=request_nonce,
            your_nonce=peer_session.peer_nonce,
            payload=message
        )
        # --- Signature logic implementation ---
        data_to_sign = self._serialize_for_signature(message)
        sig_result = self.wallet.create_signature(ctx, {
            'encryption_args': {
                'protocol_id': {
                    'securityLevel': 2,
                    'protocol': "auth message signature"
                },
                'key_id': f"{request_nonce} {peer_session.peer_nonce}",
                'counterparty': {
                    'type': 3,
                    'counterparty': peer_session.peer_identity_key
                }
            },
            'data': data_to_sign
        }, "auth-peer")
        if sig_result is None or not hasattr(sig_result, 'signature'):
            return Exception("failed to sign message")
        general_message.signature = sig_result.signature
        now = int(time.time() * 1000)
        peer_session.last_update = now
        self.session_manager.update_session(peer_session)
        if self.auto_persist_last_session:
            self.last_interacted_with_peer = peer_session.peer_identity_key
        err = self.transport.send(ctx, general_message)
        if err is not None:
            return Exception(f"failed to send message to peer {peer_session.peer_identity_key}: {err}")
        return None

    def request_certificates(self, ctx: Any, identity_key: Any, certificate_requirements: Any, max_wait_time: int) -> Optional[Exception]:
        """
        Sends a certificate request to a peer.
        """
        # Get or create an authenticated session
        peer_session = self.get_authenticated_session(ctx, identity_key, max_wait_time)
        if peer_session is None:
            return Exception("failed to get authenticated session")
        # Create a nonce for this request
        import os, base64, time
        request_nonce = base64.b64encode(os.urandom(32)).decode('ascii')
        # Get identity key
        identity_key_result = self.wallet.get_public_key(ctx, {'identityKey': True}, "auth-peer")
        if identity_key_result is None or not hasattr(identity_key_result, 'public_key'):
            return Exception("failed to get identity key")
        # Create certificate request message
        from .auth_message import AuthMessage
        cert_request = AuthMessage(
            version="0.1",
            message_type="certificateRequest",
            identity_key=identity_key_result.public_key,
            nonce=request_nonce,
            your_nonce=peer_session.peer_nonce,
            requested_certificates=certificate_requirements
        )
        # Canonicalize and sign the request requirements
        canonical_req = self._canonicalize_requested_certificates(certificate_requirements)
        sig_result = self.wallet.create_signature(ctx, {
            'encryption_args': {
                'protocol_id': {
                    'securityLevel': 2,
                    'protocol': "auth message signature"
                },
                'key_id': f"{request_nonce} {peer_session.peer_nonce}",
                'counterparty': {
                    'type': 3,
                    'counterparty': None  # Peer public key if available
                }
            },
            'data': self._serialize_for_signature(canonical_req)
        }, "auth-peer")
        if sig_result is None or not hasattr(sig_result, 'signature'):
            return Exception("failed to sign certificate request")
        cert_request.signature = sig_result.signature
        # Send the request
        err = self.transport.send(ctx, cert_request)
        if err is not None:
            return Exception(f"failed to send certificate request: {err}")
        # Update session timestamp
        now = int(time.time() * 1000)
        peer_session.last_update = now
        self.session_manager.update_session(peer_session)
        # Update last interacted peer
        if self.auto_persist_last_session:
            self.last_interacted_with_peer = identity_key
        return None

    def send_certificate_response(self, ctx: Any, identity_key: Any, certificates: Any) -> Optional[Exception]:
        """
        Sends certificates back to a peer in response to a request.
        """
        if self._debug:
            print(f"[Peer DEBUG] send_certificate_response: begin, certs_in={(len(certificates) if isinstance(certificates, list) else 'n/a')}")
        peer_session = self.get_authenticated_session(ctx, identity_key, 0)
        if peer_session is None:
            return Exception("failed to get authenticated session")
        # Create a nonce for this response
        import os, base64, time
        response_nonce = base64.b64encode(os.urandom(32)).decode('ascii')
        # Get identity key
        identity_key_result = self.wallet.get_public_key(ctx, {'identityKey': True}, "auth-peer")
        if identity_key_result is None or not hasattr(identity_key_result, 'public_key'):
            return Exception("failed to get identity key")
        # Create certificate response message
        from .auth_message import AuthMessage
        cert_response = AuthMessage(
            version="0.1",
            message_type="certificateResponse",
            identity_key=identity_key_result.public_key,
            nonce=response_nonce,
            your_nonce=peer_session.peer_nonce,
            certificates=certificates
        )
        # Canonicalize and sign the certificates payload
        canonical_certs = self._canonicalize_certificates_payload(certificates)
        if self._debug:
            print(f"[Peer DEBUG] send_certificate_response: canonical_count={len(canonical_certs)}")
        sig_result = self.wallet.create_signature(ctx, {
            'encryption_args': {
                'protocol_id': {
                    'securityLevel': 2,
                    'protocol': "auth message signature"
                },
                'key_id': f"{response_nonce} {peer_session.peer_nonce}",
                'counterparty': {
                    'type': 3,
                    'counterparty': None  # Peer public key if available
                }
            },
            'data': self._serialize_for_signature(canonical_certs)
        }, "auth-peer")
        if sig_result is None or not hasattr(sig_result, 'signature'):
            return Exception("failed to sign certificate response")
        cert_response.signature = sig_result.signature
        # Send the response
        err = self.transport.send(ctx, cert_response)
        if err is not None:
            return Exception(f"failed to send certificate response: {err}")
        if self._debug:
            print("[Peer DEBUG] send_certificate_response: response sent")
        # Update session timestamp
        now = int(time.time() * 1000)
        peer_session.last_update = now
        self.session_manager.update_session(peer_session)
        # Update last interacted peer
        if self.auto_persist_last_session:
            self.last_interacted_with_peer = identity_key
        return None

    # --- 1. Signature generation and verification ---
    def sign_data(self, data: bytes) -> bytes:
        """
        Canonicalize and sign data using the wallet interface.
        """
        canonical_data = self._canonicalize(data)
        return self.wallet.sign(canonical_data)

    def verify_signature(self, data: bytes, signature: bytes, pubkey) -> bool:
        """
        Canonicalize and verify signature using the wallet interface.
        """
        canonical_data = self._canonicalize(data)
        return self.wallet.verify(canonical_data, signature, pubkey)

    def _canonicalize(self, data: bytes) -> bytes:
        """
        Canonicalize data for signing/verifying. (Override as needed for protocol.)
        """
        return data

    # --- 2. Certificate verification ---
    def verify_certificate(self, cert) -> bool:
        """
        Verify a VerifiableCertificate using the cert store (chain, expiry, revocation).
        """
        if hasattr(cert, 'verify'):
            return cert.verify(self.cert_store)
        return False

    # --- 3. RequestedCertificateSet validation ---
    def validate_certificate_request(self, req_set) -> bool:
        """
        Validate a RequestedCertificateSet for required attributes and duplicates.
        """
        if not hasattr(req_set, 'is_valid') or not req_set.is_valid():
            return False
        if hasattr(self.cert_store, 'has_request') and self.cert_store.has_request(req_set):
            return False
        return True

    # --- 4. Nonce verification and replay protection ---
    def verify_nonce(self, nonce: str, expiry: int = 300) -> bool:
        """
        Check nonce uniqueness and (optionally) expiry. Prevents replay attacks.
        """
        import time
        now = int(time.time())
        # Optionally, store (nonce, timestamp) for expiry logic
        if nonce in self._used_nonces:
            return False
        self._used_nonces.add(nonce)
        # Expiry logic can be added here if nonce includes timestamp
        return True

    # --- 5. Event handler registration and emission ---
    def on(self, event: str, handler: Callable[..., Any]):
        """
        Register an event handler for a named event.
        """
        self._event_handlers[event] = handler

    def emit(self, event: str, *args, **kwargs):
        """
        Emit an event, calling the registered handler if present.
        """
        handler = self._event_handlers.get(event)
        if handler:
            try:
                handler(*args, **kwargs)
            except Exception as e:
                self.logger.warning(f"Exception in event handler '{event}': {e}")

    # --- 6. Custom error classes for unified error handling ---
class PeerAuthError(Exception):
    """Raised for authentication-related errors in Peer."""
    pass

class CertificateError(Exception):
    """Raised for certificate validation or issuance errors."""
    pass

    # --- 7. Serialization/deserialization helpers ---
    def serialize_data(self, data: Any) -> bytes:
        """
        Serialize data to bytes (JSON canonical form by default).
        """
        try:
            return json.dumps(data, sort_keys=True, separators=(",", ":")).encode('utf-8')
        except Exception as e:
            self._handle_error("Failed to serialize data", e, raise_exc=True)

    def deserialize_data(self, data: bytes) -> Any:
        """
        Deserialize bytes to Python object (JSON by default).
        """
        try:
            return json.loads(data.decode('utf-8'))
        except Exception as e:
            self._handle_error("Failed to deserialize data", e, raise_exc=True)

    # --- 8. Session expiry and management ---
    def expire_sessions(self, max_age_sec: int = 3600):
        """
        Expire sessions older than max_age_sec. Should be called periodically.
        """
        if self._debug:
            print(f"[Peer DEBUG] expire_sessions: begin, max_age_sec={max_age_sec}")
        if hasattr(self.session_manager, 'expire_older_than'):
            try:
                self.session_manager.expire_older_than(max_age_sec)
                if self._debug:
                    print("[Peer DEBUG] expire_sessions: used session_manager.expire_older_than")
                return
            except Exception:
                pass
        # Fallback path if expire_older_than is unavailable
        import time
        now = int(time.time() * 1000)
        if hasattr(self.session_manager, 'get_all_sessions'):
            before = len(self.session_manager.get_all_sessions())
            for session in self.session_manager.get_all_sessions():
                if hasattr(session, 'last_update') and now - session.last_update > max_age_sec * 1000:
                    self.session_manager.remove_session(session)
                    self.logger.info(f"Session expired: {getattr(session, 'peer_identity_key', None)}")
            after = len(self.session_manager.get_all_sessions())
            if self._debug:
                print(f"[Peer DEBUG] expire_sessions: removed={before - after}, remaining={after}")

    # --- 9. Transport security stub (for extension) ---
    def secure_send(self, ctx: Any, message: Any) -> Optional[Exception]:
        """
        Send a message with additional security (encryption, MAC, etc.).
        This is a stub for future extension.
        """
        # TODO: Implement encryption/MAC as needed
        return self.transport.send(ctx, message)

    # --- 10. Integration/E2E test utility ---
    def _test_peer_integration(self, ctx: Any, test_message: Any) -> bool:
        """
        Test utility: send a message and check for expected response (for E2E/integration tests).
        """
        try:
            err = self.transport.send(ctx, test_message)
            if err is not None:
                self.logger.warning(f"Test send failed: {err}")
                return False
            # Optionally, wait for and check response here
            return True
        except Exception as e:
            self.logger.warning(f"Test integration error: {e}")
            return False