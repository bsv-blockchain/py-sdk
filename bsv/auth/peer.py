from typing import Callable, Dict, Optional, Any, Set
import logging
import json
import base64

from .transports.transport import Transport
# Re-export PeerSession for compatibility with session_manager typing/tests
from .peer_session import PeerSession


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
            try:
                from .requested_certificate_set import RequestedCertificateSet, RequestedCertificateTypeIDAndFieldList
                self.certificates_to_request = RequestedCertificateSet(
                    certifiers=[],
                    certificate_types=RequestedCertificateTypeIDAndFieldList(),
                )
            except Exception:
                # Fallback to a minimal dict structure if imports are unavailable
                self.certificates_to_request = {
                    'certifiers': [],
                    'certificate_types': {}
                }
        # Start the peer (register handlers, etc.)
        try:
            self.start()
        except Exception as e:
            self.logger.warning(f"Failed to start peer: {e}")
        self.FAIL_TO_GET_IDENTIFY_KEY = "failed to get identity key"
        self.AUTH_MESSAGE_SIGNATURE = "auth message signature"
        self.SESSION_NOT_FOUND = "Session not found"
        self.FAILED_TO_GET_AUTHENTICATED_SESSION = "failed to get authenticated session"

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
    def _rcs_hex_certifiers(self, raw_list: Any) -> list:
        certs: list = []
        for pk in raw_list or []:
            try:
                if hasattr(pk, 'hex') and callable(getattr(pk, 'hex')):
                    certs.append(pk.hex())
                elif isinstance(pk, (bytes, bytearray)):
                    certs.append(bytes(pk).hex())
                else:
                    certs.append(str(pk))
            except Exception:
                certs.append(str(pk))
        return certs

    def _rcs_key_to_b64(self, key: Any) -> Optional[str]:
        import base64 as _b64
        if isinstance(key, (bytes, bytearray)):
            b = bytes(key)
            return _b64.b64encode(b).decode('ascii') if len(b) == 32 else None
        ks = str(key)
        try:
            dec = _b64.b64decode(ks)
            if len(dec) == 32:
                return _b64.b64encode(dec).decode('ascii')
        except Exception:
            pass
        try:
            b = bytes.fromhex(ks)
            if len(b) == 32:
                return _b64.b64encode(b).decode('ascii')
        except Exception:
            pass
        return None

    def _rcs_types_dict_from_requested(self, req: Any) -> dict:
        if isinstance(req, dict):
            return (
                req.get('certificate_types')
                or req.get('certificateTypes')
                or req.get('types')
                or {}
            )
        return {}

    def _rcs_from_object(self, requested_obj: Any) -> tuple[list, dict]:
        certifiers = self._rcs_hex_certifiers(getattr(requested_obj, 'certifiers', []) or [])
        mapping = getattr(getattr(requested_obj, 'certificate_types', None), 'mapping', {}) or {}
        types_b64: dict = {}
        for k, v in mapping.items():
            k_b64 = self._rcs_key_to_b64(k)
            if k_b64 is None:
                continue
            types_b64[k_b64] = list(v or [])
        return certifiers, types_b64

    def _rcs_from_dict(self, requested_dict: dict) -> tuple[list, dict]:
        certifiers = self._rcs_hex_certifiers(requested_dict.get('certifiers', []))
        types_b64: dict = {}
        for k, v in self._rcs_types_dict_from_requested(requested_dict).items():
            k_b64 = self._rcs_key_to_b64(k)
            if k_b64 is None:
                continue
            types_b64[k_b64] = list(v or [])
        return certifiers, types_b64

    def _canonicalize_requested_certificates(self, requested: Any) -> dict:
        try:
            from .requested_certificate_set import RequestedCertificateSet
        except Exception:
            RequestedCertificateSet = None  # type: ignore

        if requested is None:
            return {"certifiers": [], "certificateTypes": {}}

        try:
            certifiers: list
            types_b64: dict

            if RequestedCertificateSet is not None and isinstance(requested, RequestedCertificateSet):
                certifiers, types_b64 = self._rcs_from_object(requested)
            elif isinstance(requested, dict):
                certifiers, types_b64 = self._rcs_from_dict(requested)
            else:
                certifiers, types_b64 = [], {}

            # Sort outputs deterministically
            sorted_types = {k: sorted(list(v or [])) for k, v in types_b64.items()}
            return {"certifiers": sorted(certifiers), "certificateTypes": sorted_types}
        except Exception:
            return {"certifiers": [], "certificateTypes": {}}

    # --- Helpers for certificate payload canonicalization ---
    def _b64_32(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, (bytes, bytearray)):
            b = bytes(value)
            return base64.b64encode(b).decode('ascii') if len(b) == 32 else None
        if isinstance(value, str):
            s = value
            try:
                dec = base64.b64decode(s)
                if len(dec) == 32:
                    return base64.b64encode(dec).decode('ascii')
            except Exception:
                pass
            try:
                b = bytes.fromhex(s)
                if len(b) == 32:
                    return base64.b64encode(b).decode('ascii')
            except Exception:
                pass
            return None
        return None

    def _pubkey_to_hex(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        if hasattr(value, 'hex') and callable(getattr(value, 'hex')):
            try:
                return value.hex()
            except Exception:
                return None
        if isinstance(value, (bytes, bytearray)):
            return bytes(value).hex()
        if isinstance(value, str):
            s = value
            try:
                dec = base64.b64decode(s)
                if len(dec) in (33, 65):
                    return dec.hex()
            except Exception:
                pass
            try:
                _ = bytes.fromhex(s)
                return s.lower()
            except Exception:
                return s
        return str(value)

    def _normalize_revocation_outpoint(self, rev: Any) -> Optional[dict]:
        if isinstance(rev, dict):
            return {"txid": rev.get('txid'), "index": rev.get('index')}
        if rev is not None and hasattr(rev, 'txid') and hasattr(rev, 'index'):
            return {"txid": getattr(rev, 'txid', None), "index": getattr(rev, 'index', None)}
        return None

    def _get_base_keyring_signature(self, entry: Any):
        if isinstance(entry, dict):
            return entry.get('certificate', entry), (entry.get('keyring', {}) or {}), entry.get('signature')
        return (
            getattr(entry, 'certificate', entry),
            getattr(entry, 'keyring', {}) or {},
            getattr(entry, 'signature', None),
        )

    def _extract_base_fields(self, base: Any):
        if isinstance(base, dict):
            return (
                base.get('type'),
                base.get('serialNumber') or base.get('serial_number'),
                base.get('subject'),
                base.get('certifier'),
                base.get('revocationOutpoint') or base.get('revocation_outpoint'),
                base.get('fields', {}) or {},
            )
        return (
            getattr(base, 'type', None),
            getattr(base, 'serial_number', None),
            getattr(base, 'subject', None),
            getattr(base, 'certifier', None),
            getattr(base, 'revocation_outpoint', None),
            getattr(base, 'fields', {}) or {},
        )

    def _canonicalize_cert_entry(self, entry: Any) -> dict:
        base, keyring, signature = self._get_base_keyring_signature(entry)
        cert_type_raw, serial_raw, subject_raw, certifier_raw, rev, fields = self._extract_base_fields(base)
        return {
            "type": self._b64_32(cert_type_raw) or cert_type_raw,
            "serialNumber": self._b64_32(serial_raw) or serial_raw,
            "subject": self._pubkey_to_hex(subject_raw),
            "certifier": self._pubkey_to_hex(certifier_raw),
            "revocationOutpoint": self._normalize_revocation_outpoint(rev),
            "fields": fields,
            "keyring": keyring,
            "signature": (base64.b64encode(signature).decode('ascii') if isinstance(signature, (bytes, bytearray)) else signature),
        }

    def _canonicalize_certificates_payload(self, certs: Any) -> list:
        canonical: list = []
        if not certs:
            return canonical
        for c in certs:
            try:
                canonical.append(self._canonicalize_cert_entry(c))
            except Exception:
                canonical.append(str(c))
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

        # 1) Generate our session nonce
        our_nonce = self._generate_session_nonce(ctx)
        if self._debug:
            print(f"[Peer DEBUG] handle_initial_request: our_nonce={our_nonce}, peer_nonce={initial_nonce}")

        # 2) Create and store session (auth status may be downgraded if we plan to request certs)
        session = self._create_session_for_initial(sender_public_key, initial_nonce, our_nonce)
        if self._debug:
            print(f"[Peer DEBUG] handle_initial_request: session added, nonce={session.session_nonce}")

        # 3) Get our identity key
        identity_key_result = self.wallet.get_public_key(ctx, {'identityKey': True}, "auth-peer")
        if identity_key_result is None or not hasattr(identity_key_result, 'public_key'):
            return Exception(self.FAIL_TO_GET_IDENTIFY_KEY)

        # 4) Acquire any requested certificates from the peer's initial request
        certs = []
        requested_certs = getattr(message, 'requested_certificates', None)
        if requested_certs is not None:
            certs = self._acquire_requested_certs_for_initial(ctx, requested_certs, identity_key_result)

        # 5) Build initial response and sign it
        response_err = self._send_initial_response(ctx, message, identity_key_result, initial_nonce, session, certs)
        if response_err is not None:
            return response_err

        if self._debug:
            print("[Peer DEBUG] handle_initial_request: response sent")
        return None

    def _generate_session_nonce(self, ctx: Any) -> str:
        import base64
        try:
            from .utils import create_nonce
            return create_nonce(self.wallet, {'type': 1}, ctx)
        except Exception:
            import os
            return base64.b64encode(os.urandom(32)).decode('ascii')

    def _create_session_for_initial(self, sender_public_key: Any, initial_nonce: str, our_nonce: str):
        import time
        from .peer_session import PeerSession
        session = PeerSession(
            is_authenticated=True,
            session_nonce=our_nonce,
            peer_nonce=initial_nonce,
            peer_identity_key=sender_public_key,
            last_update=int(time.time() * 1000)
        )
        # If we plan to request certificates, mark unauthenticated until received
        req_certs = getattr(self, 'certificates_to_request', None)
        if req_certs is not None and hasattr(req_certs, 'certificate_types') and len(req_certs.certificate_types) > 0:
            session.is_authenticated = False
        self.session_manager.add_session(session)
        return session

    def _acquire_requested_certs_for_initial(self, ctx: Any, requested_certs: Any, identity_key_result: Any) -> list:
        import base64
        certs: list = []
        try:
            from .verifiable_certificate import VerifiableCertificate
            from .certificate import Certificate
            # Obtain from certificate DB or wallet
            for cert_type, fields in getattr(requested_certs, 'certificate_types', {} ).items():
                args = {
                    'cert_type': base64.b64encode(cert_type).decode(),
                    'fields': fields,
                    'subject': identity_key_result.public_key.hex(),
                    'certifiers': [pk.hex() for pk in getattr(requested_certs, 'certifiers', [])],
                }
                cert_result = self.wallet.acquire_certificate(ctx, args, "auth-peer")
                if isinstance(cert_result, list):
                    for cert in cert_result:
                        if isinstance(cert, Certificate):
                            certs.append(VerifiableCertificate(cert))
                elif isinstance(cert_result, Certificate):
                    certs.append(VerifiableCertificate(cert_result))
        except Exception as e:
            self.logger.warning(f"Failed to acquire certificates: {e}")
        return certs

    def _send_initial_response(self, ctx: Any, message: Any, identity_key_result: Any, initial_nonce: str, session: Any, certs: list) -> Optional[Exception]:
        import base64
        from .auth_message import AuthMessage
        response = AuthMessage(
            version="0.1",
            message_type="initialResponse",
            identity_key=identity_key_result.public_key,
            nonce=session.session_nonce,
            your_nonce=initial_nonce,
            initial_nonce=session.session_nonce,
            certificates=certs
        )
        try:
            sig_data = self._compute_initial_sig_data(initial_nonce, session.session_nonce)
        except Exception as e:
            return Exception(f"failed to decode nonce: {e}")

        sig_result = self.wallet.create_signature(ctx, {
            'encryption_args': {
                'protocol_id': {
                    'securityLevel': 2,
                    'protocol': self.AUTH_MESSAGE_SIGNATURE
                },
                'key_id': f"{initial_nonce} {session.session_nonce}",
                'counterparty': {
                    'type': 3,
                    'counterparty': getattr(message, 'identity_key', None)
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
        return None

    def _compute_initial_sig_data(self, initial_nonce: str, session_nonce: str) -> bytes:
        import base64
        initial_nonce_bytes = base64.b64decode(initial_nonce)
        session_nonce_bytes = base64.b64decode(session_nonce)
        return initial_nonce_bytes + session_nonce_bytes

    # --- Helpers for certificate validation ---
    def _is_rcs_like(self, obj: Any) -> bool:
        return hasattr(obj, 'certifiers') and hasattr(obj, 'certificate_types')

    def _extract_certifiers_from_req(self, req: Any) -> list:
        if self._is_rcs_like(req):
            return list(getattr(req, 'certifiers', []) or [])
        if isinstance(req, dict):
            return req.get('certifiers') or req.get('Certifiers') or []
        return []

    def _extract_types_map_from_req(self, req: Any) -> Dict[bytes, list]:
        result: Dict[bytes, list] = {}
        if self._is_rcs_like(req):
            raw = getattr(getattr(req, 'certificate_types', None), 'mapping', {}) or {}
        elif isinstance(req, dict):
            raw = req.get('certificate_types') or req.get('certificateTypes') or req.get('types') or {}
        else:
            raw = {}
        for k, v in raw.items():
            key_b = bytes(k) if isinstance(k, (bytes, bytearray)) else self._decode_type_bytes(k)
            if key_b is not None:
                result[key_b] = list(v or [])
        return result

    def _normalize_requested_certificate_constraints(self, req: Any):
        try:
            certifiers = self._extract_certifiers_from_req(req)
            types_map = self._extract_types_map_from_req(req)
            return certifiers, types_map
        except Exception:
            return [], {}

    def _decode_type_bytes(self, val: Any) -> Optional[bytes]:
        if isinstance(val, (bytes, bytearray)):
            return bytes(val)
        if isinstance(val, str):
            try:
                import base64 as _b64
                return _b64.b64decode(val)
            except Exception:
                try:
                    return bytes.fromhex(val)
                except Exception:
                    return None
        return None

    # Granular validators for a single certificate
    def _get_base_cert(self, cert: Any) -> Any:
        return getattr(cert, 'certificate', cert)

    def _has_valid_signature(self, ctx: Any, cert: Any) -> bool:
        try:
            if hasattr(cert, 'verify') and not cert.verify(ctx):
                    self.logger.warning(f"Certificate signature invalid: {cert}")
                    return False
        except Exception as e:
            self.logger.warning(f"Certificate signature verification error: {e}")
            return False
        return True

    def _subject_matches_expected(self, expected_subject: Any, base_cert: Any) -> bool:
        if expected_subject is None:
            return True
        try:
            subj_hex = self._pubkey_to_hex(getattr(base_cert, 'subject', None))
            exp_hex = self._pubkey_to_hex(expected_subject)
            if subj_hex is None or exp_hex is None or subj_hex != exp_hex:
                self.logger.warning("Certificate subject does not match the expected identity key")
                return False
            return True
        except Exception as e:
            self.logger.warning(f"Subject comparison failed: {e}")
            return False

    def _is_certifier_allowed(self, allowed_certifier_hexes: Set[str], base_cert: Any) -> bool:
        if not allowed_certifier_hexes:
            return True
        try:
            cert_hex = self._pubkey_to_hex(getattr(base_cert, 'certifier', None))
            if cert_hex is None or cert_hex.lower() not in allowed_certifier_hexes:
                self.logger.warning("Certificate has unrequested certifier")
                return False
            return True
        except Exception as e:
            self.logger.warning(f"Certifier check failed: {e}")
            return False

    def _type_and_fields_valid(self, requested_types: Dict[bytes, list], base_cert: Any) -> bool:
        if not requested_types:
            return True
        try:
            cert_type_bytes = self._decode_type_bytes(getattr(base_cert, 'type', None))
            if not cert_type_bytes:
                self.logger.warning("Invalid certificate type encoding")
                return False
            if cert_type_bytes not in requested_types:
                self.logger.warning("Certificate type was not requested")
                return False
            required_fields = requested_types.get(cert_type_bytes, [])
            cert_fields = getattr(base_cert, 'fields', {}) or {}
            for field in required_fields:
                if field not in cert_fields:
                    self.logger.warning(f"Certificate missing required field: {field}")
                    return False
            return True
        except Exception as e:
            self.logger.warning(f"Type/fields validation failed: {e}")
            return False

    def _validate_single_certificate(
        self,
        ctx: Any,
        cert: Any,
        expected_subject: Any,
        allowed_certifier_hexes: Set[str],
        requested_types: Dict[bytes, list],
    ) -> bool:
        base_cert = self._get_base_cert(cert)
        if not self._has_valid_signature(ctx, cert):
            return False
        if not self._subject_matches_expected(expected_subject, base_cert):
            return False
        if not self._is_certifier_allowed(allowed_certifier_hexes, base_cert):
            return False
        if not self._type_and_fields_valid(requested_types, base_cert):
            return False
        return True

    def _validate_certificates(self, ctx: Any, certs: list, requested_certs: Any = None, expected_subject: Any = None) -> bool:
        """
        Validate VerifiableCertificates against a RequestedCertificateSet or dict.
        - Verifies signature
        - Ensures certifier is allowed (if provided)
        - Ensures type is requested and required fields are present (if provided)
        - Ensures subject matches expected_subject (if provided)
        """
        valid = True
        allowed_certifiers, requested_types = self._normalize_requested_certificate_constraints(requested_certs)
        allowed_certifier_hexes: Set[str] = set()
        for c in allowed_certifiers or []:
            hx = self._pubkey_to_hex(c)
            if isinstance(hx, str):
                allowed_certifier_hexes.add(hx.lower())

        for cert in certs:
            if not self._validate_single_certificate(ctx, cert, expected_subject, allowed_certifier_hexes, requested_types):
                valid = False
        return valid

    def handle_initial_response(self, ctx: Any, message: Any, sender_public_key: Any) -> Optional[Exception]:
        """
        Processes the response to our initial authentication request.
        """
        if self._debug:
            print("[Peer DEBUG] handle_initial_response: begin")
        session = self._retrieve_initial_response_session(sender_public_key, message)
        if session is None:
            return Exception(self.SESSION_NOT_FOUND)

        err = self._verify_and_update_session_from_initial_response(ctx, message, session)
        if err is not None:
            return err

        self._process_initial_response_certificates(ctx, message, sender_public_key)
        self._notify_initial_response_waiters(session, message)
        self._handle_requested_certificates_from_peer_message(ctx, message, sender_public_key, source_label="initialResponse")
        return None

    def _retrieve_initial_response_session(self, sender_public_key: Any, message: Any) -> Optional[Any]:
        session = self.session_manager.get_session(sender_public_key.hex()) if sender_public_key else None
        if session is None:
            your_nonce = getattr(message, 'your_nonce', None)
            if your_nonce:
                session = self.session_manager.get_session(your_nonce)
        return session

    def _verify_and_update_session_from_initial_response(self, ctx: Any, message: Any, session: Any) -> Optional[Exception]:
        try:
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
                    'protocol': self.AUTH_MESSAGE_SIGNATURE
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
        return None

    def _process_initial_response_certificates(self, ctx: Any, message: Any, sender_public_key: Any) -> None:
        certs = getattr(message, 'certificates', [])
        if not certs:
            return
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

    def _notify_initial_response_waiters(self, session: Any, message: Any) -> None:
        try:
            to_delete = None
            for cb_id, info in self.on_initial_response_received_callbacks.items():
                if info.get('session_nonce') == session.session_nonce:
                    peer_nonce = session.peer_nonce or getattr(message, 'initial_nonce', None)
                    to_delete = cb_id
                    try:
                        info.get('callback')(peer_nonce)
                    except Exception as e:
                        self.logger.warning(f"Initial response callback execution error: {e}")
                    break
            if to_delete is not None:
                del self.on_initial_response_received_callbacks[to_delete]
        except Exception as e:
            self.logger.warning(f"Initial response callback error: {e}")

    def _handle_requested_certificates_from_peer_message(self, ctx: Any, message: Any, sender_public_key: Any, source_label: str = "") -> None:
        try:
            req_from_peer = getattr(message, 'requested_certificates', None)
            if not self._has_requested_certificates(req_from_peer):
                return

            if self._try_callbacks_for_requested_certs(ctx, sender_public_key, req_from_peer, source_label):
                return

            self._auto_reply_with_requested_certs(ctx, message, sender_public_key, req_from_peer)
        except Exception as e:
            self.logger.warning(f"Requested certificates processing error: {e}")

    def _has_requested_certificates(self, req_from_peer: Any) -> bool:
        if req_from_peer is None:
            return False
        if hasattr(req_from_peer, 'certifiers') and getattr(req_from_peer, 'certifiers'):
            return True
        if isinstance(req_from_peer, dict):
            return bool(
                req_from_peer.get('certifiers')
                or req_from_peer.get('certificate_types')
                or req_from_peer.get('certificateTypes')
                or req_from_peer.get('types')
            )
        return False

    def _try_callbacks_for_requested_certs(self, ctx: Any, sender_public_key: Any, req_from_peer: Any, source_label: str) -> bool:
        if not self.on_certificate_request_received_callbacks:
            return False
        for cb in tuple(self.on_certificate_request_received_callbacks.values()):
            try:
                result = cb(sender_public_key, req_from_peer)
                if result:
                    err = self.send_certificate_response(ctx, sender_public_key, result)
                    if err is None:
                        return True
            except Exception as e:
                self.logger.warning(f"Certificate request callback error ({source_label} handling): {e}")
        return False

    def _auto_reply_with_requested_certs(self, ctx: Any, message: Any, sender_public_key: Any, req_from_peer: Any) -> None:
        try:
            canonical_req = self._canonicalize_requested_certificates(req_from_peer)
            req_for_utils = {
                'certifiers': canonical_req.get('certifiers', []),
                'types': canonical_req.get('certificateTypes', {})
            }
            from .utils import get_verifiable_certificates
            verifiable = get_verifiable_certificates(
                self.wallet,
                req_for_utils,
                getattr(message, 'identity_key', None)
            )
            if verifiable is not None:
                _err = self.send_certificate_response(ctx, sender_public_key, verifiable)
                if _err is not None:
                    self.logger.warning(f"Failed to send auto certificate response: {_err}")
        except Exception as e:
            self.logger.warning(f"Auto certificate response error: {e}")

    def handle_certificate_request(self, ctx: Any, message: Any, sender_public_key: Any) -> Optional[Exception]:
        """
        Processes a certificate request message.
        """
        if self._debug:
            print("[Peer DEBUG] handle_certificate_request: begin")
        session = self.session_manager.get_session(sender_public_key.hex()) if sender_public_key else None
        if session is None:
            return Exception(self.SESSION_NOT_FOUND)

        requested = getattr(message, 'requested_certificates', {})
        canonical_req = self._canonicalize_requested_certificates(requested)
        err = self._verify_certificate_request_signature(ctx, message, session, sender_public_key, canonical_req)
        if err is not None:
            return err

        self._touch_session(session)

        certs_to_send = self._invoke_cert_request_callbacks(sender_public_key, requested)
        if certs_to_send is None:
            subject_hex = self._get_identity_subject_hex(ctx)
            if subject_hex is None:
                return Exception("failed to get identity key for certificate response")
            certs_to_send = self._auto_acquire_certificates_for_request(ctx, canonical_req, subject_hex)

        if self._debug:
            print(f"[Peer DEBUG] handle_certificate_request: sending response, certs={len(certs_to_send or [])}")
        err = self.send_certificate_response(ctx, sender_public_key, certs_to_send or [])
        if err is not None:
            return Exception(f"failed to send certificate response: {err}")
        return None

    def _verify_certificate_request_signature(self, ctx: Any, message: Any, session: Any, sender_public_key: Any, canonical_req: dict) -> Optional[Exception]:
        cert_request_data = self._serialize_for_signature(canonical_req)
        signature = getattr(message, 'signature', None)
        verify_result = self.wallet.verify_signature(ctx, {
            'encryption_args': {
                'protocol_id': {
                    'securityLevel': 2,
                    'protocol': self.AUTH_MESSAGE_SIGNATURE
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
        return None

    def _touch_session(self, session: Any) -> None:
        import time
        session.last_update = int(time.time() * 1000)
        self.session_manager.update_session(session)

    def _invoke_cert_request_callbacks(self, sender_public_key: Any, requested: Any):
        if not self.on_certificate_request_received_callbacks:
            return None
        if self._debug:
            print("[Peer DEBUG] handle_certificate_request: invoking request callbacks")
        for cb in tuple(self.on_certificate_request_received_callbacks.values()):
            try:
                result = cb(sender_public_key, requested)
                if result:
                    return result
            except Exception as e:
                self.logger.warning(f"Certificate request callback error: {e}")
        return None

    def _get_identity_subject_hex(self, ctx: Any) -> Optional[str]:
        try:
            identity_key_result = self.wallet.get_public_key(ctx, {'identityKey': True}, "auth-peer")
            return getattr(getattr(identity_key_result, 'public_key', None), 'hex', lambda: None)()
        except Exception:
            return None

    def _auto_acquire_certificates_for_request(self, ctx: Any, canonical_req: dict, subject_hex: str) -> list:
        certs: list = []
        try:
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
        return certs

    def handle_certificate_response(self, ctx: Any, message: Any, sender_public_key: Any) -> Optional[Exception]:
        """
        Processes a certificate response message.
        """
        if self._debug:
            print("[Peer DEBUG] handle_certificate_response: begin")
        session = self.session_manager.get_session(sender_public_key.hex()) if sender_public_key else None
        if session is None:
            return Exception(self.SESSION_NOT_FOUND)

        certs = getattr(message, 'certificates', [])
        canonical_certs = self._canonicalize_certificates_payload(certs)
        cert_data = self._serialize_for_signature(canonical_certs)

        err = self._verify_certificate_response_signature(ctx, message, session, sender_public_key, cert_data)
        if err is not None:
            return err

        self._touch_session(session)

        self._process_certificate_response_certificates(ctx, message, sender_public_key)
        self._handle_requested_certificates_from_peer_message(ctx, message, sender_public_key, source_label="certificateResponse")
        return None

    def _verify_certificate_response_signature(self, ctx: Any, message: Any, session: Any, sender_public_key: Any, cert_data: bytes) -> Optional[Exception]:
        signature = getattr(message, 'signature', None)
        verify_result = self.wallet.verify_signature(ctx, {
            'encryption_args': {
                'protocol_id': {
                    'securityLevel': 2,
                    'protocol': self.AUTH_MESSAGE_SIGNATURE
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
        return None

    def _process_certificate_response_certificates(self, ctx: Any, message: Any, sender_public_key: Any) -> None:
        certs = getattr(message, 'certificates', [])
        if not certs:
            return
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

    def handle_general_message(self, ctx: Any, message: Any, sender_public_key: Any) -> Optional[Exception]:
        """
        Processes a general message.
        """
        if self._debug:
            print("[Peer DEBUG] handle_general_message: begin")
        self._optionally_verify_nonce(ctx, message, sender_public_key)
        if self._is_loopback_echo(ctx, sender_public_key):
            return None

        session = self.session_manager.get_session(sender_public_key.hex()) if sender_public_key else None
        if session is None:
            return Exception(self.SESSION_NOT_FOUND)

        payload = getattr(message, 'payload', None)
        data_to_verify = self._serialize_for_signature(payload)
        err = self._verify_general_message_signature(ctx, message, session, sender_public_key, data_to_verify)
        if err is not None:
            return err

        self._touch_session(session)
        if self.auto_persist_last_session:
            self.last_interacted_with_peer = sender_public_key
        self._dispatch_general_message_callbacks(sender_public_key, payload)
        return None

    def _optionally_verify_nonce(self, ctx: Any, message: Any, sender_public_key: Any) -> None:
        try:
            from .utils import verify_nonce
            nonce = getattr(message, 'nonce', None)
            if nonce and not verify_nonce(nonce, self.wallet, {"type": 3, "counterparty": sender_public_key}, ctx):
                self.logger.warning("general message - nonce verification failed")
        except Exception:
            pass

    def _is_loopback_echo(self, ctx: Any, sender_public_key: Any) -> bool:
        try:
            identity_key_result = self.wallet.get_public_key(ctx, {'identityKey': True}, "auth-peer")
            if identity_key_result is not None and hasattr(identity_key_result, 'public_key') and sender_public_key is not None:
                if getattr(identity_key_result.public_key, 'hex', None) and getattr(sender_public_key, 'hex', None):
                    return identity_key_result.public_key.hex() == sender_public_key.hex()
        except Exception:
            pass
        return False

    def _verify_general_message_signature(self, ctx: Any, message: Any, session: Any, sender_public_key: Any, data_to_verify: bytes) -> Optional[Exception]:
        signature = getattr(message, 'signature', None)
        verify_result = self.wallet.verify_signature(ctx, {
            'encryption_args': {
                'protocol_id': {
                    'securityLevel': 2,
                    'protocol': self.AUTH_MESSAGE_SIGNATURE
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
        if not getattr(verify_result, 'valid', False):
            return Exception("general message - invalid signature")
        return None

    def _dispatch_general_message_callbacks(self, sender_public_key: Any, payload: Any) -> None:
        for callback in self.on_general_message_received_callbacks.values():
            try:
                callback(sender_public_key, payload)
            except Exception as e:
                self.logger.warning(f"General message callback error: {e}")

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
        """
        Stop the peer. Aligns with TS/Go behavior (no strict teardown required),
        but performs best-effort cleanup:
        - Deregister transport handler by installing a no-op
        - Clear registered callbacks to avoid leaks
        """
        if self._debug:
            print("[Peer DEBUG] stop: begin")
        # Best-effort: replace on_data with a no-op to stop receiving messages
        try:
            _ = self.transport.on_data(lambda _ctx, _msg: None)
        except Exception:
            pass
        # Clear callback registries
        try:
            self.on_general_message_received_callbacks.clear()
            self.on_certificate_received_callbacks.clear()
            self.on_certificate_request_received_callbacks.clear()
            self.on_initial_response_received_callbacks.clear()
        except Exception:
            pass
        if self._debug:
            print("[Peer DEBUG] stop: done")

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
        import time
        try:
            from .utils import create_nonce
            session_nonce = create_nonce(self.wallet, { 'type': 1 }, ctx)
        except Exception:
            import os, base64
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
            return Exception(self.FAILED_TO_GET_AUTHENTICATED_SESSION)
        import os, base64, time
        request_nonce = base64.b64encode(os.urandom(32)).decode('ascii')
        identity_key_result = self.wallet.get_public_key(ctx, {'identityKey': True}, "auth-peer")
        if identity_key_result is None or not hasattr(identity_key_result, 'public_key'):
            return Exception(self.FAIL_TO_GET_IDENTIFY_KEY)
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
                    'protocol': self.AUTH_MESSAGE_SIGNATURE
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
            return Exception(self.FAILED_TO_GET_AUTHENTICATED_SESSION)
        # Create a nonce for this request
        import os, base64, time
        request_nonce = base64.b64encode(os.urandom(32)).decode('ascii')
        # Get identity key
        identity_key_result = self.wallet.get_public_key(ctx, {'identityKey': True}, "auth-peer")
        if identity_key_result is None or not hasattr(identity_key_result, 'public_key'):
            return Exception(self.FAIL_TO_GET_IDENTIFY_KEY)
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
                    'protocol': self.AUTH_MESSAGE_SIGNATURE
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
            return Exception(self.FAILED_TO_GET_AUTHENTICATED_SESSION)
        # Create a nonce for this response
        import os, base64, time
        response_nonce = base64.b64encode(os.urandom(32)).decode('ascii')
        # Get identity key
        identity_key_result = self.wallet.get_public_key(ctx, {'identityKey': True}, "auth-peer")
        if identity_key_result is None or not hasattr(identity_key_result, 'public_key'):
            return Exception(self.FAIL_TO_GET_IDENTIFY_KEY)
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
                    'protocol': self.AUTH_MESSAGE_SIGNATURE
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
        Send a message with additional security.

        Parity with TS/Go SDKs:
        - The current TS and Go implementations do not provide an additional
          secure-send layer beyond signing. For protocol parity, we delegate
          directly to the underlying transport.

        Forward-compatibility:
        - If a transport exposes a `secure_send` method, prefer it.
        - Otherwise, fall back to `send`.
        """
        try:
            secure = getattr(self.transport, 'secure_send', None)
            if callable(secure):
                return secure(ctx, message)
        except Exception:
            # Fall back to normal send on any error
            pass
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