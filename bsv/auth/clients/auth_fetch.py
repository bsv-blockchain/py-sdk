import threading
from typing import Any, Callable, Dict, Optional, List, Tuple
import logging
import base64
import os
import time
import urllib.parse
import json
import struct
import requests
from requests.exceptions import RetryError, HTTPError

from bsv.auth.peer import Peer
from bsv.auth.session_manager import DefaultSessionManager
from bsv.auth.requested_certificate_set import RequestedCertificateSet
from bsv.auth.verifiable_certificate import VerifiableCertificate
from bsv.auth.transports.simplified_http_transport import SimplifiedHTTPTransport
from bsv.auth.peer import PeerOptions

class SimplifiedFetchRequestOptions:
    def __init__(self, method: str = "GET", headers: Optional[Dict[str, str]] = None, body: Optional[bytes] = None, retry_counter: Optional[int] = None):
        self.method = method
        self.headers = headers or {}
        self.body = body
        self.retry_counter = retry_counter

class AuthPeer:
    def __init__(self):
        self.peer = None  # type: Optional[Peer]
        self.identity_key = ""
        self.supports_mutual_auth = None  # type: Optional[bool]
        self.pending_certificate_requests: List[bool] = []

class AuthFetch:
    def __init__(self, wallet, requested_certs, session_manager=None):
        if session_manager is None:
            session_manager = DefaultSessionManager()
        self.session_manager = session_manager
        self.wallet = wallet
        self.callbacks = {}  # type: Dict[str, Dict[str, Callable]]
        self.certificates_received = []  # type: List[VerifiableCertificate]
        self.requested_certificates = requested_certs
        self.peers = {}  # type: Dict[str, AuthPeer]
        self.logger = logging.getLogger("AuthHTTP")

    def _check_retry_limit(self, config: SimplifiedFetchRequestOptions) -> None:
        """Check and decrement retry counter."""
        if config.retry_counter is not None:
            if config.retry_counter <= 0:
                raise RetryError("request failed after maximum number of retries")
            config.retry_counter -= 1

    def _get_or_create_peer(self, base_url: str) -> AuthPeer:
        """Get existing peer or create new one for base URL."""
        if base_url not in self.peers:
            transport = SimplifiedHTTPTransport(base_url)
            peer = Peer(PeerOptions(
                wallet=self.wallet,
                transport=transport,
                certificates_to_request=self.requested_certificates,
                session_manager=self.session_manager
            ))
            auth_peer = AuthPeer()
            auth_peer.peer = peer
            self.peers[base_url] = auth_peer
            
            def _on_certs_received(sender_public_key, certs):
                try:
                    self.certificates_received.extend(certs or [])
                except Exception:
                    pass
            self.peers[base_url].peer.listen_for_certificates_received(_on_certs_received)
        
        return self.peers[base_url]

    def _try_fallback_http(self, url_str: str, config: SimplifiedFetchRequestOptions, peer: AuthPeer):
        """Try HTTP fallback if mutual auth is not supported."""
        if peer.supports_mutual_auth is not None and peer.supports_mutual_auth is False:
            resp = self.handle_fetch_and_validate(url_str, config, peer)
            if getattr(resp, 'status_code', None) == 402:
                return self.handle_payment_and_retry(url_str, config, resp)
            return resp
        return None

    def _setup_callbacks(self, request_nonce_b64: str) -> tuple[threading.Event, dict]:
        """Set up response callbacks and event."""
        response_event = threading.Event()
        response_holder = {'resp': None, 'err': None}
        self.callbacks[request_nonce_b64] = {
            'resolve': lambda resp: (response_holder.update({'resp': resp}), response_event.set()),
            'reject': lambda err: (response_holder.update({'err': err}), response_event.set()),
        }
        return response_event, response_holder

    def _create_message_listener(self, request_nonce_b64: str, url_str: str, config: SimplifiedFetchRequestOptions):
        """Create listener for general messages."""
        def on_general_message(sender_public_key, payload):
            try:
                resp_obj = self._parse_general_response(sender_public_key, payload, request_nonce_b64, url_str, config)
            except Exception:
                return
            if resp_obj is None:
                return
            self.callbacks[request_nonce_b64]['resolve'](resp_obj)
        return on_general_message

    def _handle_peer_error(self, err: Exception, base_url: str, url_str: str, config: SimplifiedFetchRequestOptions, request_nonce_b64: str, peer_to_use: AuthPeer) -> None:
        """Handle errors from peer transmission."""
        err_str = str(err)
        if 'Session not found for nonce' in err_str:
            try:
                del self.peers[base_url]
            except Exception:
                pass
            if config.retry_counter is None:
                config.retry_counter = 3
            self.callbacks[request_nonce_b64]['resolve'](self.fetch(url_str, config))
        elif 'HTTP server failed to authenticate' in err_str:
            try:
                resp = self.handle_fetch_and_validate(url_str, config, peer_to_use)
                self.callbacks[request_nonce_b64]['resolve'](resp)
            except Exception as e:
                self.callbacks[request_nonce_b64]['reject'](e)
        else:
            self.callbacks[request_nonce_b64]['reject'](err)

    def _cleanup_and_get_response(self, peer: AuthPeer, listener_id: Any, request_nonce_b64: str, response_holder: dict) -> Any:
        """Cleanup listeners and return response."""
        peer.peer.stop_listening_for_general_messages(listener_id)
        self.callbacks.pop(request_nonce_b64, None)
        
        if response_holder['err']:
            raise RuntimeError(response_holder['err'])
        return response_holder['resp']

    def fetch(self, url_str: str, config: Optional[SimplifiedFetchRequestOptions] = None):
        if config is None:
            config = SimplifiedFetchRequestOptions()
        
        # Check retry limit
        self._check_retry_limit(config)
        
        # Parse URL and get/create peer
        parsed_url = urllib.parse.urlparse(url_str)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        peer_to_use = self._get_or_create_peer(base_url)
        
        # Try fallback HTTP if auth not supported
        fallback_resp = self._try_fallback_http(url_str, config, peer_to_use)
        if fallback_resp is not None:
            return fallback_resp
        
        # Generate request nonce and serialize request
        request_nonce = os.urandom(32)
        request_nonce_b64 = base64.b64encode(request_nonce).decode()
        request_data = self.serialize_request(
            config.method, config.headers, config.body or b"", parsed_url, request_nonce
        )
        
        # Set up callbacks and listener
        response_event, response_holder = self._setup_callbacks(request_nonce_b64)
        on_general_message = self._create_message_listener(request_nonce_b64, url_str, config)
        listener_id = peer_to_use.peer.listen_for_general_messages(on_general_message)
        
        # Send request via peer
        try:
            err = peer_to_use.peer.to_peer(request_data, None, 30000)
            if err:
                self._handle_peer_error(err, base_url, url_str, config, request_nonce_b64, peer_to_use)
        except Exception as e:
            self.callbacks[request_nonce_b64]['reject'](e)
        
        # Wait for response
        response_event.wait(timeout=30)
        
        # Cleanup and get response
        resp_obj = self._cleanup_and_get_response(peer_to_use, listener_id, request_nonce_b64, response_holder)
        
        # Handle payment if needed
        try:
            if getattr(resp_obj, 'status_code', None) == 402:
                return self.handle_payment_and_retry(ctx, url_str, config, resp_obj)
        except Exception:
            pass
        
        return resp_obj

    # --- Helpers to parse the general response payload and build a Response-like object ---
    def _parse_general_response(self, sender_public_key: Optional[Any], payload: bytes, request_nonce_b64: str, url_str: str, config: SimplifiedFetchRequestOptions):
        if not payload:
            return None
        # Try binary format first (Go/TS protocol)
        resp = self._try_parse_binary_general(sender_public_key, payload, request_nonce_b64, url_str, config)
        if resp is not None:
            return resp
        # Fallback to JSON structure used by the simplified Python transport
        try:
            txt = payload.decode('utf-8', errors='strict')
            obj = json.loads(txt)
            status = int(obj.get('status_code', 0))
            headers = obj.get('headers', {}) or {}
            body_str = obj.get('body', '')
            body_bytes = body_str.encode('utf-8')
            return self._build_response(url_str, config.method or 'GET', status, headers, body_bytes)
        except Exception:
            return None

    def _try_parse_binary_general(self, sender_public_key: Optional[Any], payload: bytes, request_nonce_b64: str, url_str: str, config: SimplifiedFetchRequestOptions):
        try:
            if len(payload) < 33:  # require nonce + at least one byte for status code varint
                return None
            reader = _BinaryReader(payload)
            response_nonce = reader.read_bytes(32)
            response_nonce_b64 = base64.b64encode(response_nonce).decode()
            if response_nonce_b64 != request_nonce_b64:
                return None
            # Save identity key and mutual auth support flag
            if sender_public_key is not None:
                try:
                    self.peers[urllib.parse.urlparse(url_str).scheme + '://' + urllib.parse.urlparse(url_str).netloc].identity_key = getattr(sender_public_key, 'to_der_hex', lambda: str(sender_public_key))()
                    self.peers[urllib.parse.urlparse(url_str).scheme + '://' + urllib.parse.urlparse(url_str).netloc].supports_mutual_auth = True
                except Exception:
                    try:
                        self.peers[urllib.parse.urlparse(url_str).scheme + '://' + urllib.parse.urlparse(url_str).netloc].supports_mutual_auth = True
                    except Exception:
                        pass
            status_code = reader.read_varint32()
            n_headers = reader.read_varint32()
            headers: Dict[str, str] = {}
            for _ in range(n_headers):
                key = reader.read_string()
                val = reader.read_string()
                headers[key] = val
            # Add back server identity key if available
            if sender_public_key is not None:
                try:
                    headers['x-bsv-auth-identity-key'] = getattr(sender_public_key, 'to_der_hex', lambda: str(sender_public_key))()
                except Exception:
                    headers['x-bsv-auth-identity-key'] = str(sender_public_key)
            body_len = reader.read_varint32()
            body_bytes = b''
            if body_len > 0:
                body_bytes = reader.read_bytes(body_len)
            return self._build_response(url_str, config.method or 'GET', int(status_code), headers, body_bytes)
        except Exception:
            return None

    def _build_response(self, url_str: str, method: str, status: int, headers: Dict[str, str], body: bytes):
        resp_obj = requests.Response()
        resp_obj.status_code = int(status)
        try:
            from requests.structures import CaseInsensitiveDict
            resp_obj.headers = CaseInsensitiveDict(headers or {})
        except Exception:
            resp_obj.headers = headers or {}
        resp_obj._content = body or b''
        resp_obj.url = url_str
        try:
            req = requests.Request(method=method or 'GET', url=url_str)
            resp_obj.request = req.prepare()
        except Exception:
            pass
        resp_obj.reason = str(status)
        return resp_obj

    def send_certificate_request(self, base_url: str, certificates_to_request):
        """
        GoのSendCertificateRequest相当: Peer経由で証明書リクエストを送り、受信まで待機。
        """
        parsed_url = urllib.parse.urlparse(base_url)
        base_url_str = f"{parsed_url.scheme}://{parsed_url.netloc}"
        if base_url_str not in self.peers:
            transport = SimplifiedHTTPTransport(base_url_str)
            peer = Peer(PeerOptions(
                wallet=self.wallet,
                transport=transport,
                certificates_to_request=self.requested_certificates,
                session_manager=self.session_manager
            ))
            auth_peer = AuthPeer()
            auth_peer.peer = peer
            self.peers[base_url_str] = auth_peer
        peer_to_use = self.peers[base_url_str]
        # コールバック用イベントと結果格納
        cert_event = threading.Event()
        cert_holder = {'certs': None, 'err': None}
        def on_certificates_received(sender_public_key, certs):
            cert_holder['certs'] = certs
            cert_event.set()
        callback_id = peer_to_use.peer.listen_for_certificates_received(on_certificates_received)
        try:
            err = peer_to_use.peer.request_certificates(None, certificates_to_request, 30000)
            if err:
                cert_holder['err'] = err
                cert_event.set()
        except Exception as e:
            cert_holder['err'] = e
            cert_event.set()
        cert_event.wait(timeout=30)
        peer_to_use.peer.stop_listening_for_certificates_received(callback_id)
        if cert_holder['err']:
            raise RuntimeError(cert_holder['err'])
        return cert_holder['certs']

    def consume_received_certificates(self):
        certs = self.certificates_received
        self.certificates_received = []
        return certs

    def serialize_request(self, method: str, headers: Dict[str, str], body: bytes, parsed_url, request_nonce: bytes):
        """
        GoのserializeRequestメソッドをPythonで再現。
        - method, headers, body, parsed_url, request_nonceをバイナリで直列化
        - ヘッダーはx-bsv-*系やcontent-type, authorizationのみ含める
        - Goのutil.NewWriter/WriteVarInt相当はbytearray+独自関数で実装
        """
        buf = bytearray()
        self._write_bytes(buf, request_nonce)
        self._write_string(buf, method)
        self._write_path_and_query(buf, parsed_url)
        included_headers = self._select_headers(headers)
        self._write_headers(buf, included_headers)
        body = self._determine_body(body, method, included_headers)
        self._write_body(buf, body)
        return bytes(buf)

    def _select_headers(self, headers):
        included_headers = []
        for k, v in headers.items():
            key = k.lower()
            if key.startswith('x-bsv-') and not key.startswith('x-bsv-auth'):
                included_headers.append((key, v))
            elif key == 'authorization':
                included_headers.append((key, v))
            elif key.startswith('content-type'):
                content_type = v.split(';')[0].strip()
                included_headers.append((key, content_type))
            else:
                self.logger.warning(f"Unsupported header in simplified fetch: {k}")
        included_headers.sort(key=lambda x: x[0])
        return included_headers

    def _determine_body(self, body, method, included_headers):
        methods_with_body = ["POST", "PUT", "PATCH", "DELETE"]
        if not body and method.upper() in methods_with_body:
            for k, v in included_headers:
                if k == 'content-type' and 'application/json' in v:
                    return b'{}'
            return b''
        return body

    def _write_path_and_query(self, buf, parsed_url):
        if parsed_url.path:
            self._write_string(buf, parsed_url.path)
        else:
            self._write_varint(buf, 0xFFFFFFFFFFFFFFFF)  # -1
        if parsed_url.query:
            self._write_string(buf, '?' + parsed_url.query)
        else:
            self._write_varint(buf, 0xFFFFFFFFFFFFFFFF)  # -1

    def _write_headers(self, buf, included_headers):
        self._write_varint(buf, len(included_headers))
        for k, v in included_headers:
            self._write_string(buf, k)
            self._write_string(buf, v)

    def _write_body(self, buf, body):
        if body:
            self._write_varint(buf, len(body))
            self._write_bytes(buf, body)
        else:
            self._write_varint(buf, 0xFFFFFFFFFFFFFFFF)  # -1

    def _write_varint(self, writer: bytearray, value: int):
        writer.extend(struct.pack('<Q', value))

    def _write_bytes(self, writer: bytearray, b: bytes):
        writer.extend(b)

    def _write_string(self, writer: bytearray, s: str):
        b = s.encode('utf-8')
        self._write_varint(writer, len(b))
        writer.extend(b)

    def handle_fetch_and_validate(self, url_str: str, config: SimplifiedFetchRequestOptions, peer_to_use: AuthPeer):
        """
        GoのhandleFetchAndValidate相当: 通常のHTTPリクエストを送り、サーバーが認証済みを偽装していないか検証。
        """
        method = config.method or "GET"
        headers = config.headers or {}
        body = config.body or b""
        resp = requests.request(method, url_str, headers=headers, data=body)
        # サーバーが認証済みを偽装していないかチェック
        for k in resp.headers:
            k_lower = k.lower()
            if k_lower == "x-bsv-auth-identity-key" or k_lower.startswith("x-bsv-auth"):
                raise PermissionError("the server is trying to claim it has been authenticated when it has not")
        # 成功時はmutual auth非対応を記録
        if resp.status_code < 400:
            peer_to_use.supports_mutual_auth = False
            return resp
        raise HTTPError(f"request failed with status: {resp.status_code}")

    def handle_payment_and_retry(self, url_str: str, config: SimplifiedFetchRequestOptions, original_response):
        """
        On 402 Payment Required, create a payment transaction, attach x-bsv-payment header, and retry.
        Refactored version (reduced Cognitive Complexity)
        """
        payment_info = self._validate_payment_headers(original_response)
        derivation_suffix = self._generate_derivation_suffix()
        derived_public_key = self._get_payment_public_key(payment_info, derivation_suffix)
        locking_script = self._build_locking_script(derived_public_key)
        tx_b64 = self._create_payment_transaction(url_str, payment_info, derivation_suffix, locking_script)
        self._set_payment_header(config, payment_info, derivation_suffix, tx_b64)
        if config.retry_counter is None:
            config.retry_counter = 3
        return self.fetch(url_str, config)

    def _validate_payment_headers(self, response):
        payment_version = response.headers.get("x-bsv-payment-version")
        if not payment_version or payment_version != "1.0":
            raise ValueError(f"unsupported x-bsv-payment-version response header. Client version: 1.0, Server version: {payment_version}")
        satoshis_required = response.headers.get("x-bsv-payment-satoshis-required")
        if not satoshis_required:
            raise ValueError("missing x-bsv-payment-satoshis-required response header")
        satoshis_required = int(satoshis_required)
        if satoshis_required <= 0:
            raise ValueError("invalid x-bsv-payment-satoshis-required response header value")
        server_identity_key = response.headers.get("x-bsv-auth-identity-key")
        if not server_identity_key:
            raise ValueError("missing x-bsv-auth-identity-key response header")
        derivation_prefix = response.headers.get("x-bsv-payment-derivation-prefix")
        if not derivation_prefix:
            raise ValueError("missing x-bsv-payment-derivation-prefix response header")
        return {
            "satoshis_required": satoshis_required,
            "server_identity_key": server_identity_key,
            "derivation_prefix": derivation_prefix
        }

    def _generate_derivation_suffix(self):
        import base64, os
        return base64.b64encode(os.urandom(8)).decode()

    def _get_payment_public_key(self, payment_info, derivation_suffix):
        if not hasattr(self.wallet, 'get_public_key'):
            raise NotImplementedError("wallet.get_public_key is not implemented")
        protocol_id = [2, '3241645161d8']
        key_id = f"{payment_info['derivation_prefix']} {derivation_suffix}"
        pubkey_result = self.wallet.get_public_key({
            "protocolID": protocol_id,
            "keyID": key_id,
            "counterparty": payment_info["server_identity_key"]
        }, None)
        if not pubkey_result or "publicKey" not in pubkey_result:
            raise RuntimeError("wallet.get_public_key did not return a publicKey")
        return pubkey_result["publicKey"]

    def _build_locking_script(self, derived_public_key):
        return p2pkh_locking_script_from_pubkey(derived_public_key)

    def _create_payment_transaction(self, url_str, payment_info, derivation_suffix, locking_script):
        import json, base64
        if not hasattr(self.wallet, 'create_action'):
            raise NotImplementedError("wallet.create_action is not implemented")
        action_args = {
            "description": f"Payment for request to {url_str}",
            "outputs": [
                {
                    "satoshis": payment_info["satoshis_required"],
                    "lockingScript": locking_script,
                    "customInstructions": json.dumps({
                        "derivationPrefix": payment_info["derivation_prefix"],
                        "derivationSuffix": derivation_suffix,
                        "payee": payment_info["server_identity_key"]
                    }),
                    "outputDescription": "HTTP request payment"
                }
            ],
            "options": {
                "randomizeOutputs": False
            }
        }
        action_result = self.wallet.create_action(action_args, None)
        if not action_result or "tx" not in action_result:
            raise RuntimeError("wallet.create_action did not return a transaction")
        tx_bytes = action_result["tx"]
        if isinstance(tx_bytes, str):
            return tx_bytes
        else:
            return base64.b64encode(tx_bytes).decode()

    def _set_payment_header(self, config, payment_info, derivation_suffix, tx_b64):
        import json
        payment_info_dict = {
            "derivationPrefix": payment_info["derivation_prefix"],
            "derivationSuffix": derivation_suffix,
            "transaction": tx_b64
        }
        payment_info_json = json.dumps(payment_info_dict)
        if config.headers is None:
            config.headers = {}
        config.headers["x-bsv-payment"] = payment_info_json


class _BinaryReader:
    """
    Minimal binary reader compatible with the Go util.Reader used by AuthHTTP.
    Supports:
    - read_bytes(n)
    - read_varint() / read_varint32()
    - read_string() where string is prefixed with varint length and -1 encoded as 0xFFFFFFFFFFFFFFFF
    """

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    def _require(self, n: int):
        if self._pos + n > len(self._data) or n < 0:
            raise ValueError("read past end of data")

    def read_bytes(self, n: int) -> bytes:
        self._require(n)
        b = self._data[self._pos:self._pos + n]
        self._pos += n
        return b

    def read_varint(self) -> int:
        self._require(1)
        first = self._data[self._pos]
        self._pos += 1
        if first < 0xFD:
            return first
        if first == 0xFD:
            self._require(2)
            val = struct.unpack_from('<H', self._data, self._pos)[0]
            self._pos += 2
            return val
        if first == 0xFE:
            self._require(4)
            val = struct.unpack_from('<I', self._data, self._pos)[0]
            self._pos += 4
            return val
        # 0xFF
        self._require(8)
        val = struct.unpack_from('<Q', self._data, self._pos)[0]
        self._pos += 8
        return val

    def read_varint32(self) -> int:
        return int(self.read_varint() & 0xFFFFFFFF)

    def read_string(self) -> str:
        length = self.read_varint()
        NEG_ONE = 0xFFFFFFFFFFFFFFFF
        if length == 0 or length == NEG_ONE:
            return ""
        b = self.read_bytes(int(length))
        return b.decode('utf-8', errors='strict')


# --- P2PKH lockingScript生成関数 ---
def p2pkh_locking_script_from_pubkey(pubkey_hex: str) -> str:
    """
    与えられた圧縮公開鍵hex文字列からP2PKH lockingScript（HexString）を生成する。
    """
    import hashlib
    import binascii
    # 1. 公開鍵hex→bytes
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    # 2. pubkey hash160
    sha256 = hashlib.sha256(pubkey_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    # 3. lockingScript: OP_DUP OP_HASH160 <20bytes> OP_EQUALVERIFY OP_CHECKSIG
    script = (
        b'76'  # OP_DUP
        b'a9'  # OP_HASH160
        + bytes([len(ripemd160)])
        + ripemd160
        + b'88'  # OP_EQUALVERIFY
        + b'ac'  # OP_CHECKSIG
    )
    return binascii.hexlify(script).decode()