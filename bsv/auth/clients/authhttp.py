import threading
from typing import Any, Callable, Dict, Optional, List
import logging
import base64
import os
import time
import urllib.parse
import requests
from requests.exceptions import RetryError, HTTPError

from bsv.auth.peer import Peer
from bsv.auth.session_manager import DefaultSessionManager
from bsv.auth.requested_certificate_set import RequestedCertificateSet
from bsv.auth.verifiable_certificate import VerifiableCertificate
from bsv.auth.transports.simplified_http_transport import SimplifiedHTTPTransport

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

    def fetch(self, ctx: Any, url_str: str, config: Optional[SimplifiedFetchRequestOptions] = None):
        if config is None:
            config = SimplifiedFetchRequestOptions()
        # Handle retry counter
        if config.retry_counter is not None:
            if config.retry_counter <= 0:
                raise RetryError("request failed after maximum number of retries")
            config.retry_counter -= 1
        # Extract base URL
        parsed_url = urllib.parse.urlparse(url_str)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        # Create peer if needed
        if base_url not in self.peers:
            transport = SimplifiedHTTPTransport(base_url)
            peer = Peer(
                wallet=self.wallet,
                transport=transport,
                certificates_to_request=self.requested_certificates,
                session_manager=self.session_manager
            )
            auth_peer = AuthPeer()
            auth_peer.peer = peer
            self.peers[base_url] = auth_peer
            # Set up certificate received/requested listeners（省略: 必要に応じて追加）
        peer_to_use = self.peers[base_url]
        # Generate request nonce
        request_nonce = os.urandom(32)
        request_nonce_b64 = base64.b64encode(request_nonce).decode()
        # Serialize request
        request_data = self.serialize_request(
            config.method,
            config.headers,
            config.body or b"",
            parsed_url,
            request_nonce
        )
        # コールバック用イベントと結果格納
        response_event = threading.Event()
        response_holder = {'resp': None, 'err': None}
        # コールバック登録
        self.callbacks[request_nonce_b64] = {
            'resolve': lambda resp: (response_holder.update({'resp': resp}), response_event.set()),
            'reject': lambda err: (response_holder.update({'err': err}), response_event.set()),
        }
        # Peerのgeneral messageリスナー登録
        def on_general_message(sender_public_key, payload):
            # 先頭32バイトがresponse_nonce
            if not payload or len(payload) < 32:
                return
            response_nonce = payload[:32]
            response_nonce_b64 = base64.b64encode(response_nonce).decode()
            if response_nonce_b64 != request_nonce_b64:
                return  # 自分のリクエストでなければ無視
            # 以降はHTTPレスポンスのデシリアライズ等（省略: 必要に応じて実装）
            self.callbacks[request_nonce_b64]['resolve'](payload)
        listener_id = peer_to_use.peer.listen_for_general_messages(on_general_message)
        try:
            # Peer経由で送信（ToPeer相当）
            err = peer_to_use.peer.to_peer(ctx, request_data, None, 30000)
            if err:
                self.callbacks[request_nonce_b64]['reject'](err)
        except Exception as e:
            self.callbacks[request_nonce_b64]['reject'](e)
        # レスポンス待機（またはタイムアウト）
        response_event.wait(timeout=30)  # 30秒タイムアウト
        # コールバック解除
        peer_to_use.peer.stop_listening_for_general_messages(listener_id)
        self.callbacks.pop(request_nonce_b64, None)
        # 結果返却
        if response_holder['err']:
            raise RuntimeError(response_holder['err'])
        return response_holder['resp']

    def send_certificate_request(self, ctx: Any, base_url: str, certificates_to_request):
        """
        GoのSendCertificateRequest相当: Peer経由で証明書リクエストを送り、受信まで待機。
        """
        parsed_url = urllib.parse.urlparse(base_url)
        base_url_str = f"{parsed_url.scheme}://{parsed_url.netloc}"
        if base_url_str not in self.peers:
            transport = SimplifiedHTTPTransport(base_url_str)
            peer = Peer(
                wallet=self.wallet,
                transport=transport,
                certificates_to_request=self.requested_certificates,
                session_manager=self.session_manager
            )
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
            err = peer_to_use.peer.request_certificates(ctx, None, certificates_to_request, 30000)
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
        import struct
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

    def handle_payment_and_retry(self, ctx: Any, url_str: str, config: SimplifiedFetchRequestOptions, original_response):
        """
        On 402 Payment Required, create a payment transaction, attach x-bsv-payment header, and retry.
        Refactored version (reduced Cognitive Complexity)
        """
        payment_info = self._validate_payment_headers(original_response)
        derivation_suffix = self._generate_derivation_suffix()
        derived_public_key = self._get_payment_public_key(ctx, payment_info, derivation_suffix)
        locking_script = self._build_locking_script(derived_public_key)
        tx_b64 = self._create_payment_transaction(ctx, url_str, payment_info, derivation_suffix, locking_script)
        self._set_payment_header(config, payment_info, derivation_suffix, tx_b64)
        if config.retry_counter is None:
            config.retry_counter = 3
        return self.fetch(ctx, url_str, config)

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

    def _get_payment_public_key(self, ctx, payment_info, derivation_suffix):
        if not hasattr(self.wallet, 'get_public_key'):
            raise NotImplementedError("wallet.get_public_key is not implemented")
        protocol_id = [2, '3241645161d8']
        key_id = f"{payment_info['derivation_prefix']} {derivation_suffix}"
        pubkey_result = self.wallet.get_public_key(ctx, {
            "protocolID": protocol_id,
            "keyID": key_id,
            "counterparty": payment_info["server_identity_key"]
        }, None)
        if not pubkey_result or "publicKey" not in pubkey_result:
            raise RuntimeError("wallet.get_public_key did not return a publicKey")
        return pubkey_result["publicKey"]

    def _build_locking_script(self, derived_public_key):
        return p2pkh_locking_script_from_pubkey(derived_public_key)

    def _create_payment_transaction(self, ctx, url_str, payment_info, derivation_suffix, locking_script):
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
        action_result = self.wallet.create_action(ctx, action_args, None)
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
