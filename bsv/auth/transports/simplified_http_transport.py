import threading
from typing import Callable, Any, Optional, List
import requests

from bsv.auth.transports.transport import Transport
from bsv.auth.auth_message import AuthMessage

class SimplifiedHTTPTransport(Transport):
    """
    Transport implementation using HTTP communication (equivalent to Go's SimplifiedHTTPTransport)
    """
    def __init__(self, base_url: str, client: Optional[Any] = None):
        self.base_url = base_url
        self.client = client or requests.Session()
        self._on_data_funcs: List[Callable[[Any, AuthMessage], Optional[Exception]]] = []
        self._lock = threading.Lock()

    def send(self, ctx: Any, message: AuthMessage) -> Optional[Exception]:
        # Return error if no callback is registered
        with self._lock:
            if not self._on_data_funcs:
                return Exception("No handler registered")
        try:
            if getattr(message, 'message_type', None) == 'general':
                # payloadをHTTPリクエストとしてデシリアライズ（簡易実装）
                # ここではpayloadはJSONでリクエスト情報が入っていると仮定
                import json
                try:
                    req_info = json.loads(message.payload.decode('utf-8'))
                except Exception as e:
                    return Exception(f"Failed to decode payload: {e}")
                method = req_info.get('method', 'GET')
                path = req_info.get('path', '/')
                headers = req_info.get('headers', {})
                body = req_info.get('body', None)
                url = self.base_url + path
                resp = self.client.request(method, url, headers=headers, data=body)
                # レスポンスをAuthMessageでラップしてコールバック
                resp_payload = {
                    'status_code': resp.status_code,
                    'headers': dict(resp.headers),
                    'body': resp.content.decode('utf-8', errors='replace')
                }
                response_msg = AuthMessage(
                    version=message.version,
                    message_type=message.message_type,
                    payload=json.dumps(resp_payload).encode('utf-8')
                )
                self._notify_handlers(ctx, response_msg)
                return None
            # 通常のAuthMessage送信
            url = self.base_url
            if getattr(message, 'message_type', None) != 'general':
                url = self.base_url.rstrip('/') + '/.well-known/auth'
            import json
            data = json.dumps(message.__dict__, default=str).encode('utf-8')
            resp = self.client.post(url, data=data, headers={'Content-Type': 'application/json'})
            if resp.status_code < 200 or resp.status_code >= 300:
                return Exception(f"HTTP request failed with status {resp.status_code}: {resp.text}")
            if resp.content:
                try:
                    resp_data = json.loads(resp.content.decode('utf-8'))
                    response_msg = AuthMessage(**resp_data)
                    self._notify_handlers(ctx, response_msg)
                except Exception:
                    pass  # 応答がAuthMessageでなければ無視
            return None
        except Exception as e:
            return Exception(f"Failed to send AuthMessage: {e}")

    def on_data(self, callback: Callable[[Any, AuthMessage], Optional[Exception]]) -> Optional[Exception]:
        if callback is None:
            return Exception("callback cannot be None")
        with self._lock:
            self._on_data_funcs.append(callback)
        return None

    def get_registered_on_data(self) -> tuple[Optional[Callable[[Any, AuthMessage], Exception]], Optional[Exception]]:
        with self._lock:
            if not self._on_data_funcs:
                return None, Exception("no handlers registered")
            return self._on_data_funcs[0], None

    def _notify_handlers(self, ctx: Any, message: AuthMessage):
        with self._lock:
            handlers = list(self._on_data_funcs)
        for handler in handlers:
            try:
                handler(ctx, message)
            except Exception:
                pass
