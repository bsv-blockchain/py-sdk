import json
import types

from bsv.auth.transports.simplified_http_transport import SimplifiedHTTPTransport
from bsv.auth.auth_message import AuthMessage
from bsv.keys import PrivateKey


class DummyResponse:
    def __init__(self, status_code=200, headers=None, content=b"{}"):
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "application/json"}
        self.content = content
        self.text = content.decode("utf-8", errors="replace")


def test_send_without_handler_returns_error(monkeypatch):
    # No handler registered
    t = SimplifiedHTTPTransport("https://example.com")
    identity_key = PrivateKey(6001).public_key()
    msg = AuthMessage(version="0.1", message_type="general", identity_key=identity_key, payload=b"{}", signature=b"")
    err = t.send(None, msg)
    assert isinstance(err, Exception)


def test_send_general_performs_http_and_notifies_handler(monkeypatch):
    # Stub requests.Session().request
    def fake_request(self, method, url, headers=None, data=None):  # noqa: D401
        assert method == "GET"
        assert url == "https://api.test.local/health"
        return DummyResponse(200, {"X-Test": "1"}, content=json.dumps({"ok": True}).encode("utf-8"))

    # Patch the session in the transport instance
    t = SimplifiedHTTPTransport("https://api.test.local")
    t.client.request = types.MethodType(fake_request, t.client)

    # Register handler to capture response
    captured = {}

    def on_data(ctx, message: AuthMessage):
        captured["msg"] = message
        return None

    assert t.on_data(on_data) is None

    # Prepare a general message with JSON payload describing the HTTP request
    payload = json.dumps({"method": "GET", "path": "/health", "headers": {}}).encode("utf-8")
    identity_key = PrivateKey(6002).public_key()
    msg = AuthMessage(version="0.1", message_type="general", identity_key=identity_key, payload=payload, signature=b"")
    err = t.send(None, msg)
    assert err is None
    assert "msg" in captured
    resp_msg = captured["msg"]
    assert isinstance(resp_msg, AuthMessage)
    body = json.loads(resp_msg.payload.decode("utf-8"))
    assert body["status_code"] == 200
    assert body["headers"]["X-Test"] == "1"


