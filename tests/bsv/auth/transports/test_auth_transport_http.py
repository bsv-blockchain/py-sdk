import json
import types
import os

from bsv.auth.transports.simplified_http_transport import SimplifiedHTTPTransport
from bsv.auth.auth_message import AuthMessage
from bsv.keys import PrivateKey
from bsv.utils.reader_writer import Writer


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
    # Verify error message indicates handler is missing
    assert "handler" in str(err).lower() or "no handler" in str(err).lower() or "not registered" in str(err).lower()


def test_send_general_performs_http_and_notifies_handler(monkeypatch):  # NOSONAR - Complexity (19), requires refactoring
    # Stub requests.Session().request
    def fake_request(self, method, url, headers=None, data=None):  # noqa: D401
        assert method == "GET"
        assert url == "https://api.test.local/health"
        # Response needs auth headers for parsing
        # Note: Only x-bsv-* (excluding x-bsv-auth-*) and authorization headers are included in payload
        response_headers = {
            "x-bsv-test": "1",  # This will be included in payload
            "x-bsv-auth-version": "0.1",
            "x-bsv-auth-identity-key": PrivateKey(6003).public_key().hex(),
            "x-bsv-auth-message-type": "general",
            "x-bsv-auth-nonce": "",
            "x-bsv-auth-your-nonce": "",
            "x-bsv-auth-signature": "",
        }
        return DummyResponse(200, response_headers, content=json.dumps({"ok": True}).encode("utf-8"))

    # Patch the session in the transport instance
    t = SimplifiedHTTPTransport("https://api.test.local")
    t.client.request = types.MethodType(fake_request, t.client)

    # Register handler to capture response
    captured = {}

    def on_data(ctx, message: AuthMessage):
        captured["msg"] = message
        return None

    assert t.on_data(on_data) is None

    # Prepare a general message with binary payload describing the HTTP request
    # Format: request_id (32 bytes) + varint method_len + method + varint path_len + path + varint search_len + search + varint n_headers + headers + varint body_len + body
    writer = Writer()
    # Request ID (32 random bytes)
    request_id = os.urandom(32)
    writer.write(request_id)
    # Method
    method = "GET"
    method_bytes = method.encode('utf-8')
    writer.write_var_int_num(len(method_bytes))
    writer.write(method_bytes)
    # Path
    path = "/health"
    path_bytes = path.encode('utf-8')
    writer.write_var_int_num(len(path_bytes))
    writer.write(path_bytes)
    # Search (query string) - empty
    writer.write_var_int_num(0)
    # Headers - empty
    writer.write_var_int_num(0)
    # Body - empty
    writer.write_var_int_num(0)
    
    payload = writer.getvalue()
    identity_key = PrivateKey(6002).public_key()
    msg = AuthMessage(version="0.1", message_type="general", identity_key=identity_key, payload=payload, signature=b"")
    err = t.send(None, msg)
    assert err is None
    assert "msg" in captured
    resp_msg = captured["msg"]
    assert isinstance(resp_msg, AuthMessage)
    # Parse binary response payload: request_id (32 bytes) + varint status_code + varint n_headers + headers + varint body_len + body
    from bsv.utils.reader_writer import Reader
    import struct
    reader = Reader(resp_msg.payload)
    # Skip request_id (32 bytes)
    request_id = reader.read(32)
    # Read status code (varint)
    status_first = reader.read(1)[0]
    if status_first < 0xFD:
        status_code = status_first
    elif status_first == 0xFD:
        status_code = struct.unpack('<H', reader.read(2))[0]
    elif status_first == 0xFE:
        status_code = struct.unpack('<I', reader.read(4))[0]
    else:
        status_code = struct.unpack('<Q', reader.read(8))[0]
    assert status_code == 200
    # Read headers count (varint)
    n_headers_first = reader.read(1)[0]
    if n_headers_first < 0xFD:
        n_headers = n_headers_first
    elif n_headers_first == 0xFD:
        n_headers = struct.unpack('<H', reader.read(2))[0]
    elif n_headers_first == 0xFE:
        n_headers = struct.unpack('<I', reader.read(4))[0]
    else:
        n_headers = struct.unpack('<Q', reader.read(8))[0]
    # Read headers
    headers = {}
    for _ in range(n_headers):
        # Read key length (varint)
        key_len_first = reader.read(1)[0]
        if key_len_first < 0xFD:
            key_len = key_len_first
        elif key_len_first == 0xFD:
            key_len = struct.unpack('<H', reader.read(2))[0]
        elif key_len_first == 0xFE:
            key_len = struct.unpack('<I', reader.read(4))[0]
        else:
            key_len = struct.unpack('<Q', reader.read(8))[0]
        key = reader.read(key_len).decode('utf-8')
        # Read value length (varint)
        value_len_first = reader.read(1)[0]
        if value_len_first < 0xFD:
            value_len = value_len_first
        elif value_len_first == 0xFD:
            value_len = struct.unpack('<H', reader.read(2))[0]
        elif value_len_first == 0xFE:
            value_len = struct.unpack('<I', reader.read(4))[0]
        else:
            value_len = struct.unpack('<Q', reader.read(8))[0]
        value = reader.read(value_len).decode('utf-8')
        headers[key] = value
    assert headers.get("x-bsv-test") == "1"


