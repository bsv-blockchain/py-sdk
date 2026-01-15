import json
import os
import struct
import types

from bsv.auth.auth_message import AuthMessage
from bsv.auth.transports.simplified_http_transport import SimplifiedHTTPTransport
from bsv.keys import PrivateKey
from bsv.utils.reader_writer import Reader, Writer


def _read_varint(reader: Reader) -> int:
    """Read a varint value from the reader."""
    first = reader.read(1)[0]
    if first < 0xFD:
        return first
    elif first == 0xFD:
        return struct.unpack("<H", reader.read(2))[0]
    elif first == 0xFE:
        return struct.unpack("<I", reader.read(4))[0]
    else:
        return struct.unpack("<Q", reader.read(8))[0]


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
    err = t.send(msg)
    assert isinstance(err, Exception)
    # Verify error message indicates handler is missing
    assert "handler" in str(err).lower() or "no handler" in str(err).lower() or "not registered" in str(err).lower()


def _create_fake_request():
    """Create a fake request function for testing."""

    def fake_request(self, method, url, headers=None, data=None):
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

    return fake_request


def _build_test_http_request_payload():
    """Build a test HTTP request payload for the auth transport."""
    writer = Writer()
    # Request ID (32 random bytes)
    request_id = os.urandom(32)
    writer.write(request_id)
    # Method
    method = "GET"
    method_bytes = method.encode("utf-8")
    writer.write_var_int_num(len(method_bytes))
    writer.write(method_bytes)
    # Path
    path = "/health"
    path_bytes = path.encode("utf-8")
    writer.write_var_int_num(len(path_bytes))
    writer.write(path_bytes)
    # Search (query string) - empty
    writer.write_var_int_num(0)
    # Headers - empty
    writer.write_var_int_num(0)
    # Body - empty
    writer.write_var_int_num(0)

    return writer.getvalue()


def test_send_general_performs_http_and_notifies_handler(
    monkeypatch,
):  # NOSONAR - Complexity (19), requires refactoring
    fake_request = _create_fake_request()

    # Patch the session in the transport instance
    t = SimplifiedHTTPTransport("https://api.test.local")
    t.client.request = types.MethodType(fake_request, t.client)

    # Register handler to capture response
    captured = {}

    def on_data(message: AuthMessage):
        captured["msg"] = message

    assert t.on_data(on_data) is None

    payload = _build_test_http_request_payload()
    identity_key = PrivateKey(6002).public_key()
    msg = AuthMessage(version="0.1", message_type="general", identity_key=identity_key, payload=payload, signature=b"")
    err = t.send(msg)
    assert err is None
    assert "msg" in captured
    resp_msg = captured["msg"]
    assert isinstance(resp_msg, AuthMessage)
    # Parse binary response payload: request_id (32 bytes) + varint status_code + varint n_headers + headers + varint body_len + body
    reader = Reader(resp_msg.payload)
    # Skip request_id (32 bytes)
    _ = reader.read(32)
    # Read status code (varint)
    status_code = _read_varint(reader)
    assert status_code == 200
    # Read headers count (varint)
    n_headers = _read_varint(reader)
    # Read headers
    headers = {}
    for _ in range(n_headers):
        # Read key length (varint)
        key_len = _read_varint(reader)
        key = reader.read(key_len).decode("utf-8")
        # Read value length (varint)
        value_len = _read_varint(reader)
        value = reader.read(value_len).decode("utf-8")
        headers[key] = value
    assert headers.get("x-bsv-test") == "1"
