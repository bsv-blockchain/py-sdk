import pytest

pytestmark = pytest.mark.skip(reason="Deprecated integration; covered by full E2E tests")
import asyncio
from aiohttp import web
import base64
import json

# [Server]
# cd py-sdk && PYTHONPATH=/mnt/extra/bsv-blockchain/py-sdk python3 tests/test_authfetch_server.py &
# [Client]
# cd py-sdk && python3 -m pytest -v tests/test_authfetch_server_client.py | cat

# 簡易セッション管理
db_sessions = {}

async def handle_authfetch(request):
    data = await request.read()
    try:
        msg = json.loads(data.decode())
    except Exception:
        # Intentional: Server error handling - catch all exceptions to return proper HTTP error
        return web.Response(status=400, text="Invalid message format")

    msg_type = msg.get("message_type")
    if msg_type == "initialRequest":
        client_nonce = msg.get("initial_nonce")
        identity_key = msg.get("identity_key")
        server_nonce = base64.b64encode(b"server_nonce_32bytes____1234567890").decode()
        db_sessions[identity_key] = {
            "client_nonce": client_nonce,
            "server_nonce": server_nonce,
            "is_authenticated": True,
        }
        response = {
            "version": "0.1",
            "message_type": "initialResponse",
            "identity_key": "server_identity_key_dummy",
            "initial_nonce": server_nonce,
            "your_nonce": client_nonce,
            "certificates": [],
            "signature": "dummy_signature"
        }
        return web.Response(body=json.dumps(response).encode(), content_type="application/json")
    elif msg_type == "general":
        identity_key = msg.get("identity_key")
        session = db_sessions.get(identity_key)
        if not session or not session.get("is_authenticated"):
            return web.Response(status=403, text="Not authenticated")
        response = {
            "version": "0.1",
            "message_type": "general",
            "identity_key": "server_identity_key_dummy",
            "payload": msg.get("payload"),
            "signature": "dummy_signature"
        }
        return web.Response(body=json.dumps(response).encode(), content_type="application/json")
    else:
        return web.Response(status=400, text="Unknown message_type")

app = web.Application()
app.router.add_post("/authfetch", handle_authfetch)

if __name__ == "__main__":
    web.run_app(app, port=8082)
