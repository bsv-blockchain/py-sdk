import pytest

pytestmark = pytest.mark.skip(reason="Deprecated integration; covered by full E2E tests")
import asyncio
import aiohttp
import base64
import json

@pytest.mark.asyncio
async def test_authfetch_server_flow():
    url = "https://localhost:8083/authfetch"
    # 1. initialRequest送信
    client_nonce = base64.b64encode(b"client_nonce_32bytes____1234567890").decode()
    initial_request = {
        "version": "0.1",
        "message_type": "initialRequest",
        "identity_key": "client_identity_key_dummy",
        "initial_nonce": client_nonce,
        "requested_certificates": [],
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=json.dumps(initial_request).encode()) as resp:
            assert resp.status == 200
            response_data = await resp.json()
            assert response_data["message_type"] == "initialResponse"
            server_nonce = response_data["initial_nonce"]
            # 2. generalメッセージ送信（認証済みセッションで）
            general_msg = {
                "version": "0.1",
                "message_type": "general",
                "identity_key": "client_identity_key_dummy",
                "payload": {"test": "hello"},
                "nonce": client_nonce,
                "your_nonce": server_nonce,
            }
            async with session.post(url, data=json.dumps(general_msg).encode()) as resp2:
                assert resp2.status == 200
                general_resp = await resp2.json()
                assert general_resp["message_type"] == "general"
                assert general_resp["payload"]["test"] == "hello"
