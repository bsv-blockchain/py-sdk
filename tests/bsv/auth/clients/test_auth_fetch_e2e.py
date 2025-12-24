import pytest
import json
import sys
from pathlib import Path
from aiohttp import web
from bsv.auth.clients.auth_fetch import AuthFetch, SimplifiedFetchRequestOptions
from bsv.auth.requested_certificate_set import RequestedCertificateSet
from bsv.auth.peer import PeerOptions
import asyncio

# Add parent directory to path for SSL helper
test_dir = Path(__file__).parent.parent
sys.path.insert(0, str(test_dir))
from test_ssl_helper import get_server_ssl_context

class DummyWallet:
    def get_public_key(self, ctx, args, originator):
        return {"publicKey": "02a1633c...", "derivationPrefix": "m/0"}
    def create_action(self, ctx, args, originator):
        return {"tx": "0100000001abcdef..."}
    def create_signature(self, ctx, args, originator):
        return {"signature": b"dummy_signature"}
    def verify_signature(self, ctx, args, originator):
        return {"valid": True}

import json
import pytest
from aiohttp import web

import pytest_asyncio

@pytest_asyncio.fixture
async def auth_server(unused_tcp_port):
    async def handle_authfetch(request):
        print("[auth_server] /authfetch called")
        body = await request.json()
        print(f"[auth_server] received body: {body}")
        # emulate processing delay so the test actually waits
        await asyncio.sleep(0.3)
        # 最小応答（initialRequestに対するinitialResponse）
        resp = {
            "message_type": "initialResponse",
            "server_nonce": "c2VydmVyX25vbmNl",
        }
        print(f"[auth_server] sending: {resp}")
        return web.json_response(resp)

    app = web.Application()
    app.router.add_post("/authfetch", handle_authfetch)
    runner = web.AppRunner(app)
    await runner.setup()
    port = unused_tcp_port
    
    # Get SSL context for HTTPS
    ssl_context = get_server_ssl_context()
    
    site = web.TCPSite(runner, "127.0.0.1", port, ssl_context=ssl_context)
    await site.start()
    try:
        yield f"https://127.0.0.1:{port}"
    finally:
        await runner.cleanup()

@pytest.mark.asyncio
async def test_authfetch_e2e(auth_server):
    import requests
    from unittest.mock import patch
    
    wallet = DummyWallet()
    requested_certs = RequestedCertificateSet()
    auth_fetch = AuthFetch(wallet, requested_certs)

    from bsv.auth.clients.auth_fetch import AuthPeer

    base = auth_server.rstrip("/")
    # 既存のキーを消してから、フォールバック指定のPeerを登録
    auth_fetch.peers.pop(base, None)
    ap = AuthPeer()
    ap.supports_mutual_auth = False  # ← 有効化
    auth_fetch.peers[base] = ap

    headers = {"Content-Type": "application/json"}
    config = SimplifiedFetchRequestOptions(
        method="POST",
        headers=headers,
        body=b'{"message_type":"initialRequest","initial_nonce":"dGVzdF9ub25jZQ==","identity_key":"test_client_key"}'
    )
    
    # Configure requests to accept self-signed certificates
    original_request = requests.Session.request
    def patched_request(self, method, url, **kwargs):
        kwargs['verify'] = False
        return original_request(self, method, url, **kwargs)
    
    with patch.object(requests.Session, 'request', patched_request):
        with patch.object(requests.Session, 'post', lambda self, url, **kwargs: original_request(self, 'POST', url, **{**kwargs, 'verify': False})):
            print(f"[test] calling fetch to {base}/authfetch")
            resp = await asyncio.wait_for(
                asyncio.to_thread(auth_fetch.fetch, f"{base}/authfetch", config),
                timeout=10,
            )
    
    print(f"[test] got response: status={getattr(resp,'status_code',None)} text={getattr(resp,'text',None)}")
    assert resp is not None
    assert resp.status_code == 200
    data = json.loads(resp.text)
    assert data.get("message_type") == "initialResponse"
