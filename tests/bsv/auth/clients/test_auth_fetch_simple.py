import pytest
import os
import sys
import time
import subprocess
import requests
import json
from bsv.auth.clients.auth_fetch import AuthFetch, SimplifiedFetchRequestOptions, AuthPeer
from bsv.auth.requested_certificate_set import RequestedCertificateSet

class DummyWallet:
    """Mock wallet for testing"""
    def get_public_key(self, ctx, args, originator):
        return {"publicKey": "02a1633cafb311f41c1137864d7dd7cf2d5c9e5c2e5b5f5a5d5c5b5a59584f5e5f", "derivationPrefix": "m/0"}
    
    def create_action(self, ctx, args, originator):
        return {"tx": "0100000001abcdef..."}
    
    def create_signature(self, ctx, args, originator):
        return {"signature": b"dummy_signature"}
    
    def verify_signature(self, ctx, args, originator):
        return {"valid": True}

@pytest.fixture(scope="module")
def auth_full_server():
    # Launch using relative paths
    this_dir = os.path.dirname(__file__)
    server_script = os.path.abspath(os.path.join(this_dir, "..", "test_auth_server_full.py"))
    # Inherit current environment (keeps parent PYTHONPATH)
    p = subprocess.Popen([
        sys.executable,
        server_script,
    ], env=os.environ)
    base = "http://localhost:8084"
    ok = False
    start = time.time()
    while time.time() - start < 10.0:
        try:
            r = requests.get(f"{base}/health", timeout=0.5)
            if r.status_code == 200:
                ok = True
                break
        except Exception:
            pass
        time.sleep(0.1)
    if not ok:
        p.terminate()
        raise RuntimeError("auth server failed to start on :8084")
    try:
        yield p
    finally:
        try:
            p.terminate()
            p.wait(timeout=5)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass

def test_auth_fetch_fallback_to_http(auth_full_server):
    """Test AuthFetch fallback to regular HTTP when mutual auth is disabled"""
    try:
        wallet = DummyWallet()
        requested_certs = RequestedCertificateSet()
        auth_fetch = AuthFetch(wallet, requested_certs)
        
        # Pre-configure the peer to NOT support mutual auth
        base_url = "http://localhost:8084"
        auth_peer = AuthPeer()
        auth_peer.supports_mutual_auth = False
        auth_fetch.peers[base_url] = auth_peer
        
        # Test with health endpoint (should work with regular HTTP)
        config = SimplifiedFetchRequestOptions(method="GET")
        resp = auth_fetch.fetch(None, "http://localhost:8084/health", config)
        
        assert resp is not None
        assert resp.status_code == 200
        assert "BSV Auth Server is running" in resp.text
        
        print("✓ HTTP fallback test passed")
        
    except Exception as e:
        pytest.fail(f"HTTP fallback test failed: {e}")

def test_auth_fetch_json_post(auth_full_server):
    """Test AuthFetch with JSON POST to auth endpoint using HTTP fallback"""
    try:
        wallet = DummyWallet()
        requested_certs = RequestedCertificateSet()
        auth_fetch = AuthFetch(wallet, requested_certs)
        
        # Pre-configure the peer to NOT support mutual auth
        base_url = "http://localhost:8084"
        auth_peer = AuthPeer()
        auth_peer.supports_mutual_auth = False
        auth_fetch.peers[base_url] = auth_peer
        
        # Test with auth endpoint using initialRequest message
        config = SimplifiedFetchRequestOptions(
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps({
                "version": "0.1",
                "messageType": "initialRequest",
                "identityKey": "02a1633cafb311f41c1137864d7dd7cf2d5c9e5c2e5b5f5a5d5c5b5a59584f5e5f",
                "nonce": "dGVzdF9ub25jZV8zMmJ5dGVzX2Zvcl90ZXN0aW5nXzEyMzQ="
            }).encode()
        )
        
        resp = auth_fetch.fetch(None, "http://localhost:8084/auth", config)
        
        assert resp is not None
        assert resp.status_code == 200
        
        # Parse response
        response_data = json.loads(resp.text)
        assert response_data.get("messageType") == "initialResponse"
        assert "identityKey" in response_data
        assert "nonce" in response_data
        
        print("✓ JSON POST test passed")
        
    except Exception as e:
        pytest.fail(f"JSON POST test failed: {e}")

if __name__ == "__main__":
    test_auth_fetch_fallback_to_http()
    test_auth_fetch_json_post()
    print("All simple tests passed!")
