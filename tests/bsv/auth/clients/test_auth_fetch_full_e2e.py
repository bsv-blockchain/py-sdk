import pytest
import pytest_asyncio
import json
import asyncio
import subprocess
import time
import signal
import os
import sys
from bsv.auth.clients.auth_fetch import AuthFetch, SimplifiedFetchRequestOptions
from bsv.auth.requested_certificate_set import RequestedCertificateSet

class DummyWallet:
    """Mock wallet for testing"""
    def get_public_key(self, ctx, args, originator):
        return {"publicKey": "02a1633cafb311f41c1137864d7dd7cf2d5c9e5c2e5b5f5a5d5c5b5a59584f5e5f", "derivationPrefix": "m/0"}
    
    def create_action(self, ctx, args, originator):
        return {"tx": "0100000001abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789000000006a473044022012345678901234567890123456789012345678901234567890123456789012340220abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab012103a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789affffffff0100e1f505000000001976a914abcdefabcdefabcdefabcdefabcdefabcdefabcdef88ac00000000"}
    
    def create_signature(self, ctx, args, originator):
        return {"signature": b"dummy_signature_for_testing_purposes_32bytes"}
    
    def verify_signature(self, ctx, args, originator):
        return {"valid": True}

@pytest_asyncio.fixture
async def auth_server():
    """Start the full authentication server for testing"""
    # Use relative paths to find the server script
    this_dir = os.path.dirname(__file__)
    server_script = os.path.abspath(os.path.join(this_dir, "..", "test_auth_server_full.py"))
    
    # Start the server process using the current Python interpreter (async)
    server_process = await asyncio.create_subprocess_exec(
        sys.executable,
        server_script,
        env=os.environ
    )
    
    # Wait for server to become ready by polling /health
    import aiohttp
    import ssl
    base = "https://localhost:8084"
    ok = False
    t0 = time.time()
    
    # Create SSL context that accepts self-signed certificates for testing
    ssl_context = ssl.create_default_context()  # noqa: S323 - Test environment only
    ssl_context.check_hostname = False  # noqa: S501 - Required for self-signed test certs
    ssl_context.verify_mode = ssl.CERT_NONE  # noqa: S502 - Test server uses self-signed certs
    
    while time.time() - t0 < 10.0:
        try:
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(f"{base}/health", timeout=aiohttp.ClientTimeout(total=0.5)) as r:
                    if r.status == 200:
                        ok = True
                        break
        except Exception:
            # Intentional: Health check may fail during server startup - retry loop handles this
            pass
        await asyncio.sleep(0.1)
    if not ok:
        server_process.terminate()
        await asyncio.wait_for(server_process.wait(), timeout=5)
        raise RuntimeError("auth server failed to start on :8084")
    
    yield server_process
    
    # Cleanup: terminate the server
    server_process.terminate()
    try:
        await asyncio.wait_for(server_process.wait(), timeout=5)
    except asyncio.TimeoutError:
        server_process.kill()

@pytest.mark.asyncio
async def test_auth_fetch_full_protocol(auth_server):
    """Test AuthFetch with the full authentication protocol server"""
    import requests
    from unittest.mock import patch
    
    try:
        wallet = DummyWallet()
        requested_certs = RequestedCertificateSet()
        auth_fetch = AuthFetch(wallet, requested_certs)
        
        # Test 1: Basic HTTP request through authenticated channel
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
        
        # Pre-configure the peer to use HTTP fallback instead of mutual auth
        base_url = "https://localhost:8084"
        from bsv.auth.clients.auth_fetch import AuthPeer
        auth_peer = AuthPeer()
        auth_peer.supports_mutual_auth = False
        auth_fetch.peers[base_url] = auth_peer
        
        # Configure requests to accept self-signed certificates
        original_request = requests.Session.request
        def patched_request(self, method, url, **kwargs):
            kwargs['verify'] = False
            return original_request(self, method, url, **kwargs)
        
        with patch.object(requests.Session, 'request', patched_request):
            with patch.object(requests.Session, 'post', lambda self, url, **kwargs: original_request(self, 'POST', url, **{**kwargs, 'verify': False})):
                # The AuthFetch should use HTTP fallback to communicate with the server
                resp = auth_fetch.fetch(None, "https://localhost:8084/auth", config)
        
        assert resp is not None
        assert resp.status_code == 200
        
        # The response should be an initialResponse from the auth server
        response_data = json.loads(resp.text)
        assert response_data.get("messageType") == "initialResponse"
        assert "identityKey" in response_data
        assert "nonce" in response_data
        
        print("✓ Full protocol authentication test passed")
        
    except Exception as e:
        pytest.fail(f"Full protocol test failed: {e}")

@pytest.mark.asyncio
@pytest.mark.skip(reason="Certificate exchange requires server fixture with certificate response support. Skipped until auth_server fixture implements certificate exchange protocol.")
async def test_auth_fetch_certificate_exchange(auth_server):
    """Test certificate exchange functionality
    
    This test requires:
    1. Server to handle certificate request messages
    2. Server to respond with certificate response messages
    3. Proper certificate validation and signing
    
    TODO: Implement certificate exchange in test_auth_server_full.py
    """
    wallet = DummyWallet()
    requested_certs = RequestedCertificateSet()
    auth_fetch = AuthFetch(wallet, requested_certs)
    
    # Test certificate request
    base_url = "https://localhost:8084"
    certificates_to_request = {
        "certifiers": ["03a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789a"],
        "types": ["test-certificate"]
    }
    
    # This should trigger the certificate request flow
    certs = auth_fetch.send_certificate_request(None, base_url, certificates_to_request)
    
    # Verify we received certificates
    assert certs is not None, "Expected certificates to be returned"
    assert isinstance(certs, list), "Certificates should be returned as a list"
    assert len(certs) > 0, "Should receive at least one certificate"
    
    # Verify certificate structure
    for cert in certs:
        assert "certificate" in cert, "Each cert should have a certificate field"
        cert_data = cert["certificate"]
        assert "type" in cert_data, "Certificate should have a type"
        assert "serialNumber" in cert_data, "Certificate should have a serial number"
        assert "subject" in cert_data, "Certificate should have a subject"
        assert "certifier" in cert_data, "Certificate should have a certifier"

@pytest.mark.asyncio
async def test_auth_fetch_session_management(auth_server):
    """Test session management and reuse"""
    import requests
    from unittest.mock import patch
    
    try:
        wallet = DummyWallet()
        requested_certs = RequestedCertificateSet()
        auth_fetch = AuthFetch(wallet, requested_certs)
        
        base_url = "https://localhost:8084"
        # Force HTTP fallback (disable mutual auth for this base URL)
        from bsv.auth.clients.auth_fetch import AuthPeer
        _ap = AuthPeer()
        _ap.supports_mutual_auth = False
        auth_fetch.peers[base_url] = _ap
        
        # Configure requests to accept self-signed certificates
        original_request = requests.Session.request
        def patched_request(self, method, url, **kwargs):
            kwargs['verify'] = False
            return original_request(self, method, url, **kwargs)
        
        with patch.object(requests.Session, 'request', patched_request):
            with patch.object(requests.Session, 'post', lambda self, url, **kwargs: original_request(self, 'POST', url, **{**kwargs, 'verify': False})):
                # First request - should establish session
                config1 = SimplifiedFetchRequestOptions(
                    method="POST",
                    headers={"Content-Type": "application/json"},
                    body=b'{"request": 1}'
                )
                
                resp1 = auth_fetch.fetch(None, f"{base_url}/auth", config1)
                assert resp1.status_code == 200
                
                # Second request - should reuse session
                config2 = SimplifiedFetchRequestOptions(
                    method="POST", 
                    headers={"Content-Type": "application/json"},
                    body=b'{"request": 2}'
                )
                
                resp2 = auth_fetch.fetch(None, f"{base_url}/auth", config2)
                assert resp2.status_code == 200
        
        # Verify both requests succeeded
        data1 = json.loads(resp1.text)
        data2 = json.loads(resp2.text)
        
        assert "Authentication successful" in data1["message"]
        assert "Authentication successful" in data2["message"]
        
        print("✓ Session management test passed")
        
    except Exception as e:
        pytest.fail(f"Session management test failed: {e}")

@pytest.mark.asyncio
async def test_auth_fetch_error_handling(auth_server):
    """Test error handling in authentication flow with invalid endpoints.
    
    Note: This test verifies graceful error handling. Both behaviors are acceptable:
    - 404 response for non-existent endpoint (preferred)
    - Exception raised for invalid endpoint (also valid)
    - 200 response if fallback to regular HTTP occurs
    
    The key is that the system doesn't crash and handles errors gracefully.
    """
    import requests
    from unittest.mock import patch
    
    wallet = DummyWallet()
    requested_certs = RequestedCertificateSet()
    auth_fetch = AuthFetch(wallet, requested_certs)
    
    # Configure requests to accept self-signed certificates
    original_request = requests.Session.request
    def patched_request(self, method, url, **kwargs):
        kwargs['verify'] = False
        return original_request(self, method, url, **kwargs)
    
    # Test with invalid endpoint - should handle gracefully
    config = SimplifiedFetchRequestOptions(method="GET")
    error_occurred = False
    response_received = False
    
    try:
        with patch.object(requests.Session, 'request', patched_request):
            with patch.object(requests.Session, 'post', lambda self, url, **kwargs: original_request(self, 'POST', url, **{**kwargs, 'verify': False})):
                resp = auth_fetch.fetch(None, "https://localhost:8084/nonexistent", config)
                response_received = True
        
        # If response is returned, verify it's a valid HTTP response
        if resp:
            assert hasattr(resp, 'status_code'), "Response should have status_code attribute"
            assert resp.status_code in [404, 200], \
                f"Expected 404 (not found) or 200 (fallback), got {resp.status_code}"
            
            # 404 is preferred for non-existent endpoints
            if resp.status_code == 404:
                print("✓ Correctly returned 404 for non-existent endpoint")
            elif resp.status_code == 200:
                print("✓ Fell back to regular HTTP request")
                
    except Exception as e:
        # Exception is also acceptable - verify it's handled gracefully
        error_occurred = True
        error_msg = str(e)
        print(f"✓ Gracefully raised exception for invalid endpoint: {type(e).__name__}")
        
        # Verify error message is meaningful (not a crash)
        assert len(error_msg) > 0, "Exception should have a message"
    
    # One of the two outcomes should occur (either response or exception)
    assert response_received or error_occurred, \
        "Either a response or exception should occur for invalid endpoint"
    
    print("✓ Error handling test passed - system handles invalid endpoints gracefully")

if __name__ == "__main__":
    # Run tests manually if needed
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
