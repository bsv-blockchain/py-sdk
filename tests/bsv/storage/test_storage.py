import pytest
from bsv.storage.uploader import Uploader
from bsv.storage.downloader import Downloader
from bsv.storage.exceptions import UploadError, DownloadError, NetworkError, AuthError
from bsv.storage.interfaces import FindFileData, UploadMetadata, RenewFileResult

class DummyWallet:
    def get_public_key(self, ctx, args, originator):
        return {'public_key': 'dummy_pubkey'}
    def create_action(self, ctx, args, originator):
        return {'tx': b'dummy_tx_bytes'}

@pytest.fixture
def uploader():
    return Uploader(storage_url='http://dummy-storage', wallet=DummyWallet())

@pytest.fixture
def downloader():
    return Downloader(network='mainnet')

def test_publish_file_network_error(uploader, monkeypatch):
    def fail_post(*a, **kw):
        raise Exception('network fail')
    monkeypatch.setattr('requests.post', fail_post)
    with pytest.raises(NetworkError):
        uploader.publish_file(b'data', 'application/octet-stream', 60)

def test_download_no_host(downloader, monkeypatch):
    monkeypatch.setattr(downloader, 'resolve', lambda u: [])
    with pytest.raises(DownloadError):
        downloader.download('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e')

def test_download_network_error(downloader, monkeypatch):
    monkeypatch.setattr(downloader, 'resolve', lambda u: ['http://dummy-url'])
    def fail_get(*a, **kw):
        import requests
        raise requests.RequestException('network fail')
    monkeypatch.setattr('requests.get', fail_get)
    with pytest.raises(NetworkError):
        downloader.download('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e')

def test_publish_file_upload_error(uploader, monkeypatch):
    # Force AuthFetch to use HTTP fallback by patching the fetch method
    original_fetch = uploader.auth_fetch.fetch
    def mock_fetch(ctx, url_str, config):
        # Force HTTP fallback by calling handle_fetch_and_validate directly
        from urllib.parse import urlparse
        parsed_url = urlparse(url_str)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        if base_url not in uploader.auth_fetch.peers:
            from bsv.auth.clients.auth_fetch import AuthPeer
            from bsv.auth.peer import Peer, PeerOptions
            from bsv.auth.transports.simplified_http_transport import SimplifiedHTTPTransport
            transport = SimplifiedHTTPTransport(base_url)
            peer = Peer(PeerOptions(
                wallet=uploader.auth_fetch.wallet,
                transport=transport,
                certificates_to_request=uploader.auth_fetch.requested_certificates,
                session_manager=uploader.auth_fetch.session_manager
            ))
            auth_peer = AuthPeer()
            auth_peer.peer = peer
            auth_peer.supports_mutual_auth = False
            uploader.auth_fetch.peers[base_url] = auth_peer
        else:
            uploader.auth_fetch.peers[base_url].supports_mutual_auth = False
        return uploader.auth_fetch.handle_fetch_and_validate(url_str, config, uploader.auth_fetch.peers[base_url])
    
    monkeypatch.setattr(uploader.auth_fetch, 'fetch', mock_fetch)
    
    class DummyResp:
        ok = False
        status_code = 500
        headers = {}
        def json(self):
            return {"status": "error"}
    monkeypatch.setattr('requests.post', lambda *a, **kw: DummyResp())
    monkeypatch.setattr('requests.request', lambda *a, **kw: DummyResp())
    with pytest.raises(NetworkError):  # HTTPError gets wrapped as NetworkError
        uploader.publish_file(b'data', 'application/octet-stream', 60)

def test_publish_file_402_payment(uploader, monkeypatch):
    # Force AuthFetch to use HTTP fallback by patching the fetch method
    original_fetch = uploader.auth_fetch.fetch
    def mock_fetch(ctx, url_str, config):
        # Force HTTP fallback by calling handle_fetch_and_validate directly
        from urllib.parse import urlparse
        parsed_url = urlparse(url_str)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        if base_url not in uploader.auth_fetch.peers:
            from bsv.auth.clients.auth_fetch import AuthPeer
            from bsv.auth.peer import Peer, PeerOptions
            from bsv.auth.transports.simplified_http_transport import SimplifiedHTTPTransport
            transport = SimplifiedHTTPTransport(base_url)
            peer = Peer(PeerOptions(
                wallet=uploader.auth_fetch.wallet,
                transport=transport,
                certificates_to_request=uploader.auth_fetch.requested_certificates,
                session_manager=uploader.auth_fetch.session_manager
            ))
            auth_peer = AuthPeer()
            auth_peer.peer = peer
            auth_peer.supports_mutual_auth = False
            uploader.auth_fetch.peers[base_url] = auth_peer
        else:
            uploader.auth_fetch.peers[base_url].supports_mutual_auth = False
        resp = uploader.auth_fetch.handle_fetch_and_validate(url_str, config, uploader.auth_fetch.peers[base_url])
        if getattr(resp, 'status_code', None) == 402:
            return uploader.auth_fetch.handle_payment_and_retry(ctx, url_str, config, resp)
        return resp
    
    monkeypatch.setattr(uploader.auth_fetch, 'fetch', mock_fetch)
    
    class DummyResp402:
        ok = False
        status_code = 402
        headers = {
            'x-bsv-payment-version': '1.0',
            'x-bsv-payment-satoshis-required': '1000',
            'x-bsv-auth-identity-key': 'server_key',
            'x-bsv-payment-derivation-prefix': 'prefix',
        }
        def json(self):
            return {"status": "error"}
    class DummyRespOK:
        ok = True
        status_code = 200
        headers = {}
        def json(self):
            return {"status": "success", "uploadURL": "http://dummy-upload", "requiredHeaders": {}}
    called = {}
    def fake_post(url, *a, **kw):
        if not called.get('first'):
            called['first'] = True
            return DummyResp402()
        return DummyRespOK()
    monkeypatch.setattr('requests.post', fake_post)
    monkeypatch.setattr('requests.request', fake_post)
    monkeypatch.setattr('requests.put', lambda *a, **kw: DummyRespOK())
    result = uploader.publish_file(b'data', 'application/octet-stream', 60)
    assert result.published
    # UHRP URL is generated from file data, not from uploadURL
    assert result.uhrp_url.startswith("uhrp://")

def test_publish_file_auth_error(monkeypatch):
    class BadWallet:
        def get_public_key(self, *a, **kw):
            raise Exception('fail')
    uploader = Uploader(storage_url='http://dummy-storage', wallet=BadWallet())
    
    # Force AuthFetch to use HTTP fallback by patching the fetch method
    original_fetch = uploader.auth_fetch.fetch
    def mock_fetch(ctx, url_str, config):
        # Force HTTP fallback by calling handle_fetch_and_validate directly
        from urllib.parse import urlparse
        parsed_url = urlparse(url_str)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        if base_url not in uploader.auth_fetch.peers:
            from bsv.auth.clients.auth_fetch import AuthPeer
            from bsv.auth.peer import Peer, PeerOptions
            from bsv.auth.transports.simplified_http_transport import SimplifiedHTTPTransport
            transport = SimplifiedHTTPTransport(base_url)
            peer = Peer(PeerOptions(
                wallet=uploader.auth_fetch.wallet,
                transport=transport,
                certificates_to_request=uploader.auth_fetch.requested_certificates,
                session_manager=uploader.auth_fetch.session_manager
            ))
            auth_peer = AuthPeer()
            auth_peer.peer = peer
            auth_peer.supports_mutual_auth = False
            uploader.auth_fetch.peers[base_url] = auth_peer
        else:
            uploader.auth_fetch.peers[base_url].supports_mutual_auth = False
        return uploader.auth_fetch.handle_fetch_and_validate(url_str, config, uploader.auth_fetch.peers[base_url])
    
    monkeypatch.setattr(uploader.auth_fetch, 'fetch', mock_fetch)
    
    # Mock requests.request to simulate auth error
    class DummyAuthErrorResp:
        ok = False
        status_code = 401
        headers = {}
        def json(self):
            return {"status": "unauthorized"}
    monkeypatch.setattr('requests.request', lambda *a, **kw: DummyAuthErrorResp())
    
    with pytest.raises(NetworkError):  # BadWallet exception gets wrapped as NetworkError
        uploader.publish_file(b'data', 'application/octet-stream', 60)

def test_find_file_success(uploader, monkeypatch):
    class DummyResp:
        ok = True
        status_code = 200
        def json(self):
            return {"status": "success", "data": {"name": "file.txt", "size": "123", "mimeType": "text/plain", "expiryTime": 9999}}
    monkeypatch.setattr(uploader.auth_fetch, 'fetch', lambda *a, **kw: DummyResp())
    result = uploader.find_file('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e')
    assert isinstance(result, FindFileData)
    assert result.name == "file.txt"
    assert result.size == "123"
    assert result.mime_type == "text/plain"
    assert result.expiry_time == 9999

def test_find_file_error(uploader, monkeypatch):
    class DummyResp:
        ok = True
        status_code = 200
        def json(self):
            return {"status": "error", "code": "notfound", "description": "not found"}
    monkeypatch.setattr(uploader.auth_fetch, 'fetch', lambda *a, **kw: DummyResp())
    import pytest
    with pytest.raises(UploadError):
        uploader.find_file('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e')

def test_list_uploads_success(uploader, monkeypatch):
    class DummyResp:
        ok = True
        status_code = 200
        def json(self):
            return {"status": "success", "uploads": [
                {"uhrpUrl": "uhrp://XUUJuMCC2qDVeZtq2yJKg4z5ztfdoSCmKE3BF6BconmUjpoPMoNh", "expiryTime": 123, "name": "file1", "size": "10", "mimeType": "text/plain"},
                {"uhrpUrl": "uhrp://XUUSQj8rmVor3DrPVs9TJUutuDRnXbpurZd3GvAtyExkCJsb3J58", "expiryTime": 456, "name": "file2", "size": "20", "mimeType": "image/png"}
            ]}
    monkeypatch.setattr(uploader.auth_fetch, 'fetch', lambda *a, **kw: DummyResp())
    uploads = uploader.list_uploads()
    assert isinstance(uploads, list)
    assert all(isinstance(u, UploadMetadata) for u in uploads)
    assert uploads[0].uhrp_url == "uhrp://XUUJuMCC2qDVeZtq2yJKg4z5ztfdoSCmKE3BF6BconmUjpoPMoNh"
    assert uploads[0].name == "file1"
    assert uploads[1].mime_type == "image/png"

def test_list_uploads_error(uploader, monkeypatch):
    class DummyResp:
        ok = True
        status_code = 200
        def json(self):
            return {"status": "error", "code": "fail", "description": "fail"}
    monkeypatch.setattr(uploader.auth_fetch, 'fetch', lambda *a, **kw: DummyResp())
    import pytest
    with pytest.raises(UploadError):
        uploader.list_uploads()

def test_renew_file_success(uploader, monkeypatch):
    class DummyResp:
        ok = True
        status_code = 200
        def json(self):
            return {"status": "success", "prevExpiryTime": 1, "newExpiryTime": 2, "amount": 3}
    monkeypatch.setattr(uploader.auth_fetch, 'fetch', lambda *a, **kw: DummyResp())
    result = uploader.renew_file('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e', 10)
    assert isinstance(result, RenewFileResult)
    assert result.status == "success"
    assert result.prev_expiry_time == 1
    assert result.new_expiry_time == 2
    assert result.amount == 3

def test_renew_file_error(uploader, monkeypatch):
    class DummyResp:
        ok = True
        status_code = 200
        def json(self):
            return {"status": "error", "code": "fail", "description": "fail"}
    monkeypatch.setattr(uploader.auth_fetch, 'fetch', lambda *a, **kw: DummyResp())
    import pytest
    with pytest.raises(UploadError):
        uploader.renew_file('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e', 10)

def test_downloader_hash_mismatch(downloader, monkeypatch):
    # Patch resolve to return a URL, and requests.get to return wrong data
    monkeypatch.setattr(downloader, 'resolve', lambda u: ['http://dummy-url'])
    class DummyResp:
        status_code = 200
        ok = True
        content = b'not the right data'
        headers = {'Content-Type': 'text/plain'}
    monkeypatch.setattr('requests.get', lambda *a, **kw: DummyResp())
    import pytest
    # The hash will not match, so DownloadError should be raised
    with pytest.raises(DownloadError):
        downloader.download('uhrp://XUTGszj56w85kJ3RkyWF76myV5FLZZPZvPg8tEr2mpnuadpwB9qE')  # proper UHRP encoded hash (mockhash)

def test_downloader_download_error(downloader, monkeypatch):
    # Patch resolve to return a URL, and requests.get to return error
    monkeypatch.setattr(downloader, 'resolve', lambda u: ['http://dummy-url'])
    class DummyResp:
        status_code = 500
        ok = False
        content = b''
        headers = {'Content-Type': 'text/plain'}
    monkeypatch.setattr('requests.get', lambda *a, **kw: DummyResp())
    import pytest
    with pytest.raises(DownloadError):
        downloader.download('uhrp://XUTGszj56w85kJ3RkyWF76myV5FLZZPZvPg8tEr2mpnuadpwB9qE')
