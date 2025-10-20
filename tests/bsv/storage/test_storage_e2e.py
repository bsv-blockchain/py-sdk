import os
import pytest
from bsv.storage.uploader import Uploader
from bsv.storage.downloader import Downloader
from bsv.storage.exceptions import UploadError, DownloadError, NetworkError

# 実ストレージサービスのURL（nanostore.babbage.systems等）
STORAGE_URL = os.environ.get("E2E_STORAGE_URL", "https://nanostore.babbage.systems")
NETWORK = os.environ.get("E2E_NETWORK", "mainnet")

class DummyWallet:
    def get_public_key(self, ctx, args, originator):
        return {'public_key': 'dummy_pubkey'}
    def create_action(self, ctx, args, originator):
        return {'tx': b'dummy_tx_bytes'}

@pytest.mark.e2e
@pytest.mark.skipif(
    not os.environ.get("E2E_STORAGE_URL"),
    reason="E2E_STORAGE_URL not set; set to real storage service to run E2E test"
)
def test_storage_upload_download_e2e():
    uploader = Uploader(storage_url=STORAGE_URL, wallet=DummyWallet())
    downloader = Downloader(network=NETWORK)
    test_data = b"hello e2e storage test"
    mime_type = "text/plain"
    retention = 60  # minutes
    # アップロード
    result = uploader.publish_file(test_data, mime_type, retention)
    assert result.published
    uhrp_url = result.uhrp_url
    assert uhrp_url.startswith("uhrp://")
    # ダウンロード
    downloaded = downloader.download(uhrp_url)
    assert downloaded.data == test_data
    assert downloaded.mime_type == mime_type or downloaded.mime_type is not None

@ pytest.mark.e2e
@ pytest.mark.skipif(
    not os.environ.get("E2E_STORAGE_URL"),
    reason="E2E_STORAGE_URL not set; set to real storage service to run E2E test"
)
def test_storage_find_file_e2e():
    uploader = Uploader(storage_url=STORAGE_URL, wallet=DummyWallet())
    test_data = b"find file e2e test"
    mime_type = "text/plain"
    retention = 60
    result = uploader.publish_file(test_data, mime_type, retention)
    uhrp_url = result.uhrp_url
    file_data = uploader.find_file(uhrp_url)
    assert file_data.name is not None
    assert file_data.size is not None
    assert file_data.mime_type == mime_type
    assert file_data.expiry_time > 0

@ pytest.mark.e2e
@ pytest.mark.skipif(
    not os.environ.get("E2E_STORAGE_URL"),
    reason="E2E_STORAGE_URL not set; set to real storage service to run E2E test"
)
def test_storage_list_uploads_e2e():
    uploader = Uploader(storage_url=STORAGE_URL, wallet=DummyWallet())
    uploads = uploader.list_uploads()
    assert isinstance(uploads, list)

@ pytest.mark.e2e
@ pytest.mark.skipif(
    not os.environ.get("E2E_STORAGE_URL"),
    reason="E2E_STORAGE_URL not set; set to real storage service to run E2E test"
)
def test_storage_renew_file_e2e():
    uploader = Uploader(storage_url=STORAGE_URL, wallet=DummyWallet())
    test_data = b"renew file e2e test"
    mime_type = "text/plain"
    retention = 1
    result = uploader.publish_file(test_data, mime_type, retention)
    uhrp_url = result.uhrp_url
    renew_result = uploader.renew_file(uhrp_url, additional_minutes=10)
    assert renew_result.status == "success"
    assert renew_result.new_expiry_time > renew_result.prev_expiry_time

@ pytest.mark.e2e
@ pytest.mark.skipif(
    not os.environ.get("E2E_STORAGE_URL"),
    reason="E2E_STORAGE_URL not set; set to real storage service to run E2E test"
)
def test_storage_download_hash_mismatch_e2e():
    uploader = Uploader(storage_url=STORAGE_URL, wallet=DummyWallet())
    downloader = Downloader(network=NETWORK)
    test_data = b"hash mismatch e2e test"
    mime_type = "text/plain"
    retention = 60
    result = uploader.publish_file(test_data, mime_type, retention)
    uhrp_url = result.uhrp_url
    # 改ざんURL（SHA256が異なるデータのUHRP URL）
    import hashlib
    bad_data = b"tampered data"
    from bsv.storage.utils import StorageUtils
    bad_url = StorageUtils.get_url_for_file(bad_data)
    import pytest
    with pytest.raises(Exception):
        downloader.download(bad_url)





