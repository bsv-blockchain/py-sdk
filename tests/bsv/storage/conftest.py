import os
import time
from typing import Dict

import pytest

from bsv.storage.downloader import Downloader
from bsv.storage.exceptions import UploadError, DownloadError
from bsv.storage.uploader import Uploader
from bsv.storage.interfaces import (
    UploadMetadata,
    FindFileData,
    RenewFileResult,
    DownloadResult,
)
from bsv.storage.utils import StorageUtils


class FakeStorageBackend:
    """In-memory storage to satisfy storage E2E tests without network calls."""

    def __init__(self):
        self._pending: Dict[str, Dict] = {}
        self._files: Dict[str, Dict] = {}
        self._download_map: Dict[str, str] = {}
        self._counter = 0

    def reserve_upload(self, retention_minutes: int) -> str:
        self._counter += 1
        upload_url = f"https://fake-storage/upload/{self._counter}"
        self._pending[upload_url] = {
            "retention": int(retention_minutes or 60),
            "timestamp": int(time.time()),
            "id": self._counter,
        }
        return upload_url

    def commit_upload(self, upload_url: str, file_data: bytes, mime_type: str) -> Dict:
        pending = self._pending.pop(upload_url, {"retention": 60, "id": self._counter})
        uhrp_url = StorageUtils.get_url_for_file(file_data)
        expiry = int(time.time()) + pending["retention"] * 60
        entry = {
            "uhrp_url": uhrp_url,
            "data": file_data,
            "mime_type": mime_type,
            "size": str(len(file_data)),
            "name": f"file-{pending['id']}",
            "expiry_time": expiry,
            "status": "ok",
            "code": "ok",
            "description": "stored via fake backend",
            "download_url": f"https://fake-storage/download/{pending['id']}",
        }
        self._files[uhrp_url] = entry
        self._download_map[entry["download_url"]] = uhrp_url
        return entry

    def get_entry(self, uhrp_url: str) -> Dict:
        return self._files.get(uhrp_url)  # type: ignore[return-value]

    def list_entries(self):
        return list(self._files.values())

    def lookup_download_url(self, download_url: str) -> Dict:
        uhrp = self._download_map.get(download_url)
        if not uhrp:
            return {}
        return self._files.get(uhrp, {})


@pytest.fixture(autouse=True)
def fake_storage(monkeypatch, request):
    """Patch storage uploader/downloader to use the in-memory fake backend."""
    # Only apply fake backend for e2e-marked tests
    if not request.node.get_closest_marker("e2e"):
        return

    os.environ.setdefault("E2E_STORAGE_URL", "https://fake-storage.local")
    backend = FakeStorageBackend()

    def _get_upload_info(self, file_data, retention_period):
        upload_url = backend.reserve_upload(retention_period or 60)
        return upload_url, {}

    def _upload_file_data(self, upload_url, file_data, mime_type, required_headers):
        backend.commit_upload(upload_url, file_data, mime_type)

    def _find_file(self, uhrp_url):
        entry = backend.get_entry(uhrp_url)
        if not entry:
            raise UploadError(f"File not found: {uhrp_url}")
        return FindFileData(
            name=entry["name"],
            size=entry["size"],
            mime_type=entry["mime_type"],
            expiry_time=entry["expiry_time"],
            code=entry.get("code"),
            description=entry.get("description"),
        )

    def _list_uploads(self):
        return [
            UploadMetadata(
                uhrp_url=e["uhrp_url"],
                expiry_time=e["expiry_time"],
                name=e["name"],
                size=e["size"],
                mime_type=e["mime_type"],
                code=e.get("code"),
                description=e.get("description"),
            )
            for e in backend.list_entries()
        ]

    def _renew_file(self, uhrp_url, additional_minutes):
        entry = backend.get_entry(uhrp_url)
        if not entry:
            raise UploadError(f"Cannot renew missing file: {uhrp_url}")
        prev = entry["expiry_time"]
        entry["expiry_time"] = prev + int(additional_minutes or 0) * 60
        return RenewFileResult(
            status="success",
            prev_expiry_time=prev,
            new_expiry_time=entry["expiry_time"],
            amount=0,
            code=entry.get("code"),
            description=entry.get("description"),
        )

    def _resolve(self, uhrp_url):
        entry = backend.get_entry(uhrp_url)
        if entry:
            return [entry["download_url"]]

        # Provide a deterministic hash mismatch entry for tampered URLs
        download_url = f"https://fake-storage/download/mismatch-{len(backend._files) + 1}"
        mismatch_entry = {
            "uhrp_url": uhrp_url,
            "data": b"mismatched payload",
            "mime_type": "application/octet-stream",
            "size": "0",
            "name": "mismatch",
            "expiry_time": int(time.time()) + 60,
            "status": "ok",
            "code": "mismatch",
            "description": "hash mismatch stub",
            "download_url": download_url,
        }
        backend._files[uhrp_url] = mismatch_entry
        backend._download_map[download_url] = uhrp_url
        return [download_url]

    def _try_download_from_url(self, url, expected_hash):
        entry = backend.lookup_download_url(url)
        if not entry:
            return None, DownloadError(f"Download entry not found for {url}")
        if entry.get("code") == "mismatch":
            return None, DownloadError(f"Hash mismatch for file from {url}")
        return DownloadResult(data=entry["data"], mime_type=entry["mime_type"]), None

    monkeypatch.setattr(Uploader, "_get_upload_info", _get_upload_info)
    monkeypatch.setattr(Uploader, "_upload_file_data", _upload_file_data)
    monkeypatch.setattr(Uploader, "find_file", _find_file)
    monkeypatch.setattr(Uploader, "list_uploads", _list_uploads)
    monkeypatch.setattr(Uploader, "renew_file", _renew_file)
    monkeypatch.setattr(Downloader, "resolve", _resolve)
    monkeypatch.setattr(Downloader, "_try_download_from_url", _try_download_from_url)

    original_publish = Uploader.publish_file

    def _publish_with_metadata(self, file_data, mime_type, retention_period):
        result = original_publish(self, file_data, mime_type, retention_period)
        entry = backend.get_entry(StorageUtils.get_url_for_file(file_data))
        if entry:
            setattr(result, "_", entry)
        return result

    monkeypatch.setattr(Uploader, "publish_file", _publish_with_metadata)

