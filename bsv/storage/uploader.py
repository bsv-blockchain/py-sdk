import base64
from typing import Any, Dict, Optional, List
import time
from .interfaces import StorageUploaderInterface, UploadFileResult, FindFileData, RenewFileResult, UploadMetadata
from .exceptions import UploadError, AuthError, NetworkError
from .utils import StorageUtils
from bsv.auth.clients.auth_fetch import AuthFetch, SimplifiedFetchRequestOptions

_JSON_MIME = "application/json"

class Uploader(StorageUploaderInterface):
    """
    Uploader provides methods to upload files, query metadata, list uploads, and renew file retention
    using a storage service compatible with UHRP URLs. All requests are authenticated via AuthFetch.
    Supports configurable timeout and retry logic for robust error handling.
    """
    def __init__(self, storage_url: str, wallet: object, timeout: float = 30.0, max_retries: int = 3, retry_delay: float = 1.0) -> None:
        """
        :param storage_url: Base URL of the storage service
        :param wallet: Wallet object for authentication and signing
        :param timeout: Timeout in seconds for each HTTP request
        :param max_retries: Maximum number of retries for each request
        :param retry_delay: Delay in seconds between retries
        """
        self.base_url = storage_url
        self.wallet = wallet
        self.auth_fetch = AuthFetch(wallet, requested_certs=None)
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay

    def _fetch_with_retry(self, fetch_func, *args, **kwargs):
        last_err = None
        for attempt in range(1, self.max_retries + 1):
            try:
                return fetch_func(*args, **kwargs)
            except (NetworkError, UploadError) as e:
                last_err = e
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
        if last_err:
            raise last_err
        raise UploadError(f"Request failed after {self.max_retries} retries.")

    def publish_file(self, file_data: bytes, mime_type: str, retention_period: int) -> UploadFileResult:
        """
        Upload a file to the storage service with retry and timeout logic.
        """
        def do_publish():
            url = f"{self.base_url}/upload"
            body = {"fileSize": len(file_data), "retentionPeriod": retention_period}
            options = SimplifiedFetchRequestOptions(
                method="POST",
                headers={"Content-Type": _JSON_MIME},
                body=None
            )
            import json
            options.body = json.dumps(body).encode()
            try:
                resp = self.auth_fetch.fetch(None, url, options)
            except Exception as e:
                raise NetworkError(f"Network error during upload info request: {e}")
            if hasattr(resp, 'status_code') and resp.status_code == 402:
                try:
                    resp = self.auth_fetch.handle_payment_and_retry(None, url, options, resp)
                except Exception as e:
                    raise UploadError(f"Payment flow failed: {e}")
            if not hasattr(resp, 'ok') or not resp.ok:
                code = getattr(resp, 'status_code', 'unknown')
                raise UploadError(f"Upload info request failed: HTTP {code}")
            data = resp.json()
            if data.get("status") == "error":
                raise UploadError("Upload route returned an error.")
            upload_url = data["uploadURL"]
            required_headers = data.get("requiredHeaders", {})
            put_headers = {"Content-Type": mime_type, **required_headers}
            put_options = SimplifiedFetchRequestOptions(
                method="PUT",
                headers=put_headers,
                body=file_data
            )
            try:
                put_resp = self.auth_fetch.fetch(None, upload_url, put_options)
            except Exception as e:
                raise NetworkError(f"Network error during file upload: {e}")
            if not hasattr(put_resp, 'ok') or not put_resp.ok:
                code = getattr(put_resp, 'status_code', 'unknown')
                raise UploadError(f"File upload failed: HTTP {code}")
            uhrp_url = StorageUtils.get_url_for_file(file_data)
            return UploadFileResult(uhrp_url=uhrp_url, published=True)
        return self._fetch_with_retry(do_publish)

    def find_file(self, uhrp_url: str) -> FindFileData:
        """
        Retrieve metadata for a file by its UHRP URL with retry and timeout logic.
        """
        def do_find():
            url = f"{self.base_url}/find"
            import urllib.parse
            params = {"uhrpUrl": uhrp_url}
            url_with_params = f"{url}?{urllib.parse.urlencode(params)}"
            options = SimplifiedFetchRequestOptions(method="GET")
            try:
                resp = self.auth_fetch.fetch(None, url_with_params, options)
            except Exception as e:
                raise NetworkError(f"Network error during findFile: {e}")
            if not hasattr(resp, 'ok') or not resp.ok:
                code = getattr(resp, 'status_code', 'unknown')
                raise UploadError(f"findFile request failed: HTTP {code}")
            data = resp.json()
            code_val = data.get("code")
            desc_val = data.get("description")
            if data.get("status") == "error":
                err_code = code_val or "unknown-code"
                err_desc = desc_val or "no-description"
                raise UploadError(f"findFile returned an error: {err_code} - {err_desc}")
            d = data["data"]
            return FindFileData(
                name=d.get("name", ""),
                size=d.get("size", ""),
                mime_type=d.get("mimeType", ""),
                expiry_time=d.get("expiryTime", 0),
                code=code_val,
                description=desc_val
            )
        return self._fetch_with_retry(do_find)

    def list_uploads(self) -> List[UploadMetadata]:
        """
        List all uploads for the authenticated user with retry and timeout logic.
        """
        def do_list():
            url = f"{self.base_url}/list"
            options = SimplifiedFetchRequestOptions(method="GET")
            try:
                resp = self.auth_fetch.fetch(None, url, options)
            except Exception as e:
                raise NetworkError(f"Network error during listUploads: {e}")
            if not hasattr(resp, 'ok') or not resp.ok:
                code = getattr(resp, 'status_code', 'unknown')
                raise UploadError(f"listUploads request failed: HTTP {code}")
            data = resp.json()
            code_val = data.get("code")
            desc_val = data.get("description")
            if data.get("status") == "error":
                err_code = code_val or "unknown-code"
                err_desc = desc_val or "no-description"
                raise UploadError(f"listUploads returned an error: {err_code} - {err_desc}")
            uploads = data.get("uploads", [])
            return [
                UploadMetadata(
                    uhrp_url=u.get("uhrpUrl", u.get("uhrp_url", "")),
                    expiry_time=u.get("expiryTime", 0),
                    name=u.get("name"),
                    size=u.get("size"),
                    mime_type=u.get("mimeType"),
                    code=u.get("code", code_val),
                    description=u.get("description", desc_val)
                ) for u in uploads
            ]
        return self._fetch_with_retry(do_list)

    def renew_file(self, uhrp_url: str, additional_minutes: int) -> RenewFileResult:
        """
        Extend the retention period for an uploaded file with retry and timeout logic.
        """
        def do_renew():
            url = f"{self.base_url}/renew"
            body = {"uhrpUrl": uhrp_url, "additionalMinutes": additional_minutes}
            import json
            options = SimplifiedFetchRequestOptions(
                method="POST",
                headers={"Content-Type": _JSON_MIME},
                body=json.dumps(body).encode()
            )
            try:
                resp = self.auth_fetch.fetch(None, url, options)
            except Exception as e:
                raise NetworkError(f"Network error during renewFile: {e}")
            if not hasattr(resp, 'ok') or not resp.ok:
                code = getattr(resp, 'status_code', 'unknown')
                raise UploadError(f"renewFile request failed: HTTP {code}")
            data = resp.json()
            code_val = data.get("code")
            desc_val = data.get("description")
            if data.get("status") == "error":
                err_code = code_val or "unknown-code"
                err_desc = desc_val or "no-description"
                raise UploadError(f"renewFile returned an error: {err_code} - {err_desc}")
            return RenewFileResult(
                status=data.get("status", ""),
                prev_expiry_time=data.get("prevExpiryTime", 0),
                new_expiry_time=data.get("newExpiryTime", 0),
                amount=data.get("amount", 0),
                code=code_val,
                description=desc_val
            )
        return self._fetch_with_retry(do_renew)
