import requests
from typing import Any, List, Optional
from .interfaces import StorageDownloaderInterface, DownloadResult
from .exceptions import DownloadError, NetworkError
from bsv.overlay.lookup import LookupResolver, LookupQuestion
from bsv.transaction import Transaction
from bsv.transaction.pushdrop import parse_pushdrop_locking_script
from .utils import StorageUtils
import hashlib
import time

class Downloader(StorageDownloaderInterface):
    """
    Downloader provides methods to resolve UHRP URLs to HTTP URLs and download files
    from distributed storage, verifying file integrity by hash.
    Supports configurable timeout and retry logic for robust error handling.
    """
    def __init__(self, network: str, lookup_backend: Optional[Any] = None, timeout: float = 30.0, max_retries: int = 3, retry_delay: float = 1.0) -> None:
        """
        :param network: Network preset (e.g., 'mainnet', 'testnet')
        :param lookup_backend: Optional custom backend for lookup resolver
        :param timeout: Timeout in seconds for each HTTP request
        :param max_retries: Maximum number of retries for each download URL
        :param retry_delay: Delay in seconds between retries
        """
        self.network = network
        self.lookup_resolver = LookupResolver(backend=lookup_backend)
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay

    def resolve(self, uhrp_url: str) -> List[str]:
        question = LookupQuestion(service='ls_uhrp', query={'uhrpUrl': uhrp_url})
        answer = self.lookup_resolver.query(None, question)
        if answer.type != 'output-list':
            raise DownloadError('Lookup answer must be an output list')
        urls = []
        for output in answer.outputs:
            try:
                tx = Transaction.from_beef(output.beef)
                tx_out = tx.outputs[output.outputIndex]
                script_bytes = tx_out.locking_script.serialize()
                items = parse_pushdrop_locking_script(script_bytes)
                if len(items) >= 3:
                    url = items[2].decode('utf-8')
                    urls.append(url)
            except Exception:
                continue
        return urls

    def _check_response_errors(self, resp: Any) -> bool:
        def get_error_info():
            try:
                data = resp.json()
                code = data.get('code', 'unknown-code')
                desc = data.get('description', 'no-description')
                return f" (code: {code}, description: {desc})"
            except Exception:
                return ""
        if resp.status_code == 401:
            raise DownloadError("Authentication required to download this file (401)" + get_error_info())
        if resp.status_code == 403:
            raise DownloadError("Access forbidden to this file (403)" + get_error_info())
        if resp.status_code == 402:
            raise DownloadError("Payment required to download this file (402)" + get_error_info())
        if not resp.ok or resp.status_code >= 400:
            return False
        return True

    def _is_valid_hash(self, data: bytes, expected_hash: bytes) -> bool:
        actual_hash = hashlib.sha256(data).digest()
        return actual_hash == expected_hash

    def download(self, uhrp_url: str) -> DownloadResult:
        """
        Download a file from distributed storage using its UHRP URL.
        Verifies file integrity by comparing SHA256 hash.
        Retries on network errors and timeouts up to max_retries.
        :param uhrp_url: UHRP URL of the file
        :return: DownloadResult with file data and MIME type
        :raises DownloadError, NetworkError
        """
        download_urls = self.resolve(uhrp_url)
        if not isinstance(download_urls, list) or not download_urls:
            raise DownloadError("No one currently hosts this file!")
        expected_hash = StorageUtils.get_hash_from_url(uhrp_url)
        last_err = None
        for url in download_urls:
            for attempt in range(1, self.max_retries + 1):
                try:
                    resp = requests.get(url, timeout=self.timeout)
                except requests.RequestException as e:
                    last_err = NetworkError(f"Network error during file download (attempt {attempt}/{self.max_retries}): {e}")
                    if attempt < self.max_retries:
                        time.sleep(self.retry_delay)
                    continue
                if not self._check_response_errors(resp):
                    last_err = DownloadError(f"HTTP error during file download (attempt {attempt}/{self.max_retries}) from {url}")
                    if attempt < self.max_retries:
                        time.sleep(self.retry_delay)
                    continue
                data = resp.content
                mime_type = resp.headers.get('Content-Type')
                if not self._is_valid_hash(data, expected_hash):
                    last_err = DownloadError(f"Hash mismatch for file from {url} (attempt {attempt}/{self.max_retries})")
                    if attempt < self.max_retries:
                        time.sleep(self.retry_delay)
                    continue
                return DownloadResult(data=data, mime_type=mime_type)
        if last_err:
            raise last_err
        raise DownloadError(f"Unable to download content from {uhrp_url} after {self.max_retries} retries per host.")
