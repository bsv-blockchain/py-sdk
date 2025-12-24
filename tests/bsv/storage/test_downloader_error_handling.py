"""
Comprehensive error handling tests for storage/downloader.py
"""
import pytest
from unittest.mock import Mock, patch
from bsv.storage.downloader import Downloader
from bsv.storage.exceptions import DownloadError, NetworkError


class TestDownloaderErrorHandling:
    """Test downloader error handling scenarios."""

    def setup_method(self):
        """Set up test fixtures."""
        self.downloader = Downloader(network='mainnet')

    def test_http_401_authentication_required(self):
        """Test 401 authentication error response."""
        with patch.object(self.downloader, 'resolve', return_value=['https://test.com/file']):
            with patch('requests.get') as mock_get:
                # Mock 401 response with JSON error info
                mock_resp = Mock()
                mock_resp.status_code = 401
                mock_resp.ok = False
                mock_resp.json.return_value = {"code": "auth_required", "description": "Token missing"}
                mock_get.return_value = mock_resp

                with pytest.raises(DownloadError, match="Authentication required.*401.*auth_required.*Token missing"):
                    self.downloader.download('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e')

    def test_http_403_access_forbidden(self):
        """Test 403 forbidden error response."""
        with patch.object(self.downloader, 'resolve', return_value=['https://test.com/file']):
            with patch('requests.get') as mock_get:
                mock_resp = Mock()
                mock_resp.status_code = 403
                mock_resp.ok = False
                mock_resp.json.return_value = {"code": "forbidden", "description": "Access denied"}
                mock_get.return_value = mock_resp

                with pytest.raises(DownloadError, match="Access forbidden.*403.*forbidden.*Access denied"):
                    self.downloader.download('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e')

    def test_http_402_payment_required(self):
        """Test 402 payment required error response."""
        with patch.object(self.downloader, 'resolve', return_value=['https://test.com/file']):
            with patch('requests.get') as mock_get:
                mock_resp = Mock()
                mock_resp.status_code = 402
                mock_resp.ok = False
                mock_resp.json.return_value = {"code": "payment_req", "description": "1000 satoshis required"}
                mock_get.return_value = mock_resp

                with pytest.raises(DownloadError, match="Payment required.*402.*payment_req.*1000 satoshis required"):
                    self.downloader.download('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e')

    def test_http_500_server_error(self):
        """Test 500+ server error responses."""
        with patch.object(self.downloader, 'resolve', return_value=['https://test.com/file']):
            with patch('requests.get') as mock_get:
                mock_resp = Mock()
                mock_resp.status_code = 500
                mock_resp.ok = False
                mock_resp.text = "Internal Server Error"
                mock_get.return_value = mock_resp

                with pytest.raises(DownloadError, match="HTTP error during file download"):
                    self.downloader.download('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e')

    def test_http_error_without_json(self):
        """Test HTTP error response without JSON."""
        with patch.object(self.downloader, 'resolve', return_value=['https://test.com/file']):
            with patch('requests.get') as mock_get:
                mock_resp = Mock()
                mock_resp.status_code = 404
                mock_resp.ok = False
                mock_resp.json.side_effect = ValueError("No JSON")
                mock_resp.text = "Not Found"
                mock_get.return_value = mock_resp

                with pytest.raises(DownloadError, match="HTTP error during file download"):
                    self.downloader.download('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e')

    def test_network_timeout_error(self):
        """Test network timeout error with retries."""
        import requests
        with patch.object(self.downloader, 'resolve', return_value=['https://test.com/file']):
            with patch('requests.get', side_effect=requests.Timeout("Connection timed out")):
                with patch('time.sleep') as mock_sleep:
                    with pytest.raises(NetworkError, match="Network error.*attempt 3/3.*timed out"):
                        self.downloader.download('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e')

                    # Should retry 3 times (max_retries)
                    assert mock_sleep.call_count == 2  # Called after attempt 1 and 2

    def test_network_connection_error(self):
        """Test network connection error with retries."""
        import requests
        with patch.object(self.downloader, 'resolve', return_value=['https://test.com/file']):
            with patch('requests.get', side_effect=requests.ConnectionError("Connection refused")):
                with patch('time.sleep') as mock_sleep:
                    with pytest.raises(NetworkError, match="Network error.*attempt 3/3.*Connection refused"):
                        self.downloader.download('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e')

                    assert mock_sleep.call_count == 2

    def test_hash_mismatch_retry(self):
        """Test hash mismatch with retries."""
        with patch.object(self.downloader, 'resolve', return_value=['https://test.com/file']):
            with patch('requests.get') as mock_get:
                with patch('time.sleep') as mock_sleep:
                    # Mock successful response but with wrong hash
                    mock_resp = Mock()
                    mock_resp.status_code = 200
                    mock_resp.ok = True
                    mock_resp.content = b'wrong data'
                    mock_resp.headers = {'Content-Type': 'text/plain'}
                    mock_get.return_value = mock_resp

                    with pytest.raises(DownloadError, match="Hash mismatch.*attempt 3/3"):
                        self.downloader.download('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e')

                    # Should retry 3 times
                    assert mock_sleep.call_count == 2
                    assert mock_get.call_count == 3

    def test_empty_url_list(self):
        """Test when resolve() returns empty URL list."""
        with patch.object(self.downloader, 'resolve', return_value=[]):
            with pytest.raises(DownloadError, match="No one currently hosts this file"):
                self.downloader.download('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e')

    def test_non_list_url_resolution(self):
        """Test when resolve() returns non-list."""
        with patch.object(self.downloader, 'resolve', return_value="not-a-list"):
            with pytest.raises(DownloadError, match="No one currently hosts this file"):
                self.downloader.download('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e')

    def test_all_urls_fail(self):
        """Test when all URLs fail after retries."""
        import requests
        with patch.object(self.downloader, 'resolve', return_value=['https://url1.com', 'https://url2.com']):
            with patch('requests.get', side_effect=requests.ConnectionError("Failed")):
                with patch('time.sleep'):
                    with pytest.raises(NetworkError, match="Network error.*attempt 3/3"):
                        self.downloader.download('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e')

    def test_max_retries_exceeded_single_url(self):
        """Test max retries exceeded for single URL."""
        import requests
        with patch.object(self.downloader, 'resolve', return_value=['https://test.com/file']):
            with patch('requests.get', side_effect=requests.ConnectionError("Failed")):
                with patch('time.sleep'):
                    with pytest.raises(NetworkError, match="Network error.*attempt 3/3"):
                        self.downloader.download('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e')

    def test_successful_download_after_retry(self):
        """Test successful download after some retries."""
        with patch.object(self.downloader, 'resolve', return_value=['https://test.com/file']):
            with patch('requests.get') as mock_get:
                with patch('time.sleep') as mock_sleep:
                    # Mock: first two calls fail, third succeeds
                    mock_resp_fail = Mock()
                    mock_resp_fail.status_code = 500
                    mock_resp_fail.ok = False

                    mock_resp_success = Mock()
                    mock_resp_success.status_code = 200
                    mock_resp_success.ok = True
                    mock_resp_success.content = b'correct data'  # This will have the right hash
                    mock_resp_success.headers = {'Content-Type': 'text/plain'}

                    import requests
                    mock_get.side_effect = [requests.ConnectionError("Fail1"), requests.ConnectionError("Fail2"), mock_resp_success]

                    # Mock hash verification to succeed on third attempt
                    with patch.object(self.downloader, '_is_valid_hash', return_value=True):
                        result = self.downloader.download('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e')

                        assert result.data == b'correct data'
                        assert mock_sleep.call_count == 2  # Sleep after first two failures
                        assert mock_get.call_count == 3

    def test_malformed_response_json(self):
        """Test malformed JSON in error response."""
        with patch.object(self.downloader, 'resolve', return_value=['https://test.com/file']):
            with patch('requests.get') as mock_get:
                mock_resp = Mock()
                mock_resp.status_code = 400
                mock_resp.ok = False
                mock_resp.json.side_effect = ValueError("Invalid JSON")
                mock_resp.text = "Bad JSON Response"
                mock_get.return_value = mock_resp

                with pytest.raises(DownloadError, match="HTTP error during file download"):
                    self.downloader.download('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e')

    def test_timeout_with_custom_settings(self):
        """Test timeout behavior with custom downloader settings."""
        custom_downloader = Downloader(network='mainnet', timeout=5.0, max_retries=2)
        assert abs(custom_downloader.timeout - 5.0) < 0.0001  # Use approximate comparison for floats
        assert custom_downloader.max_retries == 2

        with patch.object(custom_downloader, 'resolve', return_value=['https://test.com/file']):
            import requests
            with patch('requests.get', side_effect=requests.Timeout("Timeout")):
                with patch('time.sleep'):
                    with pytest.raises(NetworkError, match="Network error.*attempt 2/2"):
                        custom_downloader.download('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e')

    def test_retry_delay_behavior(self):
        """Test that retry delay is respected."""
        import time
        with patch.object(self.downloader, 'resolve', return_value=['https://test.com/file']):
            import requests
            with patch('requests.get', side_effect=requests.ConnectionError("Fail")):
                with patch('time.sleep') as mock_sleep:
                    start_time = time.time()
                    try:
                        self.downloader.download('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e')
                    except NetworkError:
                        pass

                    # Should have slept twice (after attempt 1 and 2)
                    assert mock_sleep.call_count == 2
                    # Verify sleep was called with correct delay
                    mock_sleep.assert_any_call(self.downloader.retry_delay)
                    mock_sleep.assert_any_call(self.downloader.retry_delay)

    def test_different_retry_delays(self):
        """Test custom retry delay."""
        custom_downloader = Downloader(network='mainnet', retry_delay=2.0)
        assert abs(custom_downloader.retry_delay - 2.0) < 0.0001  # Use approximate comparison for floats

        with patch.object(custom_downloader, 'resolve', return_value=['https://test.com/file']):
            import requests
            with patch('requests.get', side_effect=requests.ConnectionError("Fail")):
                with patch('time.sleep') as mock_sleep:
                    try:
                        custom_downloader.download('uhrp://XUUGmtdnuC47vGCtZShMz1HMMHxwNa3j9e91VmYyhNmZpp8BGR2e')
                    except NetworkError:
                        pass

                    mock_sleep.assert_any_call(2.0)
