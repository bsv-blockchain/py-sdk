import aiohttp
import requests

from abc import ABC, abstractmethod
from typing import Optional, Dict

class HttpClient(ABC):
    @abstractmethod
    def fetch(self, url: str, options: dict) -> "HttpResponse":
        pass


class HttpResponse:
    def __init__(self, ok: bool, status_code: int, json_data: dict):
        self.ok = ok
        self.status_code = status_code
        self._json_data = json_data

    def json(self):
        return self._json_data


class DefaultHttpClient(HttpClient):
    async def fetch(self, url: str, options: dict) -> HttpResponse:
        async with aiohttp.ClientSession() as session:
            async with session.request(
                method=options["method"],
                url=url,
                headers=options.get("headers", {}),
                json=options.get("data", None),
            ) as response:
                try:
                    json_data = await response.json()
                    return HttpResponse(
                        ok=response.status >= 200 and response.status <= 299,
                        status_code=response.status,
                        json_data={
                            'data': json_data
                        },
                    )
                except Exception as e:
                    return HttpResponse(
                        ok=False,
                        status_code=response.status,
                        json_data={},
                    )

class SyncHttpClient(HttpClient):
    """Synchronous HTTP client compatible with DefaultHttpClient"""

    def __init__(self, default_timeout: int = 30):
        self.default_timeout = default_timeout

    def fetch(self, url: str, options: dict) -> HttpResponse:
        method = options.get("method", "GET")
        headers = options.get("headers", {})
        timeout = options.get("timeout", self.default_timeout)
        data = options.get("data", None)

        try:
            if method.upper() in ["POST", "PUT", "PATCH"] and data is not None:
                response = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=data,
                    timeout=timeout
                )
            else:
                response = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    timeout=timeout
                )

            return self._make_response(response)
        except requests.RequestException as e:
            return self._handle_error(e)

    def _make_response(self, response: requests.Response) -> HttpResponse:
        try:
            json_data = response.json()
            formatted_json = {'data': json_data}
        except (ValueError, requests.exceptions.JSONDecodeError):
            formatted_json = {}

        ok = response.status_code >= 200 and response.status_code <= 299

        return HttpResponse(
            ok=ok,
            status_code=response.status_code,
            json_data=formatted_json
        )

    def _handle_error(self, error: requests.RequestException) -> HttpResponse:
        if isinstance(error, requests.Timeout):
            status_code = 408
        elif isinstance(error, requests.ConnectionError):
            status_code = 503
        elif isinstance(error, requests.HTTPError):
            status_code = error.response.status_code if error.response else 500
        else:
            status_code = 0

        return HttpResponse(
            ok=False,
            status_code=status_code,
            json_data={"error": str(error), "error_type": type(error).__name__}
        )

    def get(self, url: str,
            headers: Optional[Dict[str, str]] = None,
            timeout: Optional[int] = None) -> HttpResponse:
        options = {
            "method": "GET",
            "headers": headers or {},
            "timeout": timeout if timeout is not None else self.default_timeout
        }
        return self.fetch(url, options)

    def post(self, url: str,
             data: Optional[dict] = None,
             headers: Optional[Dict[str, str]] = None,
             timeout: Optional[int] = None) -> HttpResponse:
        options = {
            "method": "POST",
            "headers": headers or {},
            "data": data,
            "timeout": timeout if timeout is not None else self.default_timeout
        }
        return self.fetch(url, options)


def default_sync_http_client() -> SyncHttpClient:
    return SyncHttpClient()


def default_http_client() -> HttpClient:
    return DefaultHttpClient()