import json
import os
import random
from typing import TYPE_CHECKING, Any, Dict, Optional, Union

if TYPE_CHECKING:
    from ..transaction import Transaction

from .broadcaster import Broadcaster, BroadcastFailure, BroadcastResponse
from ..http_client import HttpClient, SyncHttpClient, default_http_client, default_sync_http_client


def to_hex(bytes_data):
    return "".join(f"{x:02x}" for x in bytes_data)


def random_hex(length: int) -> str:
    return "".join(f"{random.randint(0, 255):02x}" for _ in range(length))


class ARCConfig:
    def __init__(
        self,
        api_key: Optional[str] = None,
        http_client: Optional[HttpClient] = None,
        sync_http_client: Optional[SyncHttpClient] = None,
        deployment_id: Optional[str] = None,
        callback_url: Optional[str] = None,
        callback_token: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
    ):
        self.api_key = api_key
        self.http_client = http_client
        self.sync_http_client = sync_http_client
        self.deployment_id = deployment_id
        self.callback_url = callback_url
        self.callback_token = callback_token
        self.headers = headers


def default_deployment_id() -> str:
    return f"py-sdk-{random_hex(16)}"


# ARC POST /v1/tx returns txStatus alongside txid. These mean the tx did not
# succeed as an acceptable broadcast from the network's perspective (see also
# categorize_transaction_status).
ARC_TERMINAL_FAILURE_TX_STATUSES = frozenset(
    {
        "REJECTED",
        "ERROR",
        "SEEN_IN_ORPHAN_MEMPOOL",
        "DOUBLE_SPEND_ATTEMPTED",
    }
)

# GET /v1/tx txStatus values where broadcast is accepted and ARC is still processing toward the network.
# Some deployments rarely upgrade GET to SEEN_ON_NETWORK even when the tx is relayed; live tests treat
# these as visible (see :func:`~tests.bsv.live.arc_verify.wait_until_arc_tx_seen_on_network`).
ARC_PROGRESSING_TX_STATUSES = frozenset(
    {
        "QUEUED",
        "RECEIVED",
        "STORED",
        "ANNOUNCED_TO_NETWORK",
        "REQUESTED_BY_NETWORK",
        "SENT_TO_NETWORK",
        "ACCEPTED_BY_NETWORK",
    }
)


def _arc_extract_http_error_detail(payload: Any) -> str:
    """Human-readable message from ARC/HTTP error JSON (RFC 7807 and variants)."""
    if payload is None:
        return "Unknown error"
    if isinstance(payload, str):
        return payload.strip()[:8000] or "Unknown error"
    if isinstance(payload, dict):
        for key in ("detail", "description", "message", "title"):
            v = payload.get(key)
            if v is not None and str(v).strip() != "":
                return str(v).strip()[:8000]
        try:
            return json.dumps(payload)[:8000]
        except (TypeError, ValueError):
            return str(payload)[:8000]
    return str(payload)[:8000]


def _arc_broadcast_failure_description(response_json: Any) -> str:
    """Error string from :class:`~bsv.http_client.HttpResponse` ``.json()`` shape ``{\"data\": ...}``."""
    if not isinstance(response_json, dict):
        return _arc_extract_http_error_detail(response_json)
    inner = response_json.get("data")
    return _arc_extract_http_error_detail(inner)


def arc_post_data_indicates_failure(data: Dict[str, Any]) -> Optional[str]:
    """If ARC POST `data` means the transaction failed, return a description; else None.

    Missing or unknown txStatus is treated as acceptable (backward compatible).
    """
    if not data.get("txid"):
        return None
    tx_status = data.get("txStatus")
    if not tx_status:
        return None
    if tx_status in ARC_TERMINAL_FAILURE_TX_STATUSES:
        extra = (data.get("extraInfo") or "").strip()
        if extra:
            return f"{tx_status}: {extra}"
        return tx_status
    return None


class ARC(Broadcaster):
    def __init__(self, url: str, config: Union[str, ARCConfig] = None):
        self.URL = url
        if isinstance(config, str):
            self.api_key = config
            self.http_client = default_http_client()
            self.sync_http_client = default_sync_http_client()
            self.deployment_id = default_deployment_id()
            self.callback_url = None
            self.callback_token = None
            self.headers = None
        else:
            config = config or ARCConfig()
            self.api_key = config.api_key
            self.http_client = config.http_client or default_http_client()
            self.sync_http_client = config.sync_http_client or default_sync_http_client()
            self.deployment_id = config.deployment_id or default_deployment_id()
            self.callback_url = config.callback_url
            self.callback_token = config.callback_token
            self.headers = config.headers

    async def broadcast(self, tx: "Transaction") -> Union[BroadcastResponse, BroadcastFailure]:
        # Check if all inputs have source_transaction
        has_all_source_txs = all(input.source_transaction is not None for input in tx.inputs)
        request_options = {
            "method": "POST",
            "headers": self.request_headers(),
            "data": {"rawTx": tx.to_ef().hex() if has_all_source_txs else tx.hex()},
        }
        bound = self._http_timeout_for_v1_tx_post()
        if bound is not None:
            request_options["timeout"] = bound
        try:
            response = await self.http_client.fetch(f"{self.URL}/v1/tx", request_options)

            response_json = response.json()

            if response.ok and response.status_code >= 200 and response.status_code <= 299:
                data = response_json["data"]

                if data.get("txid"):
                    failure_desc = arc_post_data_indicates_failure(data)
                    if failure_desc:
                        return BroadcastFailure(
                            status="failure",
                            code="ARC_TX_STATUS",
                            description=failure_desc,
                            txid=data.get("txid"),
                            more={
                                "http_status": response.status_code,
                                "arc_json": response_json,
                            },
                        )
                    msg = f"{data.get('txStatus', '')} {data.get('extraInfo', '')}".strip()
                    return BroadcastResponse(
                        status="success",
                        txid=data.get("txid"),
                        message=msg,
                        extra={
                            "http_status": response.status_code,
                            "arc_json": response_json,
                        },
                    )
                else:
                    return BroadcastFailure(
                        status="failure",
                        code=data.get("status", "ERR_UNKNOWN"),
                        description=_arc_extract_http_error_detail(data),
                        more={
                            "http_status": response.status_code,
                            "arc_json": response_json,
                        },
                    )
            else:
                return BroadcastFailure(
                    status="failure",
                    code=str(response.status_code),
                    description=_arc_broadcast_failure_description(response_json),
                    more={
                        "http_status": response.status_code,
                        "arc_json": response_json,
                    },
                )

        except Exception as error:
            return BroadcastFailure(
                status="failure",
                code="500",
                description=str(error),
                more={
                    "exception_type": type(error).__name__,
                    "exception": str(error),
                },
            )

    def request_headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "XDeployment-ID": self.deployment_id,
        }

        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        if self.callback_url:
            headers["X-CallbackUrl"] = self.callback_url

        if self.callback_token:
            headers["X-CallbackToken"] = self.callback_token

        if self.headers:
            headers.update(self.headers)

        return headers

    def _http_timeout_for_v1_tx_post(self) -> Optional[int]:
        """HTTP client timeout for POST /v1/tx when ARC may block (wait-for status).

        GorillaPool uses ``X-WaitForStatus`` (8 = SEEN_ON_NETWORK), not legacy
        ``X-WaitFor: SEEN_ON_NETWORK``. Optional ``X-MaxTimeout`` (seconds) may be
        set for TAAL-compatible deployments; otherwise ``ARC_X_MAX_TIMEOUT`` env
        (default 120) applies when ``X-WaitForStatus`` requests a wait.
        """
        if not self.headers:
            return None
        raw_max = self.headers.get("X-MaxTimeout")
        if raw_max is not None:
            try:
                server_sec = int(str(raw_max).strip())
            except ValueError:
                server_sec = None
            if server_sec is not None:
                return max(45, server_sec + 30)
        wfs = self.headers.get("X-WaitForStatus")
        if wfs is None:
            return None
        try:
            code = int(str(wfs).strip())
        except ValueError:
            return None
        if code <= 0:
            return None
        try:
            sec = int(os.environ.get("ARC_X_MAX_TIMEOUT", "120").strip() or "120")
        except ValueError:
            sec = 120
        return max(45, sec + 30)

    def sync_broadcast(self, tx: "Transaction", timeout: int = 30) -> Union[BroadcastResponse, BroadcastFailure]:
        """
        Synchronously broadcast a transaction

        :param tx: Transaction to broadcast
        :param timeout: Timeout setting in seconds
        :returns: BroadcastResponse or BroadcastFailure
        """
        # Check if all inputs have source_transaction
        has_all_source_txs = all(input.source_transaction is not None for input in tx.inputs)

        effective_timeout = timeout
        bound = self._http_timeout_for_v1_tx_post()
        if bound is not None:
            effective_timeout = max(effective_timeout, bound)

        try:
            response = self.sync_http_client.post(
                f"{self.URL}/v1/tx",
                data={"rawTx": tx.to_ef().hex() if has_all_source_txs else tx.hex()},
                headers=self.request_headers(),
                timeout=effective_timeout,
            )

            response_json = response.json()
            data = response_json.get("data", {})

            if response.ok:
                if data.get("txid"):
                    failure_desc = arc_post_data_indicates_failure(data)
                    if failure_desc:
                        return BroadcastFailure(
                            status="failure",
                            code="ARC_TX_STATUS",
                            description=failure_desc,
                            txid=data.get("txid"),
                            more={
                                "http_status": response.status_code,
                                "arc_json": response_json,
                            },
                        )
                    msg = f"{data.get('txStatus', '')} {data.get('extraInfo', '')}".strip()
                    return BroadcastResponse(
                        status="success",
                        txid=data.get("txid"),
                        message=msg,
                        extra={
                            "http_status": response.status_code,
                            "arc_json": response_json,
                        },
                    )
                else:
                    return BroadcastFailure(
                        status="failure",
                        code=data.get("status", "ERR_UNKNOWN"),
                        description=data.get("detail", "Unknown error"),
                        more={
                            "http_status": response.status_code,
                            "arc_json": response_json,
                        },
                    )
            else:
                # Handle special error cases
                if response.status_code == 408:
                    return BroadcastFailure(
                        status="failure",
                        code="408",
                        description=f"Transaction broadcast timed out after {effective_timeout} seconds",
                        more={"http_status": response.status_code, "arc_json": response_json},
                    )

                if response.status_code == 503:
                    return BroadcastFailure(
                        status="failure",
                        code="503",
                        description="Failed to connect to ARC service",
                        more={"http_status": response.status_code, "arc_json": response_json},
                    )

                return BroadcastFailure(
                    status="failure",
                    code=str(response.status_code),
                    description=_arc_extract_http_error_detail(data),
                    more={"http_status": response.status_code, "arc_json": response_json},
                )

        except Exception as error:
            return BroadcastFailure(
                status="failure",
                code="500",
                description=str(error),
                more={
                    "exception_type": type(error).__name__,
                    "exception": str(error),
                },
            )

    def check_transaction_status(self, txid: str, timeout: int = 5) -> dict[str, Any]:
        """
        Check transaction status synchronously

        :param txid: Transaction ID to check
        :param timeout: Timeout setting in seconds
        :returns: Dictionary containing transaction status information
        """

        try:
            response = self.sync_http_client.get(
                f"{self.URL}/v1/tx/{txid}", headers=self.request_headers(), timeout=timeout
            )
            response_data = response.json()
            data = response_data.get("data", {})

            if response.ok:
                return {
                    "txid": txid,
                    "txStatus": data.get("txStatus"),
                    "blockHash": data.get("blockHash"),
                    "blockHeight": data.get("blockHeight"),
                    "merklePath": data.get("merklePath"),
                    "extraInfo": data.get("extraInfo"),
                    "competingTxs": data.get("competingTxs"),
                    "timestamp": data.get("timestamp"),
                }
            else:
                # Handle special error cases
                if response.status_code == 408:
                    return {
                        "status": "failure",
                        "code": 408,
                        "title": "Request Timeout",
                        "detail": f"Transaction status check timed out after {timeout} seconds",
                        "txid": txid,
                        "extra_info": "Consider retrying or increasing timeout value",
                    }

                if response.status_code == 503:
                    return {
                        "status": "failure",
                        "code": 503,
                        "title": "Connection Error",
                        "detail": "Failed to connect to ARC service",
                        "txid": txid,
                    }

                # Handle general error cases
                return {
                    "status": "failure",
                    "code": data.get("status", response.status_code),
                    "title": data.get("title", "Error"),
                    "detail": data.get("detail", "Unknown error"),
                    "txid": data.get("txid", txid),
                    "extra_info": data.get("extraInfo", ""),
                }

        except Exception as error:
            return {"status": "failure", "code": "500", "title": "Internal Error", "detail": str(error), "txid": txid}

    @staticmethod
    def categorize_transaction_status(response: dict[str, Any]) -> dict[str, Any]:
        """
        Categorize transaction status based on the ARC response

        :param response: The transaction status response dictionary from ARC
        :returns: Dictionary containing status category and transaction status
        """
        try:
            tx_status = response.get("txStatus")

            if tx_status:
                # Processing transactions - still being handled by the network
                if tx_status in [
                    "UNKNOWN",
                    "QUEUED",
                    "RECEIVED",
                    "STORED",
                    "ANNOUNCED_TO_NETWORK",
                    "REQUESTED_BY_NETWORK",
                    "SENT_TO_NETWORK",
                    "ACCEPTED_BY_NETWORK",
                ]:
                    status_category = "progressing"

                # Successfully mined transactions
                elif tx_status in ["MINED"]:
                    status_category = "mined"

                # Mined in stale block - needs attention
                elif tx_status in ["MINED_IN_STALE_BLOCK"]:
                    status_category = "0confirmation"

                # Warning status - double spend attempted
                elif tx_status in ["DOUBLE_SPEND_ATTEMPTED"]:
                    status_category = "warning"

                # Seen on network - check for competing transactions
                elif tx_status in ["SEEN_ON_NETWORK"]:
                    # Check if there are competing transactions in mempool
                    if response.get("competingTxs"):
                        status_category = "warning"
                    else:
                        # Transaction is in mempool without conflicts
                        status_category = "0confirmation"

                # Rejected transactions - failed to process
                elif tx_status in ["ERROR", "REJECTED", "SEEN_IN_ORPHAN_MEMPOOL"]:
                    status_category = "rejected"

                else:
                    status_category = f"unknown_txStatus: {tx_status}"
            else:
                status_category = "error"
                tx_status = "No txStatus"

            return {"status_category": status_category, "tx_status": tx_status}

        except Exception as e:
            return {"status_category": "error", "error": str(e), "response": response}
