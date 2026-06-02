import json
import os
import random
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from ..transaction import Transaction

from ..http_client import HttpClient, SyncHttpClient, default_http_client, default_sync_http_client
from .broadcaster import Broadcaster, BroadcastFailure, BroadcastResponse


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
        "INVALID",
        "MALFORMED",
    }
)

# GET /v1/tx txStatus values where broadcast is accepted and ARC is still processing toward the network.
# Some deployments rarely upgrade GET to SEEN_ON_NETWORK even when the tx is relayed; live tests treat
# these as visible (see :func:`~tests.bsv.live.arc_verify.wait_until_arc_tx_seen_on_network`).
ARC_PROGRESSING_TX_STATUSES = frozenset(
    {
        "UNKNOWN",
        "QUEUED",
        "RECEIVED",
        "STORED",
        "ANNOUNCED_TO_NETWORK",
        "REQUESTED_BY_NETWORK",
        "SENT_TO_NETWORK",
        "ACCEPTED_BY_NETWORK",
    }
)

_ARC_503_DESCRIPTION = "Failed to connect to ARC service"

ARC_WARNING_TX_STATUSES = frozenset(
    {
        "DOUBLE_SPEND_ATTEMPTED",
        "MINED_IN_STALE_BLOCK",
        "SEEN_IN_ORPHAN_MEMPOOL",
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


def _broadcast_non_ok_failure(
    response_status: int,
    response_json: dict,
    data: Any,
    timeout_desc: str = "Transaction broadcast timed out",
) -> BroadcastFailure:
    if response_status == 408:
        return BroadcastFailure(
            status="failure",
            code="408",
            description=timeout_desc,
            more={"http_status": response_status, "arc_json": response_json},
        )
    if response_status == 503:
        return BroadcastFailure(
            status="failure",
            code="503",
            description=_ARC_503_DESCRIPTION,
            more={"http_status": response_status, "arc_json": response_json},
        )
    return BroadcastFailure(
        status="failure",
        code=str(response_status),
        description=_arc_extract_http_error_detail(data),
        more={"http_status": response_status, "arc_json": response_json},
    )


def arc_post_data_indicates_failure(data: dict[str, Any]) -> Optional[str]:
    """If ARC POST `data` means the transaction failed, return a description; else None.

    Only terminal failures (REJECTED, ERROR, etc.) are treated as failure here.
    Warning statuses (DOUBLE_SPEND_ATTEMPTED, SEEN_IN_ORPHAN_MEMPOOL, etc.) are
    NOT flagged — if ARC returned HTTP 200 with a txid, the broadcast is considered
    accepted.  Callers should use :meth:`ARC.check_transaction_status` and
    :meth:`ARC.categorize_transaction_status` to detect warning conditions afterward.
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
    def __init__(self, url: str, config: str | ARCConfig | None = None):
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

    async def broadcast(self, tx: "Transaction") -> BroadcastResponse | BroadcastFailure:
        """Broadcast a transaction to the BSV network via ARC.

        A BroadcastResponse with status="success" means ARC accepted the
        transaction for relay — it does not guarantee the transaction is
        mined or final. Use :meth:`check_transaction_status` and
        :meth:`categorize_transaction_status` to track confirmation progress.
        """
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
                        description=_arc_extract_http_error_detail(data),
                        more={
                            "http_status": response.status_code,
                            "arc_json": response_json,
                        },
                    )
            else:
                return _broadcast_non_ok_failure(response.status_code, response_json, data)

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

    def sync_broadcast(self, tx: "Transaction", timeout: int = 30) -> BroadcastResponse | BroadcastFailure:
        """Synchronously broadcast a transaction to the BSV network via ARC.

        A BroadcastResponse with status="success" means ARC accepted the
        transaction for relay — it does not guarantee the transaction is
        mined or final. Use :meth:`check_transaction_status` and
        :meth:`categorize_transaction_status` to track confirmation progress.

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
                        description=_arc_extract_http_error_detail(data),
                        more={
                            "http_status": response.status_code,
                            "arc_json": response_json,
                        },
                    )
            else:
                return _broadcast_non_ok_failure(
                    response.status_code,
                    response_json,
                    data,
                    timeout_desc=f"Transaction broadcast timed out after {effective_timeout} seconds",
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
        """Check transaction status synchronously via GET /v1/tx/{txid}.

        :param txid: Transaction ID to check
        :param timeout: Timeout setting in seconds
        :returns: On success ``{"txid", "txStatus", "blockHash", "blockHeight",
            "merklePath", "extraInfo", "competingTxs", "timestamp"}``.
            On failure ``{"status": "failure", "code", "title", "detail",
            "txid", ...}``.  Check ``result.get("status") == "failure"``
            to distinguish the two shapes.
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
                        "detail": _ARC_503_DESCRIPTION,
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
        """Categorize a transaction's ARC status into an actionable group.

        Returns ``{"status_category": ..., "tx_status": ...}`` where
        ``status_category`` is one of:

        - **mined** — included in a block; essentially final.
        - **0confirmation** — seen on network with no competing txs.
        - **progressing** — propagating; no issues detected yet.
        - **warning** — competing txs, stale block, or orphan mempool.
        - **rejected** — explicitly rejected by ARC.
        - **unknown_txStatus** — unrecognized txStatus value from ARC.
        - **error** — missing txStatus or malformed response.

        See docs/broadcasting_and_tx_status.md for handling guidance.

        :param response: The transaction status response from ARC
            (as returned by :meth:`check_transaction_status`).
        :returns: Dict with ``status_category`` and ``tx_status`` keys.
        """
        try:
            tx_status = response.get("txStatus")
            if not tx_status:
                return {"status_category": "error", "tx_status": "No txStatus"}

            if tx_status in ARC_PROGRESSING_TX_STATUSES:
                status_category = "progressing"
            elif tx_status == "MINED":
                status_category = "mined"
            elif tx_status == "SEEN_ON_NETWORK":
                status_category = "warning" if response.get("competingTxs") else "0confirmation"
            elif tx_status in ARC_WARNING_TX_STATUSES:
                status_category = "warning"
            elif tx_status in ARC_TERMINAL_FAILURE_TX_STATUSES:
                status_category = "rejected"
            else:
                status_category = "unknown_txStatus"

            return {"status_category": status_category, "tx_status": tx_status}

        except Exception as e:
            return {"status_category": "error", "error": str(e), "response": response}
