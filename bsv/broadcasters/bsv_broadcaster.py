"""BSV Broadcaster implementation.

BSV Broadcaster (bsv-blockchain/broadcaster, formerly Arcade) is the
Teranode-native, ARC-compatible transaction broadcaster. This is a port of the
TypeScript wallet-toolbox ``Arcade`` class, adapted to the py-sdk
``Broadcaster`` interface. The old ``Arcade`` / ``ArcadeConfig`` names remain
available from :mod:`bsv.broadcasters.arcade` as deprecated aliases; result
codes and keys (``ARCADE_TX_STATUS``, ``more["arcade_json"]``) keep their
original names so existing callers are unaffected.

:class:`BsvBroadcaster` is deliberately a separate, self-contained class (not
a subclass of :class:`~bsv.broadcasters.arc.ARC`) so the ARC transport is
never altered — mirroring the TS design. It is ARC-compatible on configuration
and the ``GET /tx/{txid}`` response shape, but differs where it must:

- Endpoints are served at the root: ``POST /tx`` and ``GET /tx/{txid}``
  (no ``/v1`` prefix).
- Submission encoding is Extended Format (EF) preferred, raw tx hex as a
  fallback — NOT BEEF. BSV Broadcaster's ``/tx`` parser rejects BEEF and runs
  fee/script validation that needs per-input source data, which EF carries
  inline.
- A successful submit returns HTTP 202 with
  ``{"txid", "status": 202, "txStatus": "RECEIVED"}``. An idempotent
  re-submit also returns 202 with the transaction's current status.
- HTTP 400 is a terminal validation failure (``{"error", "reason"}``) —
  the transaction itself is invalid and retrying with another provider
  will not help.
- Error bodies are flat ``{"error": ..., "reason": ...}``, not RFC 7807.
"""

import json
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from ..transaction import Transaction

from ..http_client import HttpClient, HttpResponse, SyncHttpClient, default_http_client, default_sync_http_client
from .arc import default_deployment_id
from .broadcaster import Broadcaster, BroadcastFailure, BroadcastResponse

# POST /tx (and idempotent re-submit) txStatus values meaning the transaction
# can never succeed. In BSV Broadcaster both REJECTED and DOUBLE_SPEND_ATTEMPTED are
# terminal (unlike ARC, where a double spend may still resolve).
BSV_BROADCASTER_TERMINAL_FAILURE_TX_STATUSES = frozenset(
    {
        "REJECTED",
        "DOUBLE_SPEND_ATTEMPTED",
    }
)

# txStatus values where broadcast is accepted and BSV Broadcaster is still processing
# toward the network.
BSV_BROADCASTER_PROGRESSING_TX_STATUSES = frozenset(
    {
        "UNKNOWN",
        "RECEIVED",
        "SENT_TO_NETWORK",
        "ACCEPTED_BY_NETWORK",
        "PENDING_RETRY",
        "STUMP_PROCESSING",
    }
)

# txStatus values meaning the network has seen the transaction (0-conf).
BSV_BROADCASTER_SEEN_TX_STATUSES = frozenset(
    {
        "SEEN_ON_NETWORK",
        "SEEN_MULTIPLE_NODES",
    }
)

# txStatus values meaning the transaction is included in a block.
BSV_BROADCASTER_MINED_TX_STATUSES = frozenset(
    {
        "MINED",
        "IMMUTABLE",
    }
)

_BSV_BROADCASTER_503_DESCRIPTION = "Failed to connect to BSV Broadcaster service"


class BsvBroadcasterConfig:
    """Configuration for the :class:`BsvBroadcaster` broadcaster.

    Same shape as :class:`~bsv.broadcasters.arc.ARCConfig` minus ``format``:
    BSV Broadcaster submission is always JSON ``{"rawTx": <EF or raw hex>}``.
    """

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


def _bsv_broadcaster_extract_error_detail(data: Any) -> str:
    """Human-readable message from BSV Broadcaster's flat ``{"error", "reason"}`` body."""
    if data is None:
        return "Unknown error"
    if isinstance(data, str):
        return data.strip()[:8000] or "Unknown error"
    if isinstance(data, dict):
        error = str(data.get("error") or "").strip()
        reason = str(data.get("reason") or "").strip()
        if error and reason:
            return f"{error}: {reason}"[:8000]
        if error or reason:
            return (error or reason)[:8000]
        try:
            return json.dumps(data)[:8000]
        except (TypeError, ValueError):
            return str(data)[:8000]
    return str(data)[:8000]


def bsv_broadcaster_post_data_indicates_failure(data: dict[str, Any]) -> Optional[str]:
    """If BSV Broadcaster POST `data` means the transaction failed, return a description; else None.

    Terminal statuses (REJECTED, DOUBLE_SPEND_ATTEMPTED) are flagged — an
    idempotent re-submit returns HTTP 202 with the transaction's current
    status, which can be terminal even though the HTTP status is a success.
    """
    if not data.get("txid"):
        return None
    tx_status = data.get("txStatus")
    if not tx_status:
        return None
    if tx_status in BSV_BROADCASTER_TERMINAL_FAILURE_TX_STATUSES:
        extra = (data.get("extraInfo") or "").strip()
        if extra:
            return f"{tx_status}: {extra}"
        return tx_status
    return None


class BsvBroadcaster(Broadcaster):
    def __init__(self, url: str, config: str | BsvBroadcasterConfig | None = None):
        self.URL = url
        if isinstance(config, str):
            config = BsvBroadcasterConfig(api_key=config)
        else:
            config = config or BsvBroadcasterConfig()
        self.api_key = config.api_key
        self.http_client = config.http_client or default_http_client()
        self.sync_http_client = config.sync_http_client or default_sync_http_client()
        self.deployment_id = config.deployment_id or default_deployment_id()
        self.callback_url = config.callback_url
        self.callback_token = config.callback_token
        self.headers = config.headers

    async def broadcast(self, tx: "Transaction") -> BroadcastResponse | BroadcastFailure:
        """Broadcast a transaction to the BSV network via BSV Broadcaster.

        A BroadcastResponse with status="success" means BSV Broadcaster accepted the
        transaction for validation and propagation (HTTP 202) — it does not
        guarantee the transaction is mined or final. Use
        :meth:`check_transaction_status` and
        :meth:`categorize_transaction_status` to track confirmation progress.
        """
        request_options = self._build_request_options(tx)
        try:
            response = await self.http_client.fetch(f"{self.URL}/tx", request_options)
            return self._process_broadcast_response(response)
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

    def sync_broadcast(self, tx: "Transaction", timeout: int = 30) -> BroadcastResponse | BroadcastFailure:
        """Synchronously broadcast a transaction to the BSV network via BSV Broadcaster.

        :param tx: Transaction to broadcast
        :param timeout: Timeout setting in seconds
        :returns: BroadcastResponse or BroadcastFailure
        """
        request_options = self._build_request_options(tx)
        request_options["timeout"] = timeout
        try:
            response = self.sync_http_client.fetch(f"{self.URL}/tx", request_options)
            return self._process_broadcast_response(response, timeout=timeout)
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

    def _build_request_options(self, tx: "Transaction") -> dict:
        # EF carries each input's source output (satoshis + locking script)
        # inline, which BSV Broadcaster's fee/script validation needs. Fall back to raw
        # hex when source transactions are unavailable — BSV Broadcaster also accepts
        # raw txs whose parents it can resolve itself.
        has_all_source_txs = all(input.source_transaction is not None for input in tx.inputs)
        return {
            "method": "POST",
            "headers": self.request_headers(),
            "data": {"rawTx": tx.to_ef().hex() if has_all_source_txs else tx.hex()},
        }

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

    def _process_broadcast_response(
        self, response: HttpResponse, timeout: Optional[int] = None
    ) -> BroadcastResponse | BroadcastFailure:
        response_json = response.json()
        data = response_json.get("data", {})

        if response.ok:
            if data.get("txid"):
                failure_desc = bsv_broadcaster_post_data_indicates_failure(data)
                if failure_desc:
                    return BroadcastFailure(
                        status="failure",
                        code="ARCADE_TX_STATUS",
                        description=failure_desc,
                        txid=data.get("txid"),
                        more={
                            "http_status": response.status_code,
                            "arcade_json": response_json,
                        },
                    )
                msg = f"{data.get('txStatus', '')} {data.get('extraInfo', '')}".strip()
                return BroadcastResponse(
                    status="success",
                    txid=data.get("txid"),
                    message=msg,
                    extra={
                        "http_status": response.status_code,
                        "arcade_json": response_json,
                    },
                )
            return BroadcastFailure(
                status="failure",
                code="ERR_UNKNOWN",
                description=_bsv_broadcaster_extract_error_detail(data),
                more={
                    "http_status": response.status_code,
                    "arcade_json": response_json,
                },
            )

        if response.status_code == 400:
            # Terminal validation failure: BSV Broadcaster persists a REJECTED row for
            # the transaction. Retrying (here or elsewhere) will not help.
            return BroadcastFailure(
                status="failure",
                code="400",
                description=_bsv_broadcaster_extract_error_detail(data),
                more={
                    "http_status": response.status_code,
                    "arcade_json": response_json,
                    "terminal": True,
                },
            )
        if response.status_code == 408:
            timeout_desc = (
                f"Transaction broadcast timed out after {timeout} seconds"
                if timeout is not None
                else "Transaction broadcast timed out"
            )
            return BroadcastFailure(
                status="failure",
                code="408",
                description=timeout_desc,
                more={"http_status": response.status_code, "arcade_json": response_json},
            )
        if response.status_code == 503:
            # Kafka backpressure — BSV Broadcaster sends Retry-After: 1.
            return BroadcastFailure(
                status="failure",
                code="503",
                description=_BSV_BROADCASTER_503_DESCRIPTION,
                more={"http_status": response.status_code, "arcade_json": response_json},
            )
        return BroadcastFailure(
            status="failure",
            code=str(response.status_code),
            description=_bsv_broadcaster_extract_error_detail(data),
            more={"http_status": response.status_code, "arcade_json": response_json},
        )

    def check_transaction_status(self, txid: str, timeout: int = 5) -> dict[str, Any]:
        """Check transaction status synchronously via GET /tx/{txid}.

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
                f"{self.URL}/tx/{txid}", headers=self.request_headers(), timeout=timeout
            )
            response_data = response.json()
            data = response_data.get("data", {})

            if response.ok:
                return {
                    "txid": data.get("txid", txid),
                    "txStatus": data.get("txStatus"),
                    "blockHash": data.get("blockHash"),
                    "blockHeight": data.get("blockHeight"),
                    "merklePath": data.get("merklePath"),
                    "extraInfo": data.get("extraInfo"),
                    "competingTxs": data.get("competingTxs"),
                    "timestamp": data.get("timestamp"),
                }

            if response.status_code == 404:
                return {
                    "status": "failure",
                    "code": 404,
                    "title": "Not Found",
                    "detail": _bsv_broadcaster_extract_error_detail(data) or "transaction not found",
                    "txid": txid,
                }

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
                    "detail": _BSV_BROADCASTER_503_DESCRIPTION,
                    "txid": txid,
                }

            return {
                "status": "failure",
                "code": response.status_code,
                "title": "Error",
                "detail": _bsv_broadcaster_extract_error_detail(data),
                "txid": txid,
            }

        except Exception as error:
            return {"status": "failure", "code": "500", "title": "Internal Error", "detail": str(error), "txid": txid}

    @staticmethod
    def categorize_transaction_status(response: dict[str, Any]) -> dict[str, Any]:
        """Categorize a transaction's BSV Broadcaster status into an actionable group.

        Returns ``{"status_category": ..., "tx_status": ...}`` where
        ``status_category`` is one of:

        - **mined** — MINED or IMMUTABLE; included in a block.
        - **0confirmation** — seen on network with no competing txs.
        - **progressing** — propagating; no issues detected yet.
        - **warning** — seen on network but competing txs exist.
        - **rejected** — terminal in BSV Broadcaster: REJECTED or
          DOUBLE_SPEND_ATTEMPTED (unlike ARC, a double spend is final here).
        - **unknown_txStatus** — unrecognized txStatus value from BSV Broadcaster.
        - **error** — missing txStatus or malformed response.

        :param response: The transaction status response from BSV Broadcaster
            (as returned by :meth:`check_transaction_status`).
        :returns: Dict with ``status_category`` and ``tx_status`` keys.
        """
        try:
            tx_status = response.get("txStatus")
            if not tx_status:
                return {"status_category": "error", "tx_status": "No txStatus"}

            if tx_status in BSV_BROADCASTER_PROGRESSING_TX_STATUSES:
                status_category = "progressing"
            elif tx_status in BSV_BROADCASTER_MINED_TX_STATUSES:
                status_category = "mined"
            elif tx_status in BSV_BROADCASTER_SEEN_TX_STATUSES:
                status_category = "warning" if response.get("competingTxs") else "0confirmation"
            elif tx_status in BSV_BROADCASTER_TERMINAL_FAILURE_TX_STATUSES:
                status_category = "rejected"
            else:
                status_category = "unknown_txStatus"

            return {"status_category": status_category, "tx_status": tx_status}

        except Exception as e:
            return {"status_category": "error", "error": str(e), "response": response}
