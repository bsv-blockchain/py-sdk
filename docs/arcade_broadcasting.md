# Arcade Broadcasting

_Applies to `bsv.broadcasters.arcade` (`Arcade` class)._

Arcade ([bsv-blockchain/arcade](https://github.com/bsv-blockchain/arcade)) is
the Teranode-native, ARC-compatible transaction broadcaster. The `Arcade`
class is a port of the TypeScript wallet-toolbox `Arcade` implementation,
adapted to the py-sdk `Broadcaster` interface.

`Arcade` is deliberately a separate, self-contained class — not a subclass of
`ARC` — mirroring the TS design decision that the audited ARC transport is
never altered. It is ARC-compatible on configuration and response handling,
but differs on the points listed below.

## Quick Start

```python
from bsv.broadcasters import Arcade, ArcadeConfig

# Simplest form (mainnet public endpoint)
arcade = Arcade("https://arcade-v2-us-1.bsvblockchain.tech")

# With configuration
arcade = Arcade(
    "https://arcade-v2-us-1.bsvblockchain.tech",
    ArcadeConfig(
        api_key="...",                            # Authorization: Bearer header
        callback_url="https://your.app/ingest",   # webhook for status updates
        callback_token="...",                     # scopes SSE/webhook events
    ),
)

# Async broadcast
result = await tx.broadcast(arcade)

# Sync broadcast
result = arcade.sync_broadcast(tx, timeout=30)
```

As with `ARC`, a `BroadcastResponse(status="success")` means Arcade accepted
the transaction for validation and propagation (HTTP 202) — it does **not**
mean the transaction is mined or final. See
[broadcasting_and_tx_status.md](broadcasting_and_tx_status.md) for the general
model; the notes below cover where Arcade deviates.

There is no public testnet endpoint. Passing a string as the second
constructor argument treats it as an API key, same as `ARC`.

## Differences from ARC

| | ARC | Arcade |
| --- | --- | --- |
| Submit endpoint | `POST {url}/v1/tx` | `POST {url}/tx` (no `/v1` prefix) |
| Status endpoint | `GET {url}/v1/tx/{txid}` | `GET {url}/tx/{txid}` |
| Submission encoding | raw / EF / BEEF V1 (configurable via `format`) | EF preferred, raw hex fallback — **BEEF is rejected** |
| Success response | HTTP 200 | HTTP 202 with `{"txid", "status": 202, "txStatus"}` |
| Duplicate submit | — | HTTP 202 echoing the transaction's **current** status |
| HTTP 400 | various | **terminal validation failure** — retrying anywhere is pointless |
| Error body | RFC 7807-style (`detail`, `title`) | flat `{"error": ..., "reason": ...}` |
| `DOUBLE_SPEND_ATTEMPTED` | may still resolve | **terminal** |

### Submission encoding

Arcade's `/tx` parser rejects BEEF and runs fee/script validation that needs
each input's source output (satoshis + locking script). Extended Format (EF)
carries that data inline, so `Arcade` always submits
`{"rawTx": tx.to_ef().hex()}` when every input has its `source_transaction`
set. When source transactions are missing it falls back to plain raw hex,
which Arcade also accepts if it can resolve the parents itself. There is no
`format` option — unlike `ARCConfig`, `ArcadeConfig` intentionally omits it.

### Terminal statuses on a successful HTTP response

An idempotent re-submit returns HTTP 202 with the transaction's current
status, which can already be terminal. `Arcade.broadcast()` therefore returns
a `BroadcastFailure` (code `ARCADE_TX_STATUS`) when the 202 body carries
`REJECTED` or `DOUBLE_SPEND_ATTEMPTED`, even though the HTTP request itself
succeeded.

### HTTP 400 is terminal

A 400 means Arcade validated the transaction and rejected it permanently (a
`REJECTED` record is persisted server-side). The returned `BroadcastFailure`
has `code="400"` and `more={"terminal": True, ...}` so callers can distinguish
it from transient failures (408/429/503/5xx) where retrying or failing over to
another broadcaster makes sense.

## Transaction Status

`Arcade.check_transaction_status(txid)` queries `GET /tx/{txid}` and returns
the same shape as `ARC.check_transaction_status()` (plus `merklePath` — a
hex-encoded BUMP once the transaction is mined).

Possible `txStatus` values:

```
UNKNOWN, RECEIVED, SENT_TO_NETWORK, ACCEPTED_BY_NETWORK, SEEN_ON_NETWORK,
SEEN_MULTIPLE_NODES, DOUBLE_SPEND_ATTEMPTED, REJECTED, PENDING_RETRY,
STUMP_PROCESSING, MINED, IMMUTABLE
```

Terminal: `REJECTED`, `DOUBLE_SPEND_ATTEMPTED`, `MINED`, `IMMUTABLE`.

`Arcade.categorize_transaction_status(response)` maps these into the same
category vocabulary as ARC's helper, with Arcade-specific membership:

| Category | Arcade statuses |
| --- | --- |
| `mined` | `MINED`, `IMMUTABLE` |
| `0confirmation` | `SEEN_ON_NETWORK`, `SEEN_MULTIPLE_NODES` (no competing txs) |
| `warning` | `SEEN_ON_NETWORK` / `SEEN_MULTIPLE_NODES` with `competingTxs` |
| `progressing` | `UNKNOWN`, `RECEIVED`, `SENT_TO_NETWORK`, `ACCEPTED_BY_NETWORK`, `PENDING_RETRY`, `STUMP_PROCESSING` |
| `rejected` | `REJECTED`, `DOUBLE_SPEND_ATTEMPTED` — both terminal in Arcade |
| `unknown_txStatus` / `error` | as for ARC |

Note the difference from ARC: `DOUBLE_SPEND_ATTEMPTED` categorizes as
`rejected` (terminal), not `warning`.

## Headers and Callbacks

`Arcade` sends the same headers as `ARC` (`Content-Type`, `XDeployment-ID`,
optional `Authorization`, `X-CallbackUrl`, `X-CallbackToken`, plus any
`ArcadeConfig.headers`). Of these, Arcade's submit endpoint currently honors
only `X-CallbackUrl` and `X-CallbackToken`; the rest are ignored server-side
but harmless (and `Authorization` may matter for proxied deployments).

- `callback_url` — Arcade POSTs status updates to this webhook.
- `callback_token` — a stable per-wallet token that scopes which
  transactions' events are delivered to your webhook and SSE stream
  (`GET /events?callbackToken=...`, served by Arcade's SSE service).

ARC's `X-WaitFor` / `X-WaitForStatus` blocking-wait headers are not supported
by Arcade; `Arcade` performs no wait-related timeout adjustment.

## Related

- [broadcasting_and_tx_status.md](broadcasting_and_tx_status.md) — general
  broadcast-success semantics and status-category handling (ARC-focused).
- py-wallet-toolbox `docs/ARCADE.md` — the wallet-toolbox `Arcade` provider
  (multi-provider failover, BEEF→EF handling, SSE monitor task). That
  provider is an independent implementation; this class is the low-level
  `Broadcaster` for direct `tx.broadcast()` use.
