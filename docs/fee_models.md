# Fee Models

The SDK exposes two fee calculation helpers: the simple
`SatoshisPerKilobyte` model and the new `LivePolicy` model that mirrors the
behaviour of the TypeScript SDK. This document focuses on `LivePolicy`, which
retrieves fee rates from the ARC policy API before computing the transaction
fee.

## LivePolicy

`LivePolicy` subclasses `SatoshisPerKilobyte` so it reuses the same byte-size
estimation logic while sourcing the sat/kB rate dynamically. A singleton helper
is provided so consumers can share the cached rate across transactions.

```python
from bsv.fee_models.live_policy import LivePolicy

policy = LivePolicy.get_instance()
tx.fee(policy)
```

### Configuration

```python
LivePolicy(
    cache_ttl_ms: int = 5 * 60 * 1000,
    arc_policy_url: Optional[str] = "https://arc.gorillapool.io/v1/policy",
    fallback_sat_per_kb: int = 1,
    request_timeout: Optional[int] = 30,
    api_key: Optional[str] = None,
)
```

- `cache_ttl_ms`: Milliseconds a fetched rate remains valid. Subsequent calls
  within the TTL reuse the cached value instead of re-querying ARC.
- `arc_policy_url`: Override the ARC policy endpoint. Defaults to GorillaPool's
  public service but honours the `BSV_PY_SDK_ARC_POLICY_URL` environment
  variable when set.
- `fallback_sat_per_kb`: Fee to use when the API response cannot be parsed or
  the network request fails. The default respects the
  `TRANSACTION_FEE_RATE` constant via the `Transaction.fee()` helper.
- `request_timeout`: Timeout passed to `requests.get`. Defaults to
  `HTTP_REQUEST_TIMEOUT` from `bsv.constants` (30 seconds by default).
- `api_key`: Optional token added as the `Authorization` header. You can also
  supply it through the `BSV_PY_SDK_ARC_POLICY_API_KEY` environment variable.

### Behaviour

* On a successful fetch, `LivePolicy` caches the sat/kB rate for the configured
  TTL.
* If ARC returns an error or an unexpected payload, the model logs a warning,
  falls back to the most recent cached value when available, otherwise uses the
  configured fallback rate.
* The singleton returned by `LivePolicy.get_instance()` stores cache data in a
  process-wide shared instance, making it suitable for repeated
  `Transaction.fee()` calls.

### Example Usage

```python
from bsv.transaction import Transaction
from bsv.fee_models.live_policy import LivePolicy

tx = Transaction(...)

# Use the shared singleton (default behaviour of Transaction.fee()).
tx.fee(LivePolicy.get_instance())

# Or create a custom policy with a shorter cache TTL and private endpoint.
policy = LivePolicy(
    cache_ttl_ms=60_000,
    arc_policy_url="https://arc.example.com/v1/policy",
    api_key="Bearer <token>"
)
tx.fee(policy)
```

