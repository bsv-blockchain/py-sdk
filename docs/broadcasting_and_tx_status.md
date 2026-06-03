# ARC Broadcasting and Transaction Status

_Applies to `bsv.broadcasters.arc` (`ARC` class). Written by Ken Sato
(Yenpoint), June 2026._

## What "Broadcast Success" Means

`BroadcastResponse(status="success")` means ARC has accepted the transaction
for relay to the BSV network. It does **not** mean the transaction has been
mined into a block or reached finality.

Transactions that are explicitly rejected at broadcast time are returned as
`BroadcastFailure(status="failure")`.

Because a transaction's final state is not determined until it is included in a
block, applications must decide how to handle the interim period after
broadcast. The SDK provides `ARC.categorize_transaction_status()` as a helper
for this decision.

For categories where the status is not yet final (`progressing`, `warning`),
we recommend polling via `ARC.check_transaction_status()` or using ARC's
callback feature (`ARCConfig.callback_url`) to wait for a definitive outcome.

## Status Categories

`categorize_transaction_status()` maps the `txStatus` value returned by ARC
into one of the following categories:

| Category           | Meaning                                                                                                                                                                | Suggested Action                                                 |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `mined`            | The transaction is already included in a block.                                                                                                                        | Treat as final.                                                  |
| `0confirmation`    | The transaction has been seen on the network and no competing transactions have been detected at this time.                                                            | Generally acceptable for low-value or low-risk transactions.     |
| `progressing`      | The transaction is propagating through the network. No problems have been detected, but its status is not yet determined.                                              | Wait — poll or use callbacks to monitor for a definitive status. |
| `warning`          | A condition requiring attention has been detected: competing transactions exist, the transaction was only seen in a stale block, a parent transaction is missing, etc. | The status is not yet final. Continue monitoring.                |
| `rejected`         | The transaction has been explicitly rejected by ARC.                                                                                                                   | Treat as failed.                                                 |
| `unknown_txStatus` | ARC returned a `txStatus` value that the SDK does not recognize.                                                                                                       | Treat as an exceptional case — log for investigation.            |
| `error`            | No `txStatus` was present, the response was malformed, or another error occurred.                                                                                      | Handle as an error.                                              |

### Finality

Of these categories, `mined`, `rejected`, and `error` represent outcomes that
are essentially settled — they are unlikely to change.

`0confirmation` is also reliable for most practical purposes: under BSV's
First Seen Rule, a transaction seen on the network without competing
transactions will typically be included in the next block.

`progressing` and `warning` are transient states. The transaction's fate is
still open, and further monitoring is required before an application can act
on it with confidence.

`unknown_txStatus` is a defensive catch-all for forward compatibility with
future ARC status values.

## Tip: Match Confirmation Depth to Transaction Value

> Transaction finality on a blockchain is probabilistic — match your
> confirmation requirements to what is at stake. A 10-cent micropayment
> can be accepted at `0confirmation`; a million-dollar transfer should
> wait for multiple block confirmations.

The status categories above are building blocks for implementing your own
acceptance policy.
