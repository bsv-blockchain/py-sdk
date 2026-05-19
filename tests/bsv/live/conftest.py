"""Shared fixtures and helpers for mocked live tests."""

import asyncio
import os
import time
from collections.abc import Awaitable, Callable

import aiohttp
import pytest

from bsv.broadcasters import default_broadcaster
from bsv.broadcasters.broadcaster import Broadcaster, BroadcastFailure, BroadcastResponse
from bsv.chaintracker import ChainTracker
from bsv.constants import SIGHASH, OpCode
from bsv.fee_models import SatoshisPerKilobyte
from bsv.hash import hash160
from bsv.keys import PrivateKey
from bsv.script.script import Script
from bsv.script.spend import Spend
from bsv.script.type import P2PKH, to_unlock_script_template
from bsv.transaction import Transaction
from bsv.transaction_input import TransactionInput
from bsv.transaction_output import TransactionOutput
from bsv.utils import encode_pushdata

# ---------------------------------------------------------------------------
# Live network configuration (testnet / mainnet broadcast tests)
# ---------------------------------------------------------------------------

FUNDED_TESTNET_WIF = os.environ.get("FUNDED_TESTNET_WIF")
FUNDED_MAINNET_WIF = os.environ.get("FUNDED_MAINNET_WIF")

_LIVE_DIR = os.path.dirname(__file__)
WOC_API_TESTNET = "https://api.whatsonchain.com/v1/bsv/test"
WOC_API_MAINNET = "https://api.whatsonchain.com/v1/bsv/main"
UTXO_POOL_TESTNET_FILE = os.path.join(_LIVE_DIR, ".utxo_pool.json")
UTXO_POOL_MAINNET_FILE = os.path.join(_LIVE_DIR, ".utxo_pool_mainnet.json")
WOC_EXPLORER_TESTNET_TX = "https://test.whatsonchain.com/tx"
WOC_EXPLORER_MAINNET_TX = "https://whatsonchain.com/tx"


def live_utxo_skip_woc_prune() -> bool:
    """When True, :meth:`UTXOManager.prune_pool_to_chain_unspent` is a no-op (offline / flaky WoC)."""
    return os.environ.get("LIVE_UTXO_SKIP_WOC_PRUNE", "").strip().lower() in ("1", "true", "yes")


def broadcast_failure_indicates_spent_input(result: object) -> bool:
    """True if a failed broadcast means the input UTXO is gone (already spent or unknown on-chain).

    In that case the pooled UTXO must **not** be returned to :attr:`UTXOManager.utxos` — doing so
    would poison the pool (the previous implementation always :meth:`return_utxo` on failure).

    WoC / node error text varies; we match common substrings. Duplicate / already-in-mempool
    relay messages are excluded.
    """
    parts: list[str] = []
    if isinstance(result, str):
        parts.append(result)
    else:
        for attr in ("description", "message", "code"):
            v = getattr(result, attr, None)
            if v is not None and str(v).strip():
                parts.append(str(v))
    text = " ".join(parts).lower()
    if not text.strip():
        return False
    if any(
        d in text
        for d in (
            "already in the mempool",
            "already in mempool",
            "txn-already-in-mempool",
        )
    ):
        return False
    markers = (
        "already been spent",
        "already spent",
        "inputs missing or spent",
        "missingorspent",
        "bad-txns-inputs-missingorspent",
        "missing inputs",
        "inputs missing",
        "txn-mempool-conflict",
        "missing inputs or spent",
        "input not found",
        "unknown utxo",
        "utxo not found",
        "invalid utxo",
        "double spend",
        "double-spend",
        "double_spend",
        "double_spend_attempted",
    )
    return any(m in text for m in markers)


# GorillaPool ARC
ARC_API_TESTNET_BASE = "https://testnet.arc.gorillapool.io"
ARC_API_MAINNET_BASE = "https://arc.gorillapool.io"
# TAAL ARC (https://docs.taal.com/core-products/transaction-processing/arc-endpoints)
ARC_API_TESTNET_TAAL_BASE = "https://arc-test.taal.com"
ARC_API_MAINNET_TAAL_BASE = "https://arc.taal.com"


def live_arc_base_url(network_label: str) -> str:
    """Base URL for ARC (no ``/v1`` suffix); must match session broadcaster host for GET polling.

    Env (first match wins):
      LIVE_ARC_BASE_URL — override for both networks
      LIVE_ARC_BASE_URL_TESTNET / LIVE_ARC_BASE_URL_MAINNET — per-network override
      LIVE_ARC_BACKEND — ``taal`` (default) or ``gorillapool`` (no TAAL token on public testnet).

    TAAL bearer (any one): ``TEST_TAAL_API_KEY`` / ``MAIN_TAAL_API_KEY`` (wallet-toolbox names),
    ``TAAL_TESTNET_APIKEY`` / ``TAAL_MAINNET_APIKEY``, or ``ARC_API_KEY``.
    """
    nl = (network_label or "testnet").strip().lower()
    override = os.environ.get("LIVE_ARC_BASE_URL", "").strip()
    if override:
        return override.rstrip("/")
    if nl == "mainnet":
        u = os.environ.get("LIVE_ARC_BASE_URL_MAINNET", "").strip()
        if u:
            return u.rstrip("/")
    else:
        u = os.environ.get("LIVE_ARC_BASE_URL_TESTNET", "").strip()
        if u:
            return u.rstrip("/")
    backend = os.environ.get("LIVE_ARC_BACKEND", "taal").strip().lower()
    if backend in ("gorillapool", "gorilla", "gp"):
        return ARC_API_MAINNET_BASE if nl == "mainnet" else ARC_API_TESTNET_BASE
    return ARC_API_MAINNET_TAAL_BASE if nl == "mainnet" else ARC_API_TESTNET_TAAL_BASE


def _live_arc_api_key_for_network(network_label: str) -> str | None:
    """Bearer token for ARC when configured (TAAL: prefer TAAL_* or ARC_API_KEY)."""
    nl = (network_label or "testnet").strip().lower()
    backend = os.environ.get("LIVE_ARC_BACKEND", "taal").strip().lower()
    if backend in ("gorillapool", "gorilla", "gp"):
        return os.environ.get("GORILLAPOOL_ARC_API_KEY", "").strip() or None
    raw = os.environ.get("ARC_API_KEY", "").strip() or os.environ.get("TAAL_API_KEY", "").strip()
    if raw:
        return raw
    if nl == "mainnet":
        return (
            os.environ.get("TAAL_MAINNET_APIKEY", "").strip()
            or os.environ.get("TAAL_MAINNET_API_KEY", "").strip()
            or os.environ.get("MAIN_TAAL_API_KEY", "").strip()
            or None
        )
    return (
        os.environ.get("TAAL_TESTNET_APIKEY", "").strip()
        or os.environ.get("TAAL_TESTNET_API_KEY", "").strip()
        or os.environ.get("TEST_TAAL_API_KEY", "").strip()
        or None
    )


def live_require_mined_enabled(verify_mined: bool | None = None) -> bool:
    """When True, live tests also poll until tx is MINED (or WoC confirms).

    Default is False. Normal live runs only wait for ``SEEN_ON_NETWORK`` (ARC headers + GET
    poll in :meth:`UTXOManager._ensure_arc_seen_on_network`). Set ``LIVE_REQUIRE_MINED=1``
    to add an additional wait for mined settlement (slow).
    """
    if verify_mined is not None:
        return verify_mined
    v = os.environ.get("LIVE_REQUIRE_MINED", "").strip().lower()
    return v in ("1", "true", "yes", "on")


def live_tx_confirm_timeout_sec() -> float:
    raw = os.environ.get("LIVE_TX_CONFIRM_TIMEOUT_SEC", "300")
    try:
        return float(raw)
    except ValueError:
        return 300.0


def arc_seen_poll_timeout_sec() -> float:
    """Max seconds to poll ARC GET until SEEN_ON_NETWORK / MINED after a POST that stopped early."""
    raw = os.environ.get(
        "ARC_SEEN_POLL_TIMEOUT_SEC",
        os.environ.get("ARC_X_MAX_TIMEOUT", "3"),
    )
    try:
        return float((raw or "3").strip() or "3")
    except ValueError:
        return 3.0


def arc_fanout_seen_poll_timeout_sec() -> float:
    """Max seconds for fan-out visibility wait (ARC SEEN/MINED or WoC /tx/raw mempool probe).

    If ``LIVE_FANOUT_SEEN_POLL_TIMEOUT_SEC`` is unset, uses at least 30s (and at least
    :func:`arc_seen_poll_timeout_sec`) so large fan-outs and ARC/WoC lag can resolve; per-test
    polls stay on ``ARC_SEEN_POLL_TIMEOUT_SEC`` only. Set ``LIVE_FANOUT_SEEN_POLL_TIMEOUT_SEC=3`` to
    cap fan-out the same as test txs.
    """
    raw = os.environ.get("LIVE_FANOUT_SEEN_POLL_TIMEOUT_SEC", "").strip()
    if raw:
        try:
            return float(raw)
        except ValueError:
            pass
    base = arc_seen_poll_timeout_sec()
    return max(base, 30.0)


def live_arc_seen_woc_fallback_enabled() -> bool:
    """When True (default), ARC ``SEEN_ON_NETWORK`` wait also succeeds via WhatsOnChain.

    Uses GET ``/tx/{txid}`` / ``/hex`` when indexed, and POST ``/tx/raw`` with the same hex when
    WoC reports duplicate / ``txn-mempool-conflict`` (mempool visibility without confirmations).
    Fan-out strict wait still uses only POST ``/tx/raw`` for that (not indexer GET). Set
    ``LIVE_ARC_SEEN_WOC_FALLBACK=0`` for ARC-only everywhere.
    """
    if os.environ.get("LIVE_ARC_SEEN_WOC_FALLBACK", "").strip().lower() in (
        "0",
        "false",
        "no",
        "off",
    ):
        return False
    return True


def live_broadcast_arc_wait_headers() -> dict[str, str]:
    """ARC headers so POST /v1/tx requests ``SEEN_ON_NETWORK`` (GorillaPool / BSV ARC).

    Sends ``X-WaitForStatus: 8``. Some deployments still return an earlier ``txStatus`` in
    the POST body (e.g. ``ANNOUNCED_TO_NETWORK``); :meth:`UTXOManager._ensure_arc_seen_on_network`
    then polls GET /v1/tx until ``SEEN_ON_NETWORK`` or ``MINED``.

    Env:
      LIVE_ARC_SKIP_WAIT_FOR_SEEN=1 — omit wait headers and GET enforcement (faster).
      ARC_SEEN_POLL_TIMEOUT_SEC — max seconds for that GET poll (default: same as ARC_X_MAX_TIMEOUT or 3).
    """
    if os.environ.get("LIVE_ARC_SKIP_WAIT_FOR_SEEN", "").strip().lower() in (
        "1",
        "true",
        "yes",
    ):
        return {}
    return {"X-WaitForStatus": "8"}


def _arc_with_broadcast_test_tx_headers(bc: Broadcaster) -> Broadcaster:
    """Merge :func:`live_broadcast_arc_wait_headers` into an ARC instance; pass through otherwise."""
    extra = live_broadcast_arc_wait_headers()
    if not extra:
        return bc
    from bsv.broadcasters.arc import ARC, ARCConfig

    if not isinstance(bc, ARC):
        return bc
    merged = {**(bc.headers or {}), **extra}
    config = ARCConfig(
        api_key=bc.api_key,
        http_client=bc.http_client,
        sync_http_client=bc.sync_http_client,
        deployment_id=bc.deployment_id,
        callback_url=bc.callback_url,
        callback_token=bc.callback_token,
        headers=merged,
    )
    return ARC(bc.URL, config)


def _print_live_broadcast_result(bc: Broadcaster, result: object, *, kind: str) -> None:
    """Echo broadcaster return value (success message mirrors ARC POST body for ARC)."""
    from bsv.broadcasters.arc import ARC

    tag = "ARC" if isinstance(bc, ARC) else bc.__class__.__name__
    st = getattr(result, "status", None)
    txid = getattr(result, "txid", None)
    if st == "success":
        msg = (getattr(result, "message", None) or "").strip()
        extra = f" message={msg!r}" if msg else ""
        print(f"\n  [{tag} {kind}] status=success txid={txid}{extra}")
        return
    code = getattr(result, "code", "")
    desc = getattr(result, "description", "")
    more = getattr(result, "more", None)
    print(f"\n  [{tag} {kind}] status={st!r} code={code!r} txid={txid!r}")
    print(f"  [{tag} {kind}] detail: {desc}")
    if more:
        print(f"  [{tag} {kind}] more: {more!r}")


def _ledger_diagnostics_payload(
    result: object,
    *,
    woc_http_detail: dict | None,
    visibility_poll_error: str | None,
) -> dict:
    """Structured ARC POST / WoC GET / client-transport info for the live Markdown report."""
    out: dict = {}
    st = getattr(result, "status", None)
    if st != "success":
        code = getattr(result, "code", None)
        desc = getattr(result, "description", None)
        parts = [str(code) if code is not None else "", str(desc) if desc is not None else ""]
        msg = ": ".join(p for p in parts if p).strip(": ")
        if msg:
            out["broadcast_error"] = msg
    more = getattr(result, "more", None) or {}
    extra = getattr(result, "extra", None) or {}
    if st == "success":
        if extra.get("arc_json") is not None:
            out["arc_http_response"] = extra["arc_json"]
        if extra.get("http_status") is not None:
            out["arc_http_status"] = extra["http_status"]
    else:
        if more.get("arc_json") is not None:
            out["arc_http_response"] = more["arc_json"]
        if more.get("http_status") is not None:
            out["arc_http_status"] = more["http_status"]
        tran = {k: more[k] for k in ("exception_type", "exception") if more.get(k)}
        if tran:
            out["arc_client_transport"] = tran
    if woc_http_detail:
        out["woc_probe_http"] = woc_http_detail
    if visibility_poll_error:
        out["visibility_poll_error"] = visibility_poll_error
    return out


def format_broadcast_diagnostic(result: object) -> str:
    """Rich diagnostic string for assert messages — classifies ARC rejection vs spent input vs unknown."""
    status = getattr(result, "status", None)
    txid = getattr(result, "txid", None)
    code = getattr(result, "code", None)
    desc = getattr(result, "description", None)
    msg = getattr(result, "message", None)
    more = getattr(result, "more", None)

    if result is None:
        return "No broadcast attempt made"

    if status == "success":
        return f"Broadcast succeeded: txid={txid} message={msg}"

    if code == "ARC_TX_STATUS":
        diagnosis = f"ARC terminal status ({(desc or '').split(':')[0].strip()})"
    elif broadcast_failure_indicates_spent_input(result):
        diagnosis = "spent/missing input"
    elif code and str(code).isdigit() and int(code) >= 400:
        diagnosis = f"ARC HTTP {code}"
    else:
        diagnosis = "unknown failure"

    lines = [f"BROADCAST FAILED — {diagnosis}"]
    lines.append(f"  txid={txid} code={code}")
    if desc:
        lines.append(f"  description: {desc}")
    if msg:
        lines.append(f"  message: {msg}")
    if more:
        lines.append(f"  more: {more}")
    return "\n".join(lines)


def _arc_post_first_tx_status(message: str | None) -> str | None:
    """First token of ARC :class:`BroadcastResponse` message (txStatus from POST body)."""
    if not message:
        return None
    parts = message.split()
    return parts[0] if parts else None


def _print_live_tx_raw_hex(tx: Transaction, *, kind: str) -> None:
    """Print standard raw transaction hex (``tx.hex()``), not EF wire form."""
    print(f"\n  [rawTx hex {kind}] {tx.hex()}")


def _broadcast_failure_is_transient_network(result: object) -> bool:
    """True for DNS / TCP flakiness where retrying :meth:`Broadcaster.broadcast` may succeed."""
    if getattr(result, "status", None) == "success":
        return False
    desc = (getattr(result, "description", "") or "").lower()
    more = getattr(result, "more", None)
    if not isinstance(more, dict):
        more = {}
    exc_t = (more.get("exception_type") or "").lower()
    exc_m = (more.get("exception") or "").lower()
    blob = f"{desc} {exc_t} {exc_m}"
    markers = (
        "name resolution",
        "temporary failure",
        "cannot connect to host",
        "connection refused",
        "connection reset",
        "timed out",
        "timeout",
        "network is unreachable",
        "no route to host",
        "clientconnector",
        "server disconnected",
        "broken pipe",
    )
    return any(m in blob for m in markers)


async def _broadcast_with_transient_retries(
    bc: Broadcaster,
    tx: Transaction,
    *,
    label: str = "ARC tx",
) -> BroadcastResponse | BroadcastFailure:
    """Call ``bc.broadcast``; retry on transient connect/DNS errors (env-tunable)."""
    raw_max = os.environ.get("LIVE_ARC_BROADCAST_RETRIES", "5").strip() or "5"
    try:
        max_r = int(raw_max)
    except ValueError:
        max_r = 5
    max_r = max(1, min(max_r, 20))
    raw_delay = os.environ.get("LIVE_ARC_BROADCAST_RETRY_DELAY_SEC", "1.0").strip() or "1.0"
    try:
        base_delay = float(raw_delay)
    except ValueError:
        base_delay = 1.0
    last: BroadcastResponse | BroadcastFailure | None = None
    for attempt in range(max_r):
        last = await bc.broadcast(tx)
        if getattr(last, "status", None) == "success":
            return last
        if not _broadcast_failure_is_transient_network(last):
            return last
        if attempt >= max_r - 1:
            return last
        delay = min(base_delay * (2**attempt), 30.0)
        hint = (getattr(last, "description", None) or "")[:90]
        if len(getattr(last, "description", None) or "") > 90:
            hint += "…"
        print(f"\n  [{label}] transient network error ({hint}); retry {attempt + 2}/{max_r} in {delay:.1f}s")
        await asyncio.sleep(delay)
    assert last is not None
    return last


async def _recover_arc_double_spend_if_visible_on_woc(
    woc_api_base: str,
    bc: Broadcaster,
    tx: Transaction,
    result: BroadcastResponse | BroadcastFailure,
) -> BroadcastResponse | BroadcastFailure:
    """If ARC POST failed with DOUBLE_SPEND_ATTEMPTED but WoC sees the tx, treat as success.

    ARC may report a terminal double-spend while the same tx is already visible to WhatsOnChain
    (mempool/indexer); :meth:`UTXOManager.broadcast_test_tx` uses this before printing results.
    """
    from bsv.broadcasters.arc import ARC

    if isinstance(result, BroadcastResponse) and result.status == "success":
        return result
    if not isinstance(result, BroadcastFailure):
        return result
    if not isinstance(bc, ARC):
        return result
    if getattr(result, "code", None) != "ARC_TX_STATUS":
        return result
    desc = (getattr(result, "description", "") or "").upper()
    if "DOUBLE_SPEND_ATTEMPTED" not in desc:
        return result
    rid = getattr(result, "txid", None)
    tid = tx.txid()
    if not rid or str(rid).lower() != tid.lower():
        return result
    if not live_arc_seen_woc_fallback_enabled():
        return result
    woc = (woc_api_base or "").strip()
    if not woc:
        return result

    from .arc_verify import woc_post_raw_tx_mempool_probe, woc_tx_observable_via_get

    async with aiohttp.ClientSession() as session:
        if await woc_post_raw_tx_mempool_probe(session, woc, tx.hex()):
            print(
                "\n  [ARC tx] DOUBLE_SPEND_ATTEMPTED from ARC, but WoC mempool POST accepts / duplicate — "
                "treating as success"
            )
            return BroadcastResponse(
                status="success",
                txid=tid,
                message="WOC_VISIBLE_AFTER_ARC_DOUBLE_SPEND",
            )
        reason, ok = await woc_tx_observable_via_get(session, woc, tid)
        if ok and reason:
            print(f"\n  [ARC tx] DOUBLE_SPEND_ATTEMPTED from ARC, but WoC sees tx ({reason}) — " "treating as success")
            return BroadcastResponse(
                status="success",
                txid=tid,
                message=f"WOC_VISIBLE_AFTER_ARC_DOUBLE_SPEND {reason}",
            )
    return result


# ---------------------------------------------------------------------------
# Mock implementations
# ---------------------------------------------------------------------------


class MockBroadcaster(Broadcaster):
    """Captures transactions instead of broadcasting to the network."""

    def __init__(self):
        super().__init__()
        self.transactions: list[Transaction] = []

    async def broadcast(self, transaction):
        self.transactions.append(transaction)
        return BroadcastResponse(
            status="success",
            txid=transaction.txid(),
            message="mock broadcast",
        )


class MockChainTracker(ChainTracker):
    """Always-valid chain tracker for testing."""

    async def is_valid_root_for_height(self, root: str, height: int) -> bool:
        return True

    async def current_height(self) -> int:
        return 943_816


# ---------------------------------------------------------------------------
# Deterministic key fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def priv_key():
    return PrivateKey("L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi")


@pytest.fixture
def priv_key2():
    return PrivateKey("L32Mf2qU7BLmPmnbs943EYWRv4EUpqnFxkViinPMYesxWLnL6DTA")


@pytest.fixture
def priv_key3():
    return PrivateKey("L1DkuXRTu3cGZAmJCDw2TWAoEaRKesq2sZUGzUmbYExgDwhQWe5T")


@pytest.fixture
def mock_broadcaster():
    return MockBroadcaster()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def build_funding_tx(locking_script: Script, satoshis: int = 10_000, version: int = 1) -> Transaction:
    """Create a synthetic funding transaction with one output.

    The funding tx itself does not need to be valid — it just provides
    a UTXO for a spending transaction to reference via source_transaction.
    """
    return Transaction(
        tx_inputs=[
            TransactionInput(
                source_txid="00" * 32,
                source_output_index=0,
                unlocking_script=Script(),
                sequence=0xFFFFFFFF,
            )
        ],
        tx_outputs=[
            TransactionOutput(locking_script=locking_script, satoshis=satoshis),
        ],
        version=version,
    )


def validate_spend(tx: Transaction, input_index: int) -> bool:
    """Validate a single input of a signed transaction via Spend.validate()."""
    inp = tx.inputs[input_index]

    other_inputs = []
    for j, other in enumerate(tx.inputs):
        if j != input_index:
            other_inputs.append(
                TransactionInput(
                    source_txid=other.source_txid,
                    source_output_index=other.source_output_index,
                    unlocking_script=other.unlocking_script,
                    sequence=other.sequence,
                    sighash=other.sighash,
                )
            )
            # Carry over satoshis and locking_script for preimage computation
            other_inputs[-1].satoshis = other.satoshis
            other_inputs[-1].locking_script = other.locking_script

    spend = Spend(
        {
            "sourceTXID": inp.source_txid,
            "sourceOutputIndex": inp.source_output_index,
            "sourceSatoshis": inp.satoshis,
            "lockingScript": inp.locking_script,
            "transactionVersion": tx.version,
            "otherInputs": other_inputs,
            "outputs": tx.outputs,
            "inputIndex": input_index,
            "unlockingScript": inp.unlocking_script,
            "inputSequence": inp.sequence,
            "lockTime": tx.locktime,
        }
    )
    return spend.validate()


def validate_all_inputs(tx: Transaction) -> None:
    """Validate every input in a signed transaction via Spend."""
    for i in range(len(tx.inputs)):
        assert validate_spend(tx, i), f"Spend validation failed for input {i}"


def build_signed_tx(
    locking_script: Script,
    unlock_template,
    sighash: int = SIGHASH.ALL_FORKID,
    tx_version: int = 1,
    num_inputs: int = 1,
    num_outputs: int = 1,
    satoshis: int = 10_000,
) -> Transaction:
    """Build a transaction, sign it, validate every input, and return it.

    Args:
        locking_script: The locking script for each funding output.
        unlock_template: An UnlockingScriptTemplate class (not instance).
        sighash: Sighash flag for all inputs.
        tx_version: Transaction version (1 = legacy, 2 = Chronicle).
        num_inputs: Number of inputs to create.
        num_outputs: Number of outputs to create.
        satoshis: Satoshis per funding UTXO.
    """
    inputs = []
    for _ in range(num_inputs):
        funding_tx = build_funding_tx(locking_script, satoshis=satoshis)
        inputs.append(
            TransactionInput(
                source_transaction=funding_tx,
                source_output_index=0,
                unlocking_script_template=unlock_template,
                sequence=0xFFFFFFFF,
                sighash=SIGHASH(sighash),
            )
        )

    # Distribute satoshis across outputs (leave room for fee)
    total = satoshis * num_inputs
    per_output = (total - 500) // num_outputs  # 500 sat fee buffer
    outputs = [TransactionOutput(locking_script=locking_script, satoshis=per_output) for _ in range(num_outputs)]

    tx = Transaction(inputs, outputs, version=tx_version)
    tx.sign(bypass=False)
    validate_all_inputs(tx)
    return tx


def build_cross_config_tx(
    input_configs: list[tuple[Script, object, int]],
    spending_version: int = 1,
    funding_version: int = 1,
    satoshis: int = 10_000,
) -> Transaction:
    """Build a tx with per-input sighash and explicit funding/spending versions.

    Args:
        input_configs: List of (locking_script, unlock_template, sighash) per input.
        spending_version: Version of the spending transaction.
        funding_version: Version of the synthetic funding transactions.
        satoshis: Satoshis per funding UTXO.
    """
    inputs = []
    for lock, unlock, sh in input_configs:
        funding_tx = build_funding_tx(lock, satoshis=satoshis, version=funding_version)
        inputs.append(
            TransactionInput(
                source_transaction=funding_tx,
                source_output_index=0,
                unlocking_script_template=unlock,
                sequence=0xFFFFFFFF,
                sighash=SIGHASH(sh),
            )
        )

    total = satoshis * len(input_configs)
    outputs = [TransactionOutput(locking_script=input_configs[0][0], satoshis=total - 500)]

    tx = Transaction(inputs, outputs, version=spending_version)
    tx.sign(bypass=False)
    validate_all_inputs(tx)
    return tx


def custom_unlock(priv_key: PrivateKey, data_prefix_script: Script = None):
    """Create an UnlockingScriptTemplate that pushes optional data then <sig> <pubkey>.

    Use this for opcode tests where the unlocking script needs to push
    data items before the standard P2PKH signature + public key.
    """

    def sign(tx, input_index) -> Script:
        tx_input = tx.inputs[input_index]
        sighash = tx_input.sighash
        signature = priv_key.sign(tx.preimage(input_index))
        public_key = priv_key.public_key().serialize()
        sig_script = Script(encode_pushdata(signature + sighash.to_bytes(1, "little")) + encode_pushdata(public_key))
        if data_prefix_script:
            # Data goes AFTER sig+pubkey so it's on TOP of the stack
            # when the locking script starts executing
            return Script(sig_script.serialize() + data_prefix_script.serialize())
        return sig_script

    def estimated_unlocking_byte_length() -> int:
        return 200

    return to_unlock_script_template(sign, estimated_unlocking_byte_length)


def p2pkh_lock_with_prefix(prefix_asm: str, priv_key: PrivateKey) -> Script:
    """Build a locking script: {prefix opcodes} OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG.

    The prefix opcodes consume data items from the stack before P2PKH
    validation runs on the remaining <sig> <pubkey>.
    """
    pkh = hash160(priv_key.public_key().serialize())
    prefix = Script.from_asm(prefix_asm) if prefix_asm else Script()
    p2pkh_suffix = Script(
        OpCode.OP_DUP + OpCode.OP_HASH160 + encode_pushdata(pkh) + OpCode.OP_EQUALVERIFY + OpCode.OP_CHECKSIG
    )
    return Script(prefix.serialize() + p2pkh_suffix.serialize())


# ---------------------------------------------------------------------------
# Testnet fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def funded_key():
    """Funded testnet private key. Skips if FUNDED_TESTNET_WIF not set."""
    if not FUNDED_TESTNET_WIF:
        pytest.skip("FUNDED_TESTNET_WIF not set")
    return PrivateKey(FUNDED_TESTNET_WIF)


@pytest.fixture(scope="session")
def testnet_broadcaster():
    """ARC broadcaster for testnet with Chronicle script validation skip.

    Host comes from :func:`live_arc_base_url` (default TAAL testnet). Bearer from
    ``TEST_TAAL_API_KEY`` / ``TAAL_TESTNET_APIKEY`` / ``ARC_API_KEY``, or
    ``LIVE_ARC_BACKEND=gorillapool`` without a TAAL token.

    Uses ``X-SkipScriptValidation`` because some in-path validators reject Chronicle
    sighash even when the network accepts the tx.
    """
    from bsv.broadcasters.arc import ARC, ARCConfig

    base = live_arc_base_url("testnet")
    api_key = _live_arc_api_key_for_network("testnet")
    h = {"X-SkipScriptValidation": "true"}
    config = ARCConfig(api_key=api_key, headers=h) if api_key else ARCConfig(headers=h)
    return ARC(base, config)


@pytest.fixture(scope="session")
def woc_testnet_broadcaster():
    """WoC broadcaster for testnet — submits directly to the node.

    Use this for v2 transactions with non-push unlocking scripts that ARC
    rejects (error 463) but the node accepts under Chronicle rules.
    """
    from bsv.broadcasters.whatsonchain import WhatsOnChainBroadcaster

    return WhatsOnChainBroadcaster(network="test")


@pytest.fixture(scope="session")
def funded_mainnet_key():
    """Funded mainnet private key. Skips if FUNDED_MAINNET_WIF not set."""
    if not FUNDED_MAINNET_WIF:
        pytest.skip("FUNDED_MAINNET_WIF not set")
    return PrivateKey(FUNDED_MAINNET_WIF)


@pytest.fixture(scope="session")
def mainnet_broadcaster():
    """ARC broadcaster for mainnet; host from :func:`live_arc_base_url` (default TAAL).

    Bearer: ``MAIN_TAAL_API_KEY``, ``TAAL_MAINNET_APIKEY``, or ``ARC_API_KEY``.
    """
    from bsv.broadcasters.arc import ARC, ARCConfig

    base = live_arc_base_url("mainnet")
    api_key = _live_arc_api_key_for_network("mainnet")
    h = {"X-SkipScriptValidation": "true"}
    config = ARCConfig(api_key=api_key, headers=h) if api_key else ARCConfig(headers=h)
    return ARC(base, config)


@pytest.fixture(scope="session")
def woc_mainnet_broadcaster():
    """WhatsOnChain broadcaster for mainnet — node-direct submission."""
    from bsv.broadcasters.whatsonchain import WhatsOnChainBroadcaster

    return WhatsOnChainBroadcaster(network="main")


# ---------------------------------------------------------------------------
# UTXO Manager for live testnet / mainnet chaining
# ---------------------------------------------------------------------------


class UTXOManager:
    """Manages a pool of UTXOs from a fan-out transaction for live network tests.

    UTXOs are persisted to a JSON file so they survive across test runs.
    On first run, fetches a UTXO from WoC, creates a fan-out tx, and saves
    the resulting UTXOs. On subsequent runs, loads from the file and only
    re-fans-out if the pool is exhausted.

    Flow:
    1. Try to load persisted UTXOs from the pool file
    2. :meth:`prune_pool_to_chain_unspent` — drop entries not in WoC ``/address/.../unspent``
    3. If none available, fetch from WoC and fan-out
    4. Each test calls take_utxo() which also persists the updated pool
    """

    FEE_MODEL = SatoshisPerKilobyte(100)

    def __init__(
        self,
        funded_key: PrivateKey,
        broadcaster: Broadcaster,
        *,
        woc_api_base: str = WOC_API_TESTNET,
        pool_file: str | None = None,
        explorer_tx_base: str = WOC_EXPLORER_TESTNET_TX,
        network_label: str = "testnet",
        arc_base_url: str | None = None,
    ):
        self.key = funded_key
        self.broadcaster = broadcaster
        self.woc_api_base = woc_api_base.rstrip("/")
        if arc_base_url is not None:
            self.arc_base_url = arc_base_url.rstrip("/")
        else:
            self.arc_base_url = live_arc_base_url(network_label)
        self.pool_file = pool_file if pool_file is not None else UTXO_POOL_TESTNET_FILE
        self.explorer_tx_base = explorer_tx_base.rstrip("/")
        self.network_label = network_label
        self.p2pkh = P2PKH()
        self.lock_script = self.p2pkh.lock(self.key.address())
        self.utxos: list[tuple[Transaction, int, int]] = []  # (source_tx, vout, satoshis)
        self.broadcast_count = 0
        # Cache of tx hex -> Transaction for deserialized source txs
        self._tx_cache: dict[str, Transaction] = {}
        # WoC fan-out: cache parent txs by txid (multiple inputs may share a tx)
        self._fetched_tx_by_id: dict[str, Transaction] = {}
        # WoC visibility results for post-run summary
        self._woc_visibility_results: list[tuple[str, bool]] = []

    def _append_broadcast_ledger_row(
        self,
        *,
        broadcast_index: int,
        kind: str,
        tx: Transaction | None,
        result: object,
        arc_visibility: str | None,
        woc_visible: bool | None = None,
        woc_method: str | None = None,
        pool_outputs: int | None = None,
        raw_tx_hex: str | None = None,
        woc_http_detail: dict | None = None,
        visibility_poll_error: str | None = None,
    ) -> None:
        from .live_broadcast_ledger import append_row

        st = getattr(result, "status", None)
        msg = (getattr(result, "message", None) or "").strip()
        if len(msg) > 120:
            msg = msg[:117] + "..."
        txid = getattr(result, "txid", None)
        if not txid and tx is not None:
            txid = tx.txid()
        woc_probe = "—"
        if woc_visible is not None:
            woc_probe = ("yes" if woc_visible else "no") + (f" ({woc_method})" if woc_method else "")

        hex_out = raw_tx_hex
        if hex_out is None and tx is not None:
            hex_out = tx.hex()

        diag = _ledger_diagnostics_payload(
            result,
            woc_http_detail=woc_http_detail,
            visibility_poll_error=visibility_poll_error,
        )
        fail_note = diag.get("broadcast_error") or diag.get("visibility_poll_error")
        if not fail_note:
            fail_note = "—"

        append_row(
            {
                "broadcast_index": broadcast_index,
                "kind": kind,
                "txid": txid,
                "result_status": st,
                "message_summary": msg or "—",
                "arc_visibility": arc_visibility,
                "woc_probe": woc_probe,
                "failure_or_poll_note": fail_note,
                "inputs": len(tx.inputs) if tx is not None else "—",
                "outputs": len(tx.outputs) if tx is not None else "—",
                "pool_outputs": pool_outputs,
                "network_label": self.network_label,
                "raw_tx_hex": hex_out or "",
                "diagnostics": diag,
            }
        )

    async def _ensure_arc_seen_on_network(
        self,
        bc: Broadcaster,
        result: object,
        *,
        kind: str,
        raw_tx_hex: str | None = None,
        require_arc_seen_on_network: bool = False,
    ) -> str | None:
        """When live ARC wait headers are on but POST returns an earlier txStatus, poll until visible.

        Returns ARC/WoC visibility token (e.g. ``SEEN_ON_NETWORK``, ``WOC_MEMPOOL_POST``), the POST
        status when already terminal-visible, or ``None`` when polling was skipped.

        Fan-out uses ``require_arc_seen_on_network=True`` so the pool is only created after ARC
        reports ``SEEN_ON_NETWORK`` or ``MINED``, or WhatsOnChain POST ``/tx/raw`` reports the tx
        already in mempool (ARC may lag behind a manual rebroadcast). WoC indexer GET and ARC
        "progressing" shortcuts are still disabled for fan-out.
        """
        from bsv.broadcasters.arc import ARC

        if not isinstance(bc, ARC) or not live_broadcast_arc_wait_headers():
            return None
        if getattr(result, "status", None) != "success":
            return None
        st = _arc_post_first_tx_status(getattr(result, "message", None))
        if st in ("SEEN_ON_NETWORK", "MINED"):
            return st
        txid = getattr(result, "txid", None)
        if not txid:
            return None
        if kind == "fan-out":
            tmo = arc_fanout_seen_poll_timeout_sec()
        else:
            tmo = arc_seen_poll_timeout_sec()
        woc_fb = live_arc_seen_woc_fallback_enabled()
        if require_arc_seen_on_network:
            if woc_fb:
                wait_desc = "polling ARC for SEEN_ON_NETWORK or MINED; WoC POST /tx/raw if already in mempool"
            else:
                wait_desc = (
                    "polling ARC only until SEEN_ON_NETWORK or MINED "
                    "(set LIVE_ARC_SEEN_WOC_FALLBACK=1 to allow WoC /tx/raw mempool probe)"
                )
        else:
            extra = ""
            if woc_fb:
                extra = " + WhatsOnChain (GET and/or POST /tx/raw mempool probe)"
            wait_desc = (
                f"polling ARC + WoC until visible (SEEN_ON_NETWORK/MINED, progressing, or mempool/indexer){extra}"
            )
        print(f"\n  [ARC {kind}] POST txStatus={st!r}; {wait_desc} (timeout {tmo}s)…")
        from .arc_verify import wait_until_arc_tx_seen_on_network

        final = await wait_until_arc_tx_seen_on_network(
            self.arc_base_url,
            txid,
            timeout_sec=tmo,
            woc_api_base=self.woc_api_base if woc_fb else None,
            raw_tx_hex=raw_tx_hex if woc_fb else None,
            require_arc_seen_on_network=require_arc_seen_on_network,
        )
        print(f"\n  [ARC {kind}] visibility={final!r}")
        return final

    # --- Persistence ---

    def _save_pool(self):
        """Save remaining UTXOs to disk as JSON."""
        import json

        records = []
        for source_tx, vout, satoshis in self.utxos:
            records.append(
                {
                    "source_tx_hex": source_tx.hex(),
                    "vout": vout,
                    "satoshis": satoshis,
                }
            )
        with open(self.pool_file, "w") as f:
            json.dump(records, f, indent=2)

    def _load_pool(self) -> bool:
        """Load UTXOs from disk. Returns True if any were loaded."""
        import json

        if not os.path.exists(self.pool_file):
            return False
        try:
            with open(self.pool_file) as f:
                records = json.load(f)
            if not records:
                return False
            for rec in records:
                tx_hex = rec["source_tx_hex"]
                if tx_hex not in self._tx_cache:
                    tx = Transaction.from_hex(tx_hex)
                    if tx is None:
                        continue
                    self._tx_cache[tx_hex] = tx
                self.utxos.append((self._tx_cache[tx_hex], rec["vout"], rec["satoshis"]))
            return len(self.utxos) > 0
        except (json.JSONDecodeError, KeyError, OSError):
            return False

    async def prune_pool_to_chain_unspent(self) -> int:
        """Remove persisted pool entries that WhatsOnChain does not list as unspent for our address.

        Survives crashes after ``take_utxo`` or external spends: the JSON pool can reference
        outputs that are already spent. Returns the number of entries removed.
        """
        if live_utxo_skip_woc_prune():
            return 0
        if not self.utxos:
            return 0
        try:
            rows = await self.fetch_utxos_from_woc()
        except Exception as e:
            print(f"\n  [UTXO pool] pruning skipped — WoC unspent failed ({e!r})")
            return 0
        unspent_set = {(r["tx_hash"].lower(), int(r["tx_pos"])) for r in rows}
        kept: list[tuple[Transaction, int, int]] = []
        removed = 0
        for source_tx, vout, sat in self.utxos:
            key = (source_tx.txid().lower(), vout)
            if key in unspent_set:
                kept.append((source_tx, vout, sat))
            else:
                removed += 1
        if removed:
            print(
                f"\n  [UTXO pool] dropped {removed} stale entr(y/ies) not in WoC unspent for " f"{self.key.address()}"
            )
            self.utxos = kept
            self._save_pool()
        return removed

    # --- Network ---

    async def _woc_get(self, session, url: str, *, as_json: bool = False):
        """GET with 429 retry/backoff (WhatsOnChain rate limits aggressive bursts)."""
        backoff = 1.0
        for _ in range(12):
            async with session.get(url) as resp:
                if resp.status == 429:
                    ra = resp.headers.get("Retry-After")
                    try:
                        wait = float(ra) if ra else backoff
                    except ValueError:
                        wait = backoff
                    wait = min(max(wait, 0.5), 90.0)
                    await asyncio.sleep(wait)
                    backoff = min(backoff * 1.5, 45.0)
                    continue
                if resp.status != 200:
                    raise RuntimeError(f"WoC API returned {resp.status} for {url}")
                if as_json:
                    return await resp.json()
                return (await resp.text()).strip()
        raise RuntimeError(f"WoC API rate limited (429) after retries for {url}")

    async def fetch_utxos_from_woc(self, session=None) -> list[dict]:
        """Fetch unspent outputs from WhatsOnChain API."""
        address = self.key.address()
        url = f"{self.woc_api_base}/address/{address}/unspent"
        if session is not None:
            return await self._woc_get(session, url, as_json=True)
        async with aiohttp.ClientSession() as http_session:
            return await self._woc_get(http_session, url, as_json=True)

    async def fetch_raw_tx(self, txid: str, session=None) -> Transaction:
        """Fetch a raw transaction hex from WoC and parse it."""
        url = f"{self.woc_api_base}/tx/{txid}/hex"

        def _parse(hex_str: str) -> Transaction:
            tx = Transaction.from_hex(hex_str)
            if tx is None:
                raise RuntimeError(f"Failed to parse tx {txid}")
            return tx

        if session is not None:
            hex_str = await self._woc_get(session, url, as_json=False)
            return _parse(hex_str)
        async with aiohttp.ClientSession() as http_session:
            hex_str = await self._woc_get(http_session, url, as_json=False)
            return _parse(hex_str)

    async def _get_source_tx_by_txid(self, txid: str, session=None) -> Transaction:
        if txid not in self._fetched_tx_by_id:
            self._fetched_tx_by_id[txid] = await self.fetch_raw_tx(txid, session=session)
        return self._fetched_tx_by_id[txid]

    async def wait_until_woc_sees_txid(
        self,
        txid: str,
        *,
        timeout_sec: float = 120.0,
        poll_interval: float = 1.5,
    ) -> None:
        """Poll WoC until a tx is visible (so a follow-up WoC broadcast can spend its outputs).

        Fan-out and most spends use ARC; WoC's node may lag. Call this after ARC-broadcasting
        a setup tx when step 2 must be submitted via WhatsOnChainBroadcaster.
        """
        url = f"{self.woc_api_base}/tx/{txid}/hex"
        deadline = time.monotonic() + timeout_sec
        backoff_429 = 1.0
        async with aiohttp.ClientSession() as session:
            while time.monotonic() < deadline:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        return
                    if resp.status == 429:
                        ra = resp.headers.get("Retry-After")
                        try:
                            wait = float(ra) if ra else backoff_429
                        except ValueError:
                            wait = backoff_429
                        wait = min(max(wait, 0.5), 90.0)
                        await asyncio.sleep(wait)
                        backoff_429 = min(backoff_429 * 1.5, 45.0)
                        continue
                    # Not indexed yet (or transient gateway)
                    if resp.status in (404, 400, 502, 503):
                        await asyncio.sleep(poll_interval)
                        continue
                    raise RuntimeError(f"WoC poll for tx {txid} returned {resp.status} for {url}")
        raise RuntimeError(f"WoC did not return tx {txid} within {timeout_sec}s (needed for WoC spend)")

    # --- Fan-out ---

    async def ensure_utxos(self, min_count: int = 10, satoshis_each: int = 3_000):
        """Ensure at least min_count UTXOs are available, loading or fanning out as needed."""
        # Try loading from disk first
        if not self.utxos:
            self._load_pool()

        await self.prune_pool_to_chain_unspent()

        shortfall = min_count - len(self.utxos)
        if shortfall <= 0:
            return

        # Only mint as many new pool outputs as needed (not a full min_count every time).
        await self.fan_out(shortfall, satoshis_each)

    async def fan_out(self, num_outputs: int, satoshis_each: int = 3_000):
        """Create and broadcast a fan-out transaction.

        Splits value into num_outputs P2PKH outputs of satoshis_each. Uses one
        or more WoC UTXOs (largest first) until their combined value covers the
        outputs plus a fee buffer.
        """
        async with aiohttp.ClientSession() as http_session:
            woc_utxos = await self.fetch_utxos_from_woc(http_session)
            if not woc_utxos:
                raise RuntimeError(f"No UTXOs found for address {self.key.address()} on {self.network_label}")

            woc_utxos.sort(key=lambda u: u["value"], reverse=True)
            needed = num_outputs * satoshis_each + 5_000  # fee buffer

            total = 0
            selected: list[dict] = []
            for u in woc_utxos:
                selected.append(u)
                total += u["value"]
                if total >= needed:
                    break
            else:
                raise RuntimeError(
                    f"Total unspent {total} sat across {len(woc_utxos)} UTXO(s), need at least {needed} sat "
                    f"for {num_outputs} outputs at {satoshis_each} sat each"
                )

            inputs = []
            last_parent_txid: str | None = None
            for u in selected:
                txid = u["tx_hash"]
                if last_parent_txid is not None and txid != last_parent_txid:
                    await asyncio.sleep(0.25)
                last_parent_txid = txid
                source_tx = await self._get_source_tx_by_txid(txid, session=http_session)
                inputs.append(
                    TransactionInput(
                        source_transaction=source_tx,
                        source_txid=txid,
                        source_output_index=u["tx_pos"],
                        unlocking_script_template=self.p2pkh.unlock(self.key),
                        sequence=0xFFFFFFFF,
                    )
                )

        outputs = [
            TransactionOutput(
                locking_script=self.lock_script,
                satoshis=satoshis_each,
            )
            for _ in range(num_outputs)
        ]
        # Add a change output for leftovers
        outputs.append(TransactionOutput(locking_script=self.lock_script, change=True))

        fan_out_tx = Transaction(inputs, outputs, version=1)
        fan_out_tx.fee(self.FEE_MODEL)
        fan_out_tx.sign()

        broadcast_ordinal = self.broadcast_count + 1
        print(
            f"\n  [Broadcast #{broadcast_ordinal}] kind=fan-out txs_in_broadcast=1 "
            f"pool_outputs={num_outputs} (+change) tx_inputs={len(fan_out_tx.inputs)} "
            f"tx_outputs={len(fan_out_tx.outputs)}"
        )

        # Broadcast (same ARC wait-for as broadcast_test_tx so fan-out reaches network)
        bc = _arc_with_broadcast_test_tx_headers(self.broadcaster)
        result = await _broadcast_with_transient_retries(bc, fan_out_tx, label="ARC fan-out")
        _print_live_broadcast_result(bc, result, kind="fan-out")
        _print_live_tx_raw_hex(fan_out_tx, kind="fan-out")
        arc_vis: str | None = None
        try:
            arc_vis = await self._ensure_arc_seen_on_network(
                bc,
                result,
                kind="fan-out",
                raw_tx_hex=fan_out_tx.hex(),
                require_arc_seen_on_network=True,
            )
        except Exception as exc:
            self.broadcast_count += 1
            self._append_broadcast_ledger_row(
                broadcast_index=broadcast_ordinal,
                kind="fan-out",
                tx=fan_out_tx,
                result=result,
                arc_visibility=f"ERROR: {exc!s}",
                pool_outputs=num_outputs,
                visibility_poll_error=str(exc),
            )
            raise
        self.broadcast_count += 1
        self._append_broadcast_ledger_row(
            broadcast_index=broadcast_ordinal,
            kind="fan-out",
            tx=fan_out_tx,
            result=result,
            arc_visibility=arc_vis,
            pool_outputs=num_outputs,
        )
        if result.status != "success":
            raise RuntimeError(f"Fan-out broadcast failed: {getattr(result, 'description', result.status)}")
        txid = result.txid or fan_out_tx.txid()
        print(f"\n  -> Fan-out: {self.explorer_tx_base}/{txid}")

        # Record all non-change outputs as available UTXOs
        for i in range(num_outputs):
            self.utxos.append((fan_out_tx, i, satoshis_each))

        # Persist to disk
        self._save_pool()
        return fan_out_tx

    def take_utxo(self) -> tuple[Transaction, int, int]:
        """Consume one UTXO and persist the updated pool."""
        if not self.utxos:
            raise RuntimeError("No UTXOs available — fan_out not called or all consumed")
        utxo = self.utxos.pop(0)
        self._save_pool()
        return utxo

    def return_utxo(self, utxo: tuple[Transaction, int, int]):
        """Return a UTXO to the pool (e.g. after a failed broadcast)."""
        self.utxos.insert(0, utxo)
        self._save_pool()

    async def broadcast_test_tx_retry_on_spent(
        self,
        build_tx: Callable[[tuple[Transaction, int, int]], Transaction],
        *,
        satoshis_each: int = 3_000,
        max_attempts: int = 3,
        broadcaster: Broadcaster | None = None,
        verify_mined: bool | None = None,
    ) -> tuple[BroadcastResponse | BroadcastFailure, Transaction | None]:
        """Take a pool UTXO, build a tx, broadcast; on spent-input failure take another UTXO and retry.

        Use when the on-disk pool may still list an output another run already spent.

        Returns ``(result, tx)`` where ``tx`` is the transaction that was broadcast on success, else
        ``None``.
        """
        last: BroadcastResponse | BroadcastFailure | None = None
        for _ in range(max(1, max_attempts)):
            if not self.utxos:
                await self.ensure_utxos(1, satoshis_each=satoshis_each)
            utxo = self.take_utxo()
            tx = build_tx(utxo)
            last = await self.broadcast_test_tx(
                tx,
                spent_utxo=utxo,
                broadcaster=broadcaster,
                verify_mined=verify_mined,
            )
            if last.status == "success":
                return last, tx
            if not broadcast_failure_indicates_spent_input(last):
                return last, None
        assert last is not None
        return last, None

    async def broadcast_test_tx_resilient(
        self,
        build_tx: Callable[[], Awaitable[Transaction]],
        *,
        broadcaster: Broadcaster | None = None,
        verify_mined: bool | None = None,
        max_attempts: int = 3,
    ) -> BroadcastResponse | BroadcastFailure:
        """Broadcast a transaction from ``build_tx()``; on spent-input failure, build and try again.

        Intended for pre-built spends that do not use :meth:`broadcast_test_tx`'s ``spent_utxo``
        (e.g. step-2 tx after :func:`~tests.bsv.live.live_tx_helpers.build_two_step_live_tx`). If the
        network reports the inputs are gone, ``build_tx`` is awaited again (typically re-running the
        full two-step flow from a fresh pool UTXO). Transient errors are not retried.
        """
        last: BroadcastResponse | BroadcastFailure | None = None
        for _ in range(max(1, max_attempts)):
            tx = await build_tx()
            last = await self.broadcast_test_tx(tx, broadcaster=broadcaster, verify_mined=verify_mined)
            if last.status == "success":
                return last
            if not broadcast_failure_indicates_spent_input(last):
                return last
        assert last is not None
        return last

    async def broadcast_test_tx(
        self,
        tx: Transaction,
        spent_utxo: tuple[Transaction, int, int] = None,
        broadcaster: Broadcaster = None,
        *,
        verify_mined: bool | None = None,
    ) -> BroadcastResponse | BroadcastFailure:
        """Broadcast a test transaction and track it.

        If ``spent_utxo`` is provided and the broadcast fails with a **transient** error, the UTXO
        is returned to the pool. If the error indicates the input was already spent or missing
        on-chain, the UTXO is **not** re-queued (see :func:`broadcast_failure_indicates_spent_input`).
        Prints a clickable WhatsonChain link on successful broadcasts.

        Args:
            broadcaster: Optional override broadcaster (e.g. WoC for txs
                that ARC rejects due to non-push unlocking scripts).
            verify_mined: If True, wait for ARC MINED or WoC confirmations (slow).
                If None, use env (default: off; only SEEN_ON_NETWORK is enforced by default).

        For ARC broadcasters, :func:`live_broadcast_arc_wait_headers` is merged by default
        (``X-WaitForStatus: 8`` / SEEN_ON_NETWORK). Set ``LIVE_ARC_SKIP_WAIT_FOR_SEEN=1`` to
        disable. Non-ARC broadcasters are unchanged.
        """
        from .arc_verify import wait_until_live_tx_confirmed

        broadcast_ordinal = self.broadcast_count + 1
        n_in, n_out = len(tx.inputs), len(tx.outputs)
        print(f"\n  [Broadcast #{broadcast_ordinal}] kind=tx txs_in_broadcast=1 " f"inputs={n_in} outputs={n_out}")

        bc = _arc_with_broadcast_test_tx_headers(broadcaster or self.broadcaster)
        result = await _broadcast_with_transient_retries(bc, tx, label="ARC tx")
        result = await _recover_arc_double_spend_if_visible_on_woc(self.woc_api_base, bc, tx, result)
        _print_live_broadcast_result(bc, result, kind="tx")
        _print_live_tx_raw_hex(tx, kind="tx")
        arc_visibility: str | None = None
        try:
            arc_visibility = await self._ensure_arc_seen_on_network(bc, result, kind="tx", raw_tx_hex=tx.hex())
        except Exception as exc:
            self.broadcast_count += 1
            self._append_broadcast_ledger_row(
                broadcast_index=broadcast_ordinal,
                kind="tx",
                tx=tx,
                result=result,
                arc_visibility=f"ERROR: {exc!s}",
                visibility_poll_error=str(exc),
            )
            raise
        self.broadcast_count += 1
        woc_visible: bool | None = None
        woc_method: str | None = None
        woc_http_detail: dict | None = None
        if result.status == "success":
            txid = result.txid or tx.txid()
            print(f"\n  -> {self.explorer_tx_base}/{txid}")
            # Non-blocking WoC visibility probe
            try:
                from .arc_verify import check_woc_visibility

                visible, method, elapsed, woc_http_detail = await check_woc_visibility(self.woc_api_base, txid)
                if visible:
                    print(f"  [WoC visibility] observable=yes (via {method} after {elapsed:.1f}s)")
                else:
                    print(f"  [WoC visibility] observable=no ({method} after {elapsed:.1f}s)")
                self._woc_visibility_results.append((txid, visible))
                woc_visible = visible
                woc_method = method
            except Exception:
                pass  # never fail the test for a visibility check
            if live_require_mined_enabled(verify_mined):
                await wait_until_live_tx_confirmed(
                    self.arc_base_url,
                    self.woc_api_base,
                    txid,
                    timeout_sec=live_tx_confirm_timeout_sec(),
                )
        self._append_broadcast_ledger_row(
            broadcast_index=broadcast_ordinal,
            kind="tx",
            tx=tx,
            result=result,
            arc_visibility=arc_visibility,
            woc_visible=woc_visible,
            woc_method=woc_method,
            woc_http_detail=woc_http_detail,
        )
        if result.status != "success" and spent_utxo is not None:
            if broadcast_failure_indicates_spent_input(result):
                print(
                    f"\n  [UTXO pool] input no longer spendable — not re-queuing "
                    f"{spent_utxo[0].txid()}:{spent_utxo[1]}"
                )
            else:
                self.return_utxo(spent_utxo)
        return result


# ---------------------------------------------------------------------------
# test_live_testnet: WoC JSON audit (xfail strict when broadcast passes)
# ---------------------------------------------------------------------------


def pytest_configure(config):
    """Short defaults for live ARC waits unless the user set env vars explicitly."""
    os.environ.setdefault("ARC_SEEN_POLL_TIMEOUT_SEC", "15")
    os.environ.setdefault("ARC_X_MAX_TIMEOUT", "5")


def pytest_sessionstart(session):
    try:
        from .live_broadcast_ledger import reset as _live_broadcast_ledger_reset
    except ImportError:
        return
    _live_broadcast_ledger_reset()


def pytest_sessionfinish(session, exitstatus):
    try:
        from .live_broadcast_ledger import write_markdown_report
    except ImportError:
        return
    path = write_markdown_report()
    if path:
        print(f"\n[live tests] Broadcast report written to {path}")


def pytest_collection_modifyitems(config, items):
    """Mark audited testnet live node IDs xfail(strict=True) — see test_live_testnet docstring."""
    if os.environ.get("LIVE_WOC_JSON_XFAIL_AUDIT", "").strip().lower() not in (
        "1",
        "true",
        "yes",
    ):
        return
    try:
        from ._testnet_woc_xfail_nodeids import TESTNET_LIVE_WOC_JSON_XFAIL_NODEIDS
    except ImportError:
        return
    reason = (
        "WhatsOnChain test JSON GET /v1/bsv/test/tx/{txid} returned 404 for a tx printed "
        "in the Apr 2026 live audit (or body missing txid/hash). Broadcast may still succeed "
        "via ARC; SEEN_ON_NETWORK is default, mined polling is opt-in. This marker is only applied "
        "when LIVE_WOC_JSON_XFAIL_AUDIT=1. 404 here is not proof the tx is off-chain."
    )
    mark = pytest.mark.xfail(reason=reason, strict=True)
    for item in items:
        if item.nodeid in TESTNET_LIVE_WOC_JSON_XFAIL_NODEIDS:
            item.add_marker(mark)
