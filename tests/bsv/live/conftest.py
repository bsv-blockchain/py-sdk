"""Shared fixtures and helpers for mocked live tests."""

import asyncio
import os
import time

import aiohttp
import pytest

from bsv.broadcasters import default_broadcaster
from bsv.broadcasters.broadcaster import Broadcaster, BroadcastResponse
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

# GorillaPool ARC (same hosts as testnet_broadcaster / mainnet_broadcaster fixtures)
ARC_API_TESTNET_BASE = "https://testnet.arc.gorillapool.io"
ARC_API_MAINNET_BASE = "https://arc.gorillapool.io"


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
        os.environ.get("ARC_X_MAX_TIMEOUT", "120"),
    )
    try:
        return float((raw or "120").strip() or "120")
    except ValueError:
        return 120.0


def live_broadcast_arc_wait_headers() -> dict[str, str]:
    """ARC headers so POST /v1/tx requests ``SEEN_ON_NETWORK`` (GorillaPool / BSV ARC).

    Sends ``X-WaitForStatus: 8``. Some deployments still return an earlier ``txStatus`` in
    the POST body (e.g. ``ANNOUNCED_TO_NETWORK``); :meth:`UTXOManager._ensure_arc_seen_on_network`
    then polls GET /v1/tx until ``SEEN_ON_NETWORK`` or ``MINED``.

    Env:
      LIVE_ARC_SKIP_WAIT_FOR_SEEN=1 — omit wait headers and GET enforcement (faster).
      ARC_SEEN_POLL_TIMEOUT_SEC — max seconds for that GET poll (default: same as ARC_X_MAX_TIMEOUT or 120).
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
    print(f"\n  [{tag} {kind}] status={st!r} code={code!r} txid={txid!r} description={desc!r}")


def _arc_post_first_tx_status(message: str | None) -> str | None:
    """First token of ARC :class:`BroadcastResponse` message (txStatus from POST body)."""
    if not message:
        return None
    parts = message.split()
    return parts[0] if parts else None


def _print_live_tx_raw_hex(tx: Transaction, *, kind: str) -> None:
    """Print standard raw transaction hex (``tx.hex()``), not EF wire form."""
    print(f"\n  [rawTx hex {kind}] {tx.hex()}")


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
    """ARC broadcaster pointed at testnet with Chronicle script validation skip.

    Uses X-SkipScriptValidation header because the ARC testnet validator
    doesn't support Chronicle sighash yet, even though the underlying
    node does (txs are accepted into the network).
    """
    from bsv.broadcasters.arc import ARC, ARCConfig

    config = ARCConfig(headers={"X-SkipScriptValidation": "true"})
    return ARC("https://testnet.arc.gorillapool.io", config)


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
    """ARC broadcaster for mainnet with Chronicle-friendly script validation skip.

    Same X-SkipScriptValidation header as testnet ARC: the in-path validator can
    reject Chronicle / OTDA txs that the network still accepts.
    """
    from bsv.broadcasters.arc import ARC, ARCConfig

    config = ARCConfig(headers={"X-SkipScriptValidation": "true"})
    return ARC("https://arc.gorillapool.io", config)


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
    2. If none available, fetch from WoC and fan-out
    3. Each test calls take_utxo() which also persists the updated pool
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
            self.arc_base_url = (
                ARC_API_MAINNET_BASE if network_label == "mainnet" else ARC_API_TESTNET_BASE
            )
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

    async def _ensure_arc_seen_on_network(self, bc: Broadcaster, result: object, *, kind: str) -> None:
        """When live ARC wait headers are on but POST returns an earlier txStatus, poll GET."""
        from bsv.broadcasters.arc import ARC

        if not isinstance(bc, ARC) or not live_broadcast_arc_wait_headers():
            return
        if getattr(result, "status", None) != "success":
            return
        st = _arc_post_first_tx_status(getattr(result, "message", None))
        if st in ("SEEN_ON_NETWORK", "MINED"):
            return
        txid = getattr(result, "txid", None)
        if not txid:
            return
        tmo = arc_seen_poll_timeout_sec()
        print(
            f"\n  [ARC {kind}] POST txStatus={st!r}; "
            f"polling GET until SEEN_ON_NETWORK or MINED (timeout {tmo}s)…"
        )
        from .arc_verify import wait_until_arc_tx_seen_on_network

        final = await wait_until_arc_tx_seen_on_network(
            self.arc_base_url,
            txid,
            timeout_sec=tmo,
        )
        print(f"\n  [ARC {kind}] GET txStatus={final!r}")

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

        # Broadcast (same ARC wait-for as broadcast_test_tx so fan-out reaches network)
        bc = _arc_with_broadcast_test_tx_headers(self.broadcaster)
        result = await bc.broadcast(fan_out_tx)
        _print_live_broadcast_result(bc, result, kind="fan-out")
        _print_live_tx_raw_hex(fan_out_tx, kind="fan-out")
        await self._ensure_arc_seen_on_network(bc, result, kind="fan-out")
        if result.status != "success":
            raise RuntimeError(f"Fan-out broadcast failed: {getattr(result, 'description', result.status)}")
        self.broadcast_count += 1
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

    async def broadcast_test_tx(
        self,
        tx: Transaction,
        spent_utxo: tuple[Transaction, int, int] = None,
        broadcaster: Broadcaster = None,
        *,
        verify_mined: bool | None = None,
    ) -> BroadcastResponse:
        """Broadcast a test transaction and track it.

        If spent_utxo is provided and the broadcast fails, the UTXO is
        returned to the pool since it was never actually spent on-chain.
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

        bc = _arc_with_broadcast_test_tx_headers(broadcaster or self.broadcaster)
        result = await bc.broadcast(tx)
        _print_live_broadcast_result(bc, result, kind="tx")
        _print_live_tx_raw_hex(tx, kind="tx")
        await self._ensure_arc_seen_on_network(bc, result, kind="tx")
        self.broadcast_count += 1
        if result.status == "success":
            txid = result.txid or tx.txid()
            print(f"\n  -> {self.explorer_tx_base}/{txid}")
            if live_require_mined_enabled(verify_mined):
                await wait_until_live_tx_confirmed(
                    self.arc_base_url,
                    self.woc_api_base,
                    txid,
                    timeout_sec=live_tx_confirm_timeout_sec(),
                )
        if result.status != "success" and spent_utxo is not None:
            self.return_utxo(spent_utxo)
        return result


# ---------------------------------------------------------------------------
# test_live_testnet: WoC JSON audit (xfail strict when broadcast passes)
# ---------------------------------------------------------------------------


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
