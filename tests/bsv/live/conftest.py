"""Shared fixtures and helpers for mocked live tests."""

import os

import pytest

from bsv.broadcasters.broadcaster import BroadcastResponse, Broadcaster
from bsv.broadcasters import default_broadcaster
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
# Testnet configuration
# ---------------------------------------------------------------------------

FUNDED_TESTNET_WIF = os.environ.get("FUNDED_TESTNET_WIF")


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


def build_funding_tx(locking_script: Script, satoshis: int = 10_000) -> Transaction:
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
        version=1,
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
    outputs = [
        TransactionOutput(locking_script=locking_script, satoshis=per_output)
        for _ in range(num_outputs)
    ]

    tx = Transaction(inputs, outputs, version=tx_version)
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
        sig_script = Script(
            encode_pushdata(signature + sighash.to_bytes(1, "little"))
            + encode_pushdata(public_key)
        )
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
        OpCode.OP_DUP
        + OpCode.OP_HASH160
        + encode_pushdata(pkh)
        + OpCode.OP_EQUALVERIFY
        + OpCode.OP_CHECKSIG
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


# ---------------------------------------------------------------------------
# UTXO Manager for testnet chaining
# ---------------------------------------------------------------------------


class UTXOManager:
    """Manages a pool of UTXOs from a fan-out transaction for testnet tests.

    UTXOs are persisted to a JSON file so they survive across test runs.
    On first run, fetches a UTXO from WoC, creates a fan-out tx, and saves
    the resulting UTXOs. On subsequent runs, loads from the file and only
    re-fans-out if the pool is exhausted.

    Flow:
    1. Try to load persisted UTXOs from .utxo_pool.json
    2. If none available, fetch from WoC and fan-out
    3. Each test calls take_utxo() which also persists the updated pool
    """

    WOC_TESTNET = "https://api.whatsonchain.com/v1/bsv/test"
    FEE_MODEL = SatoshisPerKilobyte(100)
    POOL_FILE = os.path.join(os.path.dirname(__file__), ".utxo_pool.json")

    def __init__(self, funded_key: PrivateKey, broadcaster):
        self.key = funded_key
        self.broadcaster = broadcaster
        self.p2pkh = P2PKH()
        self.lock_script = self.p2pkh.lock(self.key.address())
        self.utxos: list[tuple[Transaction, int, int]] = []  # (source_tx, vout, satoshis)
        self.broadcast_count = 0
        # Cache of tx hex -> Transaction for deserialized source txs
        self._tx_cache: dict[str, Transaction] = {}

    # --- Persistence ---

    def _save_pool(self):
        """Save remaining UTXOs to disk as JSON."""
        import json

        records = []
        for source_tx, vout, satoshis in self.utxos:
            records.append({
                "source_tx_hex": source_tx.hex(),
                "vout": vout,
                "satoshis": satoshis,
            })
        with open(self.POOL_FILE, "w") as f:
            json.dump(records, f, indent=2)

    def _load_pool(self) -> bool:
        """Load UTXOs from disk. Returns True if any were loaded."""
        import json

        if not os.path.exists(self.POOL_FILE):
            return False
        try:
            with open(self.POOL_FILE) as f:
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

    async def fetch_utxos_from_woc(self) -> list[dict]:
        """Fetch unspent outputs from WhatsOnChain testnet API."""
        import aiohttp

        address = self.key.address()
        url = f"{self.WOC_TESTNET}/address/{address}/unspent"
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"WoC API returned {resp.status} for {url}")
                return await resp.json()

    async def fetch_raw_tx(self, txid: str) -> Transaction:
        """Fetch a raw transaction hex from WoC and parse it."""
        import aiohttp

        url = f"{self.WOC_TESTNET}/tx/{txid}/hex"
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"WoC API returned {resp.status} for {url}")
                hex_str = await resp.text()
                tx = Transaction.from_hex(hex_str.strip())
                if tx is None:
                    raise RuntimeError(f"Failed to parse tx {txid}")
                return tx

    # --- Fan-out ---

    async def ensure_utxos(self, min_count: int = 10, satoshis_each: int = 3_000):
        """Ensure at least min_count UTXOs are available, loading or fanning out as needed."""
        # Try loading from disk first
        if not self.utxos:
            self._load_pool()

        if len(self.utxos) >= min_count:
            return

        # Need to fan out
        await self.fan_out(min_count, satoshis_each)

    async def fan_out(self, num_outputs: int, satoshis_each: int = 3_000):
        """Create and broadcast a fan-out transaction.

        Takes the largest available UTXO and splits it into num_outputs
        P2PKH outputs, each with satoshis_each satoshis.
        """
        # Fetch UTXOs from WoC
        woc_utxos = await self.fetch_utxos_from_woc()
        if not woc_utxos:
            raise RuntimeError(
                f"No UTXOs found for address {self.key.address()} on testnet"
            )

        # Sort by value descending, pick the largest
        woc_utxos.sort(key=lambda u: u["value"], reverse=True)
        best = woc_utxos[0]
        needed = num_outputs * satoshis_each + 5_000  # fee buffer
        if best["value"] < needed:
            raise RuntimeError(
                f"Largest UTXO has {best['value']} sat, need at least {needed} sat "
                f"for {num_outputs} outputs at {satoshis_each} sat each"
            )

        # Fetch the source transaction
        source_tx = await self.fetch_raw_tx(best["tx_hash"])

        # Build the fan-out tx
        inp = TransactionInput(
            source_transaction=source_tx,
            source_txid=best["tx_hash"],
            source_output_index=best["tx_pos"],
            unlocking_script_template=self.p2pkh.unlock(self.key),
            sequence=0xFFFFFFFF,
        )
        outputs = [
            TransactionOutput(
                locking_script=self.lock_script,
                satoshis=satoshis_each,
            )
            for _ in range(num_outputs)
        ]
        # Add a change output for leftovers
        outputs.append(
            TransactionOutput(locking_script=self.lock_script, change=True)
        )

        fan_out_tx = Transaction([inp], outputs, version=1)
        fan_out_tx.fee(self.FEE_MODEL)
        fan_out_tx.sign()

        # Broadcast
        result = await self.broadcaster.broadcast(fan_out_tx)
        if result.status != "success":
            raise RuntimeError(
                f"Fan-out broadcast failed: {getattr(result, 'description', result.status)}"
            )
        self.broadcast_count += 1
        txid = result.txid or fan_out_tx.txid()
        print(f"\n  -> Fan-out: https://test.whatsonchain.com/tx/{txid}")

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
        self, tx: Transaction, spent_utxo: tuple[Transaction, int, int] = None,
        broadcaster: Broadcaster = None,
    ) -> BroadcastResponse:
        """Broadcast a test transaction and track it.

        If spent_utxo is provided and the broadcast fails, the UTXO is
        returned to the pool since it was never actually spent on-chain.
        Prints a clickable WhatsonChain link on successful broadcasts.

        Args:
            broadcaster: Optional override broadcaster (e.g. WoC for txs
                that ARC rejects due to non-push unlocking scripts).
        """
        bc = broadcaster or self.broadcaster
        result = await bc.broadcast(tx)
        self.broadcast_count += 1
        if result.status == "success":
            txid = result.txid or tx.txid()
            print(f"\n  -> https://test.whatsonchain.com/tx/{txid}")
        if result.status != "success" and spent_utxo is not None:
            self.return_utxo(spent_utxo)
        return result
