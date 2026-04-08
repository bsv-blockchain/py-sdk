# Mainnet live test refactor plan

This document describes how to introduce `FUNDED_MAINNET_WIF` and run the live suite on BSV mainnet, based on the existing `tests/bsv/live/test_live_testnet.py` and `conftest.py` setup.

## Current gaps

- `test_live_mainnet.py` imports `FUNDED_MAINNET_WIF` from `conftest`, but **`conftest.py` only defines `FUNDED_TESTNET_WIF`** — the mainnet module fails to import until conftest is updated.
- The mainnet file still uses **`pytest.mark.testnet`**, **`funded_key`**, **`testnet_broadcaster`**, **`TestTestnet*`** names, and **testnet explorer links** in places; helpers were partially renamed (`build_mainnet_tx`, `woc_mainnet_broadcaster` in some tests) but wiring is inconsistent.
- **`UTXOManager`** is testnet-only: hardcoded `WOC_TESTNET`, **`POOL_FILE = .utxo_pool.json`** (same file as testnet — must not share on mainnet), and **`broadcast_test_tx` / `fan_out`** print `https://test.whatsonchain.com/...`.

---

## 1. Create and fund `FUNDED_MAINNET_WIF`

### Key material

- Generate a **dedicated** mainnet key (do not reuse production wallets). Export **compressed WIF** so it matches how `P2PKH` / fan-out use `self.key.address()`.
- `PrivateKey(wif)` in this SDK resolves network from the WIF prefix; mainnet WIFs use the usual mainnet byte (same convention as Bitcoin).

### Funding

- Fan-out needs roughly `TOTAL_TEST_UTXOS * satoshis_each + fee buffer` for the first split (see `UTXOManager.fan_out`: `needed = num_outputs * satoshis_each + 5_000`), then each test spends and pays fees. With `TOTAL_TEST_UTXOS = 155` and `3_000` sats per output, plan for **well over** ~0.005 BSV in **one** large UTXO to be safe, plus ongoing fees for hundreds of broadcasts — **mainnet is materially more expensive than testnet**.
- Send coins to the **P2PKH address** of that key; confirm on [WhatsOnChain main](https://whatsonchain.com/) (or your explorer of choice).

### Environment

- Set `FUNDED_MAINNET_WIF` in the shell or in a **local** env file (e.g. same pattern as `FUNDED_TESTNET_WIF` in `.env.local`), and **never commit** the value.

### Optional hardening

- Treat mainnet live tests as **opt-in** only (`-m mainnet` and env var set), same spirit as testnet.

---

## 2. `conftest.py` — env, fixtures, broadcasters

| Item | Action |
|------|--------|
| **`FUNDED_MAINNET_WIF`** | `os.environ.get("FUNDED_MAINNET_WIF")` next to the testnet variable. |
| **`funded_mainnet_key` fixture** | Mirror `funded_key`: skip if unset, `return PrivateKey(FUNDED_MAINNET_WIF)`. |
| **`mainnet_broadcaster`** | `ARC("https://arc.gorillapool.io", ...)` per `default_broadcaster.py`. **Decide headers**: testnet uses `X-SkipScriptValidation` because ARC’s testnet validator lags Chronicle; on mainnet you may **omit** that header first and only reintroduce it if broadcasts fail for the same reason. |
| **`woc_mainnet_broadcaster`** | `WhatsOnChainBroadcaster(network="main")` (or `Network.MAINNET`). |

---

## 3. `UTXOManager` — network-aware + separate pool file

Refactor minimally so each instance knows:

- **WoC REST base**, e.g. test `https://api.whatsonchain.com/v1/bsv/test`, main `https://api.whatsonchain.com/v1/bsv/main` (same pattern as `WhatsOnChainBroadcaster`).
- **Pool path**, e.g. keep `.utxo_pool.json` for testnet and add **`.utxo_pool_mainnet.json`** (or pass `pool_file` in `__init__`) so testnet and mainnet runs never overwrite each other.
- **Explorer URL prefix** for logging (`test.whatsonchain.com` vs `whatsonchain.com`), used in `fan_out` and `broadcast_test_tx` instead of hardcoded test URLs.

Constructor sketch: `UTXOManager(funded_key, broadcaster, *, woc_api_base: str, pool_file: str, explorer_host: str)`.

---

## 4. `test_live_mainnet.py` — wire everything to mainnet

- **Docstring / run line**: describe mainnet, `FUNDED_MAINNET_WIF`, and `pytest tests/bsv/live/test_live_mainnet.py -v -m mainnet`.
- **`pytestmark`**: replace `testnet` with a new **`mainnet`** marker; keep `skipif(not FUNDED_MAINNET_WIF, ...)`.
- **`utxo_mgr` fixture**: depend on **`funded_mainnet_key`** and **`mainnet_broadcaster`**; construct `UTXOManager(..., woc_api_base=..., pool_file=..., explorer_host=...)`.
- **Tests that use `woc_mainnet_broadcaster`**: ensure the **`woc_mainnet_broadcaster` fixture exists** in conftest.
- **Rename** `TestTestnet*` → `TestMainnet*` (and summary strings) so reports and failures are unambiguous.
- **Comment** above helpers: update any remaining “testnet” wording to “mainnet”.

---

## 5. `pytest.ini`

- Register a **`mainnet`** marker (e.g. live mainnet broadcast; deselect with `-m "not mainnet"`).
- **CI / local default**: if you currently run `pytest -m "not testnet"`, extend to **`"not testnet and not mainnet"`** so mainnet is never picked up accidentally.

---

## 6. Docs (optional)

- README section next to testnet: env var name, cost warning, and example command.

---

## 7. Verification order

1. Import check: `python -c "from tests.bsv.live import test_live_mainnet"` (from `py-sdk` with `PYTHONPATH=.`).
2. Dry run: `pytest tests/bsv/live/test_live_mainnet.py --collect-only -q`.
3. Single cheap test first (e.g. one parametrized case via `-k`), then full file.

---

## Risk summary

- **Real money** and **many on-chain transactions**; pool file mistakes could confuse networks — separate pool path is mandatory.
- **ARC behaviour on mainnet** may differ from testnet (Chronicle / script validation); be ready to adjust `ARCConfig` or prefer WoC for the same edge cases already routed through `woc_*` on testnet.
