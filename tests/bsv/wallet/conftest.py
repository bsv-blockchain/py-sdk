import os

import pytest

from bsv.script.type import P2PKH
from bsv.wallet import ProtoWallet


class DummyWhatsOnChainTracker:
    """A lightweight tracker for wallet tests that avoids network calls."""

    def __init__(self, *args, **kwargs):  # pragma: no cover
        pass

    def query_tx(self, *args, **kwargs):
        return {"known": False, "error": "stubbed"}

    def query_address(self, *args, **kwargs):
        return {"outputs": []}

    def is_valid_root_for_height(self, *args, **kwargs):
        return False


@pytest.fixture(autouse=True)
def wallet_shims(monkeypatch):
    """Provide deterministic wallet behavior for storage/wallet tests."""
    monkeypatch.setenv("USE_WOC", "0")
    monkeypatch.setenv("WOC_API_KEY", "")
    monkeypatch.setenv("DISABLE_ARC", "1")

    def _list_self_utxos(self, args=None, originator=None):
        basket_addr = args.get("basket") if args else None
        target_addr = basket_addr or self._self_address() or "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        locking_script = P2PKH().lock(target_addr)
        return [
            {
                "txid": "00" * 32,
                "outputIndex": 0,
                "satoshis": 10_000_000,
                "lockingScript": locking_script,
                "outputDescription": "shim mock utxo",
                "basket": basket_addr or "default",
                "tags": [],
            }
        ]

    def _get_outputs_from_mock(self, args, include):
        basket = (args or {}).get("basket") or "shim-basket"
        tags = list((args or {}).get("tags") or [])
        # Use a valid address for locking script, but keep basket for filtering
        valid_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        return {
            "outputs": [
                {
                    "txid": "ff" * 32,
                    "outputIndex": 0,
                    "satoshis": 5000,
                    "lockingScript": P2PKH().lock(valid_addr),
                    "outputDescription": "shim mock output",
                    "basket": basket,
                    "tags": tags,
                    "spendable": True,
                }
            ],
            "BEEF": b"",
        }

    monkeypatch.setattr(ProtoWallet, "_list_self_utxos", _list_self_utxos)
    monkeypatch.setattr(ProtoWallet, "_get_outputs_from_mock", _get_outputs_from_mock)

    try:
        import bsv.chaintrackers as chaintrackers

        monkeypatch.setattr(chaintrackers, "WhatsOnChainTracker", DummyWhatsOnChainTracker)
    except ImportError:
        pass

    try:
        import bsv.chaintrackers.whatsonchain as whatsonchain_module

        monkeypatch.setattr(whatsonchain_module, "WhatsOnChainTracker", DummyWhatsOnChainTracker)
    except ImportError:
        pass

