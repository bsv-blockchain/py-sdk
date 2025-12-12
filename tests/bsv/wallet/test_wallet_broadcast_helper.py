import types

from bsv.keys import PrivateKey
from bsv.wallet import ProtoWallet


class _Resp:
    def __init__(self, status, json_obj):
        self.status_code = status
        self._json = json_obj
        self.ok = status == 200
    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"status {self.status_code}")
    def json(self):
        return self._json


def test_query_tx_mempool_404(monkeypatch):
    def fake_get(url, headers=None, timeout=10):
        return _Resp(404, {})
    import requests
    monkeypatch.setattr(requests, "get", fake_get, raising=False)
    w = ProtoWallet(PrivateKey(), permission_callback=lambda a: True)
    res = w.query_tx_mempool("00" * 32)
    assert res == {"known": False}


def test_query_tx_mempool_known_unconfirmed(monkeypatch):
    def fake_get(url, headers=None, timeout=10):
        return _Resp(200, {})
    import requests
    monkeypatch.setattr(requests, "get", fake_get, raising=False)
    w = ProtoWallet(PrivateKey(), permission_callback=lambda a: True)
    res = w.query_tx_mempool("11" * 32)
    assert res.get("known") is True and res.get("confirmations") == 0


def test_query_tx_mempool_confirmed(monkeypatch):
    def fake_get(url, headers=None, timeout=10):
        return _Resp(200, {"confirmations": 3})
    import requests
    monkeypatch.setattr(requests, "get", fake_get, raising=False)
    w = ProtoWallet(PrivateKey(), permission_callback=lambda a: True)
    res = w.query_tx_mempool("22" * 32)
    assert res.get("known") is True and res.get("confirmations") == 3


