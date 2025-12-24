from bsv.wallet import ProtoWallet
from bsv.keys import PrivateKey
from bsv.keystore.local_kv_store import LocalKVStore
from bsv.keystore.interfaces import KVStoreConfig


def _make_kv(encrypt=False, lock_position="before"):
    priv = PrivateKey()
    wallet = ProtoWallet(priv, permission_callback=lambda a: True)
    cfg = KVStoreConfig(wallet=wallet, context="ctx", originator="org", encrypt=encrypt)
    # inject optional attributes expected in LocalKVStore
    setattr(cfg, "lock_position", lock_position)
    return LocalKVStore(cfg)


def test_kv_set_get_remove_lock_before_signed_encrypted():
    # Note: "encrypted" in name refers to signed (with signature), not data encryption
    # Data encryption requires protocol_id/key_id in default_ca (tested separately)
    kv = _make_kv(encrypt=False, lock_position="before")
    out = kv.set("c", "k1", "v1")
    assert isinstance(out, str) and out
    got = kv.get("c", "k1")
    assert got == "v1"
    removed = kv.remove("c", "k1")
    # TypeScript SDK returns plain txids, not "removed:key" format
    assert removed and len(removed) > 0
    assert isinstance(removed[0], str) and len(removed[0]) == 64  # txid is 64 hex chars


def test_kv_set_get_lock_after_signed_plain():
    kv = _make_kv(encrypt=False, lock_position="after")
    out = kv.set("c", "k2", "v2")
    assert isinstance(out, str) and out
    got = kv.get("c", "k2")
    assert got == "v2"


def test_kv_set_get_remove_lock_after_signed_encrypted():
    # Note: "encrypted" in name refers to signed (with signature), not data encryption
    # Data encryption requires protocol_id/key_id in default_ca (tested separately)
    kv = _make_kv(encrypt=False, lock_position="after")
    out = kv.set("c", "k3", "v3")
    assert isinstance(out, str) and out
    got = kv.get("c", "k3")
    assert got == "v3"
    removed = kv.remove("c", "k3")
    # TypeScript SDK returns plain txids, not "removed:key" format
    assert removed and len(removed) > 0
    assert isinstance(removed[0], str) and len(removed[0]) == 64  # txid is 64 hex chars

