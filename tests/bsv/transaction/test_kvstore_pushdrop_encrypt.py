import base64

from bsv.keys import PrivateKey
from bsv.wallet.wallet_impl import WalletImpl
from bsv.keystore.interfaces import KVStoreConfig
from bsv.keystore.local_kv_store import LocalKVStore
from bsv.transaction.pushdrop import build_lock_before_pushdrop, decode_lock_before_pushdrop


def test_kvstore_set_get_encrypt_with_pushdrop_lock_before():
    # Wallet
    priv = PrivateKey()
    wallet = WalletImpl(priv, permission_callback=lambda action: True)

    # KV with proper protocol configuration
    default_ca = {
        "protocol_id": {"securityLevel": 2, "protocol": "kvctx"},
        "key_id": "foo"
    }
    kv = LocalKVStore(KVStoreConfig(wallet=wallet, context="kv.ctx", originator="org", encrypt=True, default_ca=default_ca))

    # Set encrypted
    outp = kv.set(None, "foo", "bar")
    assert outp.endswith(".0")

    # get() should return encrypted data with enc: prefix when encrypt=True
    val = kv.get(None, "foo", "")
    assert val.startswith("enc:"), f"Expected encrypted value with 'enc:' prefix, got: {val}"
    
    # Manually decrypt to validate compatibility
    ct = base64.b64decode(val[4:])
    dec = wallet.decrypt(None, {"encryption_args": {"protocol_id": {"securityLevel": 2, "protocol": "kvctx"}, "key_id": "foo", "counterparty": {"type": 0}}, "ciphertext": ct}, "org")
    assert isinstance(dec.get("plaintext"), (bytes, bytearray)) and dec["plaintext"].decode("utf-8") == "bar"


def test_pushdrop_multiple_fields():
    from bsv.keys import PrivateKey
    from bsv.wallet.wallet_impl import WalletImpl
    from bsv.transaction.pushdrop import build_lock_before_pushdrop, decode_lock_before_pushdrop, read_script_chunks
    priv = PrivateKey()
    pubkey = priv.public_key().serialize()
    print("pubkey (hex):", pubkey.hex(), "len:", len(pubkey))
    fields = [b"field1", b"field2", b"field3"]
    script = build_lock_before_pushdrop(fields, pubkey, lock_position="before")
    print("script (hex):", script)
    chunks = read_script_chunks(bytes.fromhex(script))
    print("chunks:", [(c.op, c.data.hex() if c.data else None) for c in chunks])
    decoded = decode_lock_before_pushdrop(bytes.fromhex(script), lock_position="before")
    print("decoded:", decoded)
    assert decoded is not None
    assert decoded["pubkey"] == pubkey
    assert decoded["fields"] == fields

def test_pushdrop_with_signature():
    from bsv.keys import PrivateKey
    from bsv.wallet.wallet_impl import WalletImpl
    from bsv.transaction.pushdrop import build_lock_before_pushdrop, decode_lock_before_pushdrop, read_script_chunks
    priv = PrivateKey()
    pubkey = priv.public_key().serialize()
    print("pubkey (hex):", pubkey.hex(), "len:", len(pubkey))
    fields = [b"data"]
    # ダミー署名
    signature = b"sigdata123"
    script = build_lock_before_pushdrop(fields, pubkey, include_signature=True, signature=signature, lock_position="before")
    print("script (hex):", script)
    chunks = read_script_chunks(bytes.fromhex(script))
    print("chunks:", [(c.op, c.data.hex() if c.data else None) for c in chunks])
    decoded = decode_lock_before_pushdrop(bytes.fromhex(script), lock_position="before")
    print("decoded:", decoded)
    assert decoded is not None
    assert decoded["pubkey"] == pubkey
    assert decoded["fields"] == [b"data", signature]

def test_pushdrop_lock_after():
    from bsv.keys import PrivateKey
    from bsv.wallet.wallet_impl import WalletImpl
    from bsv.transaction.pushdrop import build_lock_before_pushdrop, decode_lock_before_pushdrop, read_script_chunks
    priv = PrivateKey()
    pubkey = priv.public_key().serialize()
    print("pubkey (hex):", pubkey.hex(), "len:", len(pubkey))
    fields = [b"after1", b"after2"]
    script = build_lock_before_pushdrop(fields, pubkey, lock_position="after")
    print("script (hex):", script)
    chunks = read_script_chunks(bytes.fromhex(script))
    print("chunks:", [(c.op, c.data.hex() if c.data else None) for c in chunks])
    decoded = decode_lock_before_pushdrop(bytes.fromhex(script), lock_position="after")
    print("decoded:", decoded)
    assert decoded is not None
    assert decoded["pubkey"] == pubkey
    assert decoded["fields"] == fields

def test_pushdrop_invalid_script():
    # 不正なスクリプト
    script = b"\x00\x00\x00"
    decoded = decode_lock_before_pushdrop(script, lock_position="before")
    assert decoded is None


