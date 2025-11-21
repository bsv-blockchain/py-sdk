import pytest

from bsv.utils.ecdsa import (
    serialize_ecdsa_der,
    deserialize_ecdsa_der,
    serialize_ecdsa_recoverable,
    deserialize_ecdsa_recoverable,
    stringify_ecdsa_recoverable,
    unstringify_ecdsa_recoverable,
)
from bsv.keys import PrivateKey
from bsv.hash import hash256


class TestECDSAUtils:
    def test_der_roundtrip_and_low_s(self):
        priv = PrivateKey(12345)
        msg = b"abc"
        sig = priv.sign(msg, hash256)
        r, s = deserialize_ecdsa_der(sig)
        ser = serialize_ecdsa_der((r, s))
        assert ser == sig

    def test_recoverable_roundtrip_and_stringify(self):
        priv = PrivateKey(98765)
        msg = b"hello"
        rec = priv.sign_recoverable(msg, hash256)
        r, s, rec_id = deserialize_ecdsa_recoverable(rec)
        ser = serialize_ecdsa_recoverable((r, s, rec_id))
        assert ser == rec

        b64 = stringify_ecdsa_recoverable(rec, compressed=True)
        ser2, compressed = unstringify_ecdsa_recoverable(b64)
        assert compressed is True
        assert ser2 == rec

    def test_invalid_der_raises(self):
        with pytest.raises(ValueError, match=r"invalid DER encoded 0001"):
            deserialize_ecdsa_der(b"\x00\x01")


