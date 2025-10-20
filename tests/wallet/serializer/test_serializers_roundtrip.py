import pytest

from bsv.wallet.serializer.create_action_args import serialize_create_action_args, deserialize_create_action_args
from bsv.wallet.serializer.create_action_result import serialize_create_action_result, deserialize_create_action_result
from bsv.wallet.serializer.sign_action_args import serialize_sign_action_args, deserialize_sign_action_args
from bsv.wallet.serializer.sign_action_result import serialize_sign_action_result, deserialize_sign_action_result
from bsv.wallet.serializer.list_actions import serialize_list_actions_args, deserialize_list_actions_args, serialize_list_actions_result, deserialize_list_actions_result
from bsv.wallet.serializer.internalize_action import serialize_internalize_action_args, deserialize_internalize_action_args
from bsv.wallet.serializer.list_certificates import (
    serialize_list_certificates_args,
    deserialize_list_certificates_args,
    serialize_list_certificates_result,
    deserialize_list_certificates_result,
)
from bsv.wallet.serializer.internalize_action import serialize_internalize_action_result, deserialize_internalize_action_result
from bsv.wallet.serializer.prove_certificate import serialize_prove_certificate_args, deserialize_prove_certificate_args
from bsv.wallet.serializer.certificate import (
    serialize_certificate_base,
    deserialize_certificate_base,
)
from bsv.wallet.serializer.relinquish_certificate import (
    serialize_relinquish_certificate_result,
    deserialize_relinquish_certificate_result,
)


def test_create_action_args_roundtrip():
    src = {
        "description": "test",
        "inputBEEF": b"abc",
        "inputs": [
            {
                "outpoint": {"txid": b"\x11" * 32, "index": 1},
                "unlockingScript": b"\x51",
                "inputDescription": "in",
                "sequenceNumber": 5,
            }
        ],
        "outputs": [
            {
                "lockingScript": b"\x51",
                "satoshis": 1000,
                "outputDescription": "out",
                "basket": "b",
                "customInstructions": "ci",
                "tags": ["t1", "t2"],
            }
        ],
        "lockTime": 0,
        "version": 0,
        "labels": ["L"],
        "options": {
            "signAndProcess": True,
            "acceptDelayedBroadcast": False,
            "trustSelfFlag": 0,
            "knownTxids": None,
            "returnTXIDOnly": None,
            "noSend": None,
            "noSendChangeRaw": None,
            "sendWith": None,
            "randomizeOutputs": None,
        },
    }
    data = serialize_create_action_args(src)
    out = deserialize_create_action_args(data)
    assert out["description"] == src["description"]
    assert out["inputs"][0]["outpoint"]["index"] == 1
    assert out["outputs"][0]["satoshis"] == 1000


def test_create_action_result_roundtrip():
    src = {"signableTransaction": {"tx": b"\x00\x01", "reference": b"\x02"}}
    data = serialize_create_action_result(src)
    out = deserialize_create_action_result(data)
    assert out["signableTransaction"]["tx"] == b"\x00\x01"


def test_sign_action_args_roundtrip():
    src = {
        "spends": {"0": {"unlockingScript": b"\x51", "sequenceNumber": 7}},
        "reference": b"ref",
        "options": {"acceptDelayedBroadcast": True, "returnTXIDOnly": False, "noSend": None, "sendWith": []},
    }
    data = serialize_sign_action_args(src)
    out = deserialize_sign_action_args(data)
    assert out["spends"]["0"]["unlockingScript"] == b"\x51"


def test_list_actions_args_roundtrip():
    src = {
        "labels": ["a"],
        "labelQueryMode": "any",
        "includeLabels": True,
        "includeInputs": False,
        "includeInputSourceLockingScripts": None,
        "includeInputUnlockingScripts": None,
        "includeOutputs": True,
        "includeOutputLockingScripts": None,
        "limit": 10,
        "offset": None,
        "seekPermission": None,
    }
    data = serialize_list_actions_args(src)
    out = deserialize_list_actions_args(data)
    assert out["labels"] == ["a"]
    assert out["labelQueryMode"] == "any"


def test_internalize_action_args_roundtrip():
    src = {
        "tx": b"\x00\x01",
        "outputs": [
            {
                "outputIndex": 0,
                "protocol": "wallet payment",
                "paymentRemittance": {
                    "senderIdentityKey": b"\x02" * 33,
                    "derivationPrefix": b"p",
                    "derivationSuffix": b"s",
                },
            }
        ],
        "labels": ["l"],
        "description": "d",
        "seekPermission": None,
    }
    data = serialize_internalize_action_args(src)
    out = deserialize_internalize_action_args(data)
    assert out["tx"] == b"\x00\x01"
    assert out["outputs"][0]["protocol"] == "wallet payment"


def test_list_certificates_args_roundtrip():
    src = {"certifiers": [b"\x02" * 33], "types": [b"\x00" * 32], "limit": 5, "offset": None, "privileged": None, "privilegedReason": ""}
    data = serialize_list_certificates_args(src)
    out = deserialize_list_certificates_args(data)
    assert out["limit"] == 5
    assert len(out["certifiers"]) == 1


def test_prove_certificate_args_roundtrip():
    src = {
        "certificate": {
            "type": b"\x00" * 32,
            "subject": b"\x02" * 33,
            "serialNumber": b"\x01" * 32,
            "certifier": b"\x03" * 33,
            "revocationOutpoint": {"txid": b"\xaa" * 32, "index": 1},
            "signature": b"sig",
            "fields": {"name": "alice"},
        },
        "fieldsToReveal": ["name"],
        "verifier": b"\x02" * 33,
        "privileged": None,
        "privilegedReason": "",
    }
    data = serialize_prove_certificate_args(src)
    out = deserialize_prove_certificate_args(data)
    assert out["certificate"]["serialNumber"] == b"\x01" * 32


def test_list_certificates_result_roundtrip():
    src = {
        "totalCertificates": 1,
        "certificates": [
            {
                "certificateBytes": b"CB",
                "keyring": {"k": "v"},
                "verifier": b"\x02" * 33,
            }
        ],
    }
    data = serialize_list_certificates_result(src)
    out = deserialize_list_certificates_result(data)
    assert out["totalCertificates"] == 1
    assert out["certificates"][0]["certificateBytes"] == b"CB"


def test_internalize_action_result_roundtrip():
    src = {"accepted": True}
    data = serialize_internalize_action_result(src)
    out = deserialize_internalize_action_result(data)
    assert out["accepted"] is True


def test_sign_action_result_roundtrip():
    src = {
        "txid": b"\xaa" * 32,
        "tx": b"\x00\x01\x02",
        "sendWithResults": [
            {"txid": b"\xbb" * 32, "status": "sending"},
            {"txid": b"\xcc" * 32, "status": "failed"},
        ],
    }
    data = serialize_sign_action_result(src)
    out = deserialize_sign_action_result(data)
    assert out["txid"] == src["txid"]
    assert out["sendWithResults"][1]["status"] == "failed"


def test_certificate_base_roundtrip():
    cert = {
        "type": b"\x00" * 32,
        "subject": b"\x02" * 33,
        "serialNumber": b"\x01" * 32,
        "certifier": b"\x03" * 33,
        "revocationOutpoint": {"txid": b"\xaa" * 32, "index": 7},
        "signature": b"sig",
        "fields": {"name": "alice"},
    }
    data = serialize_certificate_base(cert)
    out = deserialize_certificate_base(data)
    assert out["revocationOutpoint"]["index"] == 7


def test_relinquish_certificate_result_roundtrip():
    src = {}
    data = serialize_relinquish_certificate_result(src)
    out = deserialize_relinquish_certificate_result(data)
    assert out == {}
