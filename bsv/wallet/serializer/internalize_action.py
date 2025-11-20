from typing import Dict, Any, List

from bsv.wallet.substrates.serializer import Reader, Writer

# protocol codes
WALLET_PAYMENT = 1
BASKET_INSERTION = 2

# protocol names
PROTOCOL_WALLET_PAYMENT = "wallet payment"


def serialize_internalize_action_args(args: Dict[str, Any]) -> bytes:
    w = Writer()
    # tx (beef)
    tx = args.get("tx", b"")
    w.write_varint(len(tx))
    w.write_bytes(tx)
    # outputs
    outputs: List[Dict[str, Any]] = args.get("outputs", [])
    w.write_varint(len(outputs))
    for out in outputs:
        w.write_varint(int(out.get("outputIndex", 0)))
        protocol = out.get("protocol", PROTOCOL_WALLET_PAYMENT)
        if protocol == PROTOCOL_WALLET_PAYMENT:
            w.write_byte(WALLET_PAYMENT)
            pay = out.get("paymentRemittance", {})
            w.write_bytes(pay.get("senderIdentityKey", b""))
            w.write_int_bytes(pay.get("derivationPrefix", b""))
            w.write_int_bytes(pay.get("derivationSuffix", b""))
        else:
            w.write_byte(BASKET_INSERTION)
            ins = out.get("insertionRemittance", {})
            w.write_string(ins.get("basket", ""))
            ci = ins.get("customInstructions")
            if ci is None or ci == "":
                w.write_negative_one()
            else:
                w.write_string(ci)
            tags = ins.get("tags")
            w.write_string_slice(tags)
    # labels, description, seekPermission
    w.write_string_slice(args.get("labels"))
    w.write_string(args.get("description", ""))
    w.write_optional_bool(args.get("seekPermission"))
    return w.to_bytes()


def deserialize_internalize_action_args(data: bytes) -> Dict[str, Any]:
    r = Reader(data)
    tx_len = r.read_varint()
    return {
        "tx": r.read_bytes(int(tx_len)),
        "outputs": _deserialize_internalize_outputs(r),
        "labels": r.read_string_slice(),
        "description": r.read_string(),
        "seekPermission": r.read_optional_bool(),
    }

def _deserialize_internalize_outputs(r: Reader) -> List[Dict[str, Any]]:
    """Deserialize internalize action outputs."""
    count = r.read_varint()
    return [_deserialize_internalize_output(r) for _ in range(int(count))]

def _deserialize_internalize_output(r: Reader) -> Dict[str, Any]:
    """Deserialize a single internalize output."""
    item = {"outputIndex": int(r.read_varint())}
    proto_b = r.read_byte()
    
    if proto_b == WALLET_PAYMENT:
        item["protocol"] = PROTOCOL_WALLET_PAYMENT
        item["paymentRemittance"] = {
            "senderIdentityKey": r.read_bytes(33),
            "derivationPrefix": r.read_int_bytes() or b"",
            "derivationSuffix": r.read_int_bytes() or b"",
        }
    else:
        item["protocol"] = "basket insertion"
        item["insertionRemittance"] = {
            "basket": r.read_string(),
            "customInstructions": r.read_string(),
            "tags": r.read_string_slice(),
        }
    return item


def serialize_internalize_action_result(_: Dict[str, Any]) -> bytes:
    # result uses frame for error; no payload
    return b""


def deserialize_internalize_action_result(_: bytes) -> Dict[str, Any]:
    return {"accepted": True}
