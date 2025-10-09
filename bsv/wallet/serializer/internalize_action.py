from typing import Dict, Any, List

from bsv.wallet.substrates.serializer import Reader, Writer

# protocol codes
WALLET_PAYMENT = 1
BASKET_INSERTION = 2


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
        protocol = out.get("protocol", "wallet payment")
        if protocol == "wallet payment":
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
    out: Dict[str, Any] = {}
    tx_len = r.read_varint()
    out["tx"] = r.read_bytes(int(tx_len))
    outputs = []
    count = r.read_varint()
    for _ in range(int(count)):
        item: Dict[str, Any] = {}
        item["outputIndex"] = int(r.read_varint())
        proto_b = r.read_byte()
        if proto_b == WALLET_PAYMENT:
            item["protocol"] = "wallet payment"
            pay = {
                "senderIdentityKey": r.read_bytes(33),
                "derivationPrefix": r.read_int_bytes() or b"",
                "derivationSuffix": r.read_int_bytes() or b"",
            }
            item["paymentRemittance"] = pay
        else:
            item["protocol"] = "basket insertion"
            ins = {
                "basket": r.read_string(),
                "customInstructions": r.read_string(),
                "tags": r.read_string_slice(),
            }
            item["insertionRemittance"] = ins
        outputs.append(item)
    out["outputs"] = outputs
    out["labels"] = r.read_string_slice()
    out["description"] = r.read_string()
    out["seekPermission"] = r.read_optional_bool()
    return out


def serialize_internalize_action_result(_: Dict[str, Any]) -> bytes:
    # result uses frame for error; no payload
    return b""


def deserialize_internalize_action_result(_: bytes) -> Dict[str, Any]:
    return {"accepted": True}
