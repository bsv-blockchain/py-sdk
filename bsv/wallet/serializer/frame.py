from typing import Optional

from bsv.wallet.substrates.serializer import Writer, Reader


def write_request_frame(call: int, originator: str, params: bytes) -> bytes:
    w = Writer()
    w.write_byte(call & 0xFF)
    originator_bytes = originator.encode("utf-8") if originator else b""
    w.write_byte(len(originator_bytes))
    w.write_bytes(originator_bytes)
    if params:
        w.write_bytes(params)
    return w.to_bytes()


def write_result_frame(payload: Optional[bytes] = None, error: Optional[str] = None) -> bytes:
    """
    Result frame format:
      - status: 0 = OK, 1 = ERROR
      - if OK: payload bytes as-is (no length; upstream knows exact shape)
      - if ERROR: varint+string message
    """
    w = Writer()
    if error:
        w.write_byte(1)
        w.write_string(error)
    else:
        w.write_byte(0)
        if payload:
            w.write_bytes(payload)
    return w.to_bytes()


def read_result_frame(data: bytes) -> bytes:
    r = Reader(data)
    status = r.read_byte()
    if status == 0:
        # remaining is payload
        return data[r.pos :]
    # error
    msg = r.read_string()
    raise RuntimeError(msg or "wallet wire error")
