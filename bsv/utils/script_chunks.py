from dataclasses import dataclass
from typing import List, Optional, Union


@dataclass
class ScriptChunk:
    op: int
    data: Optional[bytes]


def read_script_chunks(script: Union[bytes, str]) -> list[ScriptChunk]:
    """Parse script bytes into chunks of opcodes and data."""
    script_bytes = _normalize_script_input(script)
    return _parse_script_bytes(script_bytes)


def _normalize_script_input(script: Union[bytes, str]) -> bytes:
    """Convert script input to bytes, handling hex strings."""
    if isinstance(script, str):
        try:
            return bytes.fromhex(script)
        except Exception:
            # If conversion fails, treat as empty
            return b""
    return script


def _parse_script_bytes(script: bytes) -> list[ScriptChunk]:
    """Parse script bytes into chunks."""
    chunks: list[ScriptChunk] = []
    i = 0
    n = len(script)

    while i < n:
        op = script[i]
        i += 1

        result = _parse_single_opcode(script, op, i, n)
        if result is None:
            break

        chunk, new_i = result
        chunks.append(chunk)
        i = new_i

    return chunks


def _parse_single_opcode(script: bytes, op: int, i: int, n: int) -> Optional[tuple[ScriptChunk, int]]:
    """Parse a single opcode and return (chunk, new_index)."""
    if op <= 75:  # direct push
        return _parse_direct_push(script, op, i, n)
    elif op == 0x4C:  # OP_PUSHDATA1
        return _parse_pushdata1(script, i, n)
    elif op == 0x4D:  # OP_PUSHDATA2
        return _parse_pushdata2(script, i, n)
    elif op == 0x4E:  # OP_PUSHDATA4
        return _parse_pushdata4(script, i, n)
    else:  # Non-push opcodes
        return ScriptChunk(op=op, data=None), i


def _parse_direct_push(script: bytes, op: int, i: int, n: int) -> Optional[tuple[ScriptChunk, int]]:
    """Parse direct push opcode (length encoded in opcode)."""
    ln = op
    if i + ln > n:
        return None
    return ScriptChunk(op=op, data=script[i : i + ln]), i + ln


def _parse_pushdata1(script: bytes, i: int, n: int) -> Optional[tuple[ScriptChunk, int]]:
    """Parse OP_PUSHDATA1 opcode."""
    if i >= n:
        return None
    ln = script[i]
    i += 1
    if i + ln > n:
        return None
    return ScriptChunk(op=0x4C, data=script[i : i + ln]), i + ln


def _parse_pushdata2(script: bytes, i: int, n: int) -> Optional[tuple[ScriptChunk, int]]:
    """Parse OP_PUSHDATA2 opcode."""
    if i + 1 >= n:
        return None
    ln = int.from_bytes(script[i : i + 2], "little")
    i += 2
    if i + ln > n:
        return None
    return ScriptChunk(op=0x4D, data=script[i : i + ln]), i + ln


def _parse_pushdata4(script: bytes, i: int, n: int) -> Optional[tuple[ScriptChunk, int]]:
    """Parse OP_PUSHDATA4 opcode."""
    if i + 3 >= n:
        return None
    ln = int.from_bytes(script[i : i + 4], "little")
    i += 4
    if i + ln > n:
        return None
    return ScriptChunk(op=0x4E, data=script[i : i + ln]), i + ln


def serialize_chunks(chunks: list[ScriptChunk]) -> bytes:
    """
    Serialize a list of ScriptChunk objects back to script bytes.

    Args:
        chunks: List of ScriptChunk objects to serialize

    Returns:
        Script bytes

    Raises:
        ValueError: If chunk data is invalid for the opcode
    """
    result = bytearray()

    for chunk in chunks:
        result.append(chunk.op)
        if chunk.data is not None:
            _serialize_chunk_data(result, chunk)

    return bytes(result)


def _serialize_chunk_data(result: bytearray, chunk: ScriptChunk) -> None:
    """Serialize chunk data based on opcode type."""
    data = chunk.data

    if chunk.op <= 75:  # direct push
        _serialize_direct_push(result, chunk, data)
    elif chunk.op == 0x4C:  # OP_PUSHDATA1
        _serialize_pushdata1(result, data)
    elif chunk.op == 0x4D:  # OP_PUSHDATA2
        _serialize_pushdata2(result, data)
    elif chunk.op == 0x4E:  # OP_PUSHDATA4
        _serialize_pushdata4(result, data)
    else:
        # Non-push opcode with data - this shouldn't happen in valid scripts
        raise ValueError(f"Non-push opcode {chunk.op} should not have data")


def _serialize_direct_push(result: bytearray, chunk: ScriptChunk, data: bytes) -> None:
    """Serialize direct push opcode (opcode <= 75)."""
    if len(data) != chunk.op:
        raise ValueError(f"Direct push opcode {chunk.op} requires data length {chunk.op}, got {len(data)}")
    result.extend(data)


def _serialize_pushdata1(result: bytearray, data: bytes) -> None:
    """Serialize OP_PUSHDATA1 opcode."""
    if len(data) > 255:
        raise ValueError(f"OP_PUSHDATA1 data too long: {len(data)} bytes")
    result.append(len(data))
    result.extend(data)


def _serialize_pushdata2(result: bytearray, data: bytes) -> None:
    """Serialize OP_PUSHDATA2 opcode."""
    if len(data) > 65535:
        raise ValueError(f"OP_PUSHDATA2 data too long: {len(data)} bytes")
    result.extend(len(data).to_bytes(2, "little"))
    result.extend(data)


def _serialize_pushdata4(result: bytearray, data: bytes) -> None:
    """Serialize OP_PUSHDATA4 opcode."""
    if len(data) > 4294967295:
        raise ValueError(f"OP_PUSHDATA4 data too long: {len(data)} bytes")
    result.extend(len(data).to_bytes(4, "little"))
    result.extend(data)
