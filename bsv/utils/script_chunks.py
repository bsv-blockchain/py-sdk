from dataclasses import dataclass
from typing import Optional, List, Union


@dataclass
class ScriptChunk:
    op: int
    data: Optional[bytes]


def read_script_chunks(script: Union[bytes, str]) -> List[ScriptChunk]:  # NOSONAR - Complexity (33), requires refactoring
    # Accept hex string input for convenience (tests may pass hex)
    if isinstance(script, str):
        try:
            script = bytes.fromhex(script)
        except Exception:
            # If conversion fails, treat as empty
            script = b""
    chunks: List[ScriptChunk] = []
    i = 0
    n = len(script)
    while i < n:
        op = script[i]
        i += 1
        if op <= 75:  # direct push
            ln = op
            if i + ln > n:
                break
            chunks.append(ScriptChunk(op=op, data=script[i:i+ln]))
            i += ln
            continue
        if op == 0x4C:  # OP_PUSHDATA1
            if i >= n:
                break
            ln = script[i]
            i += 1
            if i + ln > n:
                break
            chunks.append(ScriptChunk(op=op, data=script[i:i+ln]))
            i += ln
            continue
        if op == 0x4D:  # OP_PUSHDATA2
            if i + 1 >= n:
                break
            ln = int.from_bytes(script[i:i+2], 'little')
            i += 2
            if i + ln > n:
                break
            chunks.append(ScriptChunk(op=op, data=script[i:i+ln]))
            i += ln
            continue
        if op == 0x4E:  # OP_PUSHDATA4
            if i + 3 >= n:
                break
            ln = int.from_bytes(script[i:i+4], 'little')
            i += 4
            if i + ln > n:
                break
            chunks.append(ScriptChunk(op=op, data=script[i:i+ln]))
            i += ln
            continue
        # Non-push opcodes
        chunks.append(ScriptChunk(op=op, data=None))
    return chunks


def serialize_chunks(chunks: List[ScriptChunk]) -> bytes:
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
        # Write the opcode
        result.append(chunk.op)

        # Handle data based on opcode type
        if chunk.data is not None:
            data = chunk.data

            # Validate data length based on opcode
            if chunk.op <= 75:  # direct push
                if len(data) != chunk.op:
                    raise ValueError(f"Direct push opcode {chunk.op} requires data length {chunk.op}, got {len(data)}")
                result.extend(data)
            elif chunk.op == 0x4C:  # OP_PUSHDATA1
                if len(data) > 255:
                    raise ValueError(f"OP_PUSHDATA1 data too long: {len(data)} bytes")
                result.append(len(data))
                result.extend(data)
            elif chunk.op == 0x4D:  # OP_PUSHDATA2
                if len(data) > 65535:
                    raise ValueError(f"OP_PUSHDATA2 data too long: {len(data)} bytes")
                result.extend(len(data).to_bytes(2, 'little'))
                result.extend(data)
            elif chunk.op == 0x4E:  # OP_PUSHDATA4
                if len(data) > 4294967295:
                    raise ValueError(f"OP_PUSHDATA4 data too long: {len(data)} bytes")
                result.extend(len(data).to_bytes(4, 'little'))
                result.extend(data)
            else:
                # Non-push opcode with data - this shouldn't happen in valid scripts
                raise ValueError(f"Non-push opcode {chunk.op} should not have data")
        else:
            # No data - this is correct for non-push opcodes
            pass

    return bytes(result)


