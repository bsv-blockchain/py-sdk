from dataclasses import dataclass
from typing import Optional, List


@dataclass
class ScriptChunk:
    op: int
    data: Optional[bytes]


def read_script_chunks(script: bytes) -> List[ScriptChunk]:
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


