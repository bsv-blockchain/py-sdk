from io import BytesIO
from typing import List

from .constants import SIGHASH
from .hash import hash256
from .transaction_input import TransactionInput
from .transaction_output import TransactionOutput


def _preimage(
    tx_input: TransactionInput,
    tx_version: int,
    tx_locktime: int,
    hash_prevouts: bytes,
    hash_sequence: bytes,
    hash_outputs: bytes,
) -> bytes:
    """
    BIP-143 https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
     1. nVersion of the transaction (4-byte little endian)
     2. hashPrevouts (32-byte hash)
     3. hashSequence (32-byte hash)
     4. outpoint (32-byte hash + 4-byte little endian)
     5. scriptCode of the input (serialized as scripts inside CTxOuts)
     6. value of the output spent by this input (8-byte little endian)
     7. nSequence of the input (4-byte little endian)
     8. hashOutputs (32-byte hash)
     9. nLocktime of the transaction (4-byte little endian)
    10. sighash type of the signature (4-byte little endian)
    """
    stream = BytesIO()
    # 1
    stream.write(tx_version.to_bytes(4, "little"))
    # 2
    stream.write(hash_prevouts)
    # 3
    stream.write(hash_sequence)
    # 4
    stream.write(bytes.fromhex(tx_input.source_txid)[::-1])
    stream.write(tx_input.source_output_index.to_bytes(4, "little"))
    # 5
    stream.write(tx_input.locking_script.byte_length_varint())
    stream.write(tx_input.locking_script.serialize())
    # 6
    stream.write(tx_input.satoshis.to_bytes(8, "little"))
    # 7
    stream.write(tx_input.sequence.to_bytes(4, "little"))
    # 8
    stream.write(hash_outputs)
    # 9
    stream.write(tx_locktime.to_bytes(4, "little"))
    # 10
    stream.write(tx_input.sighash.to_bytes(4, "little"))
    return stream.getvalue()


def tx_preimages(
    inputs: list[TransactionInput],
    outputs: list[TransactionOutput],
    tx_version: int,
    tx_locktime: int,
) -> list[bytes]:
    """
    :returns: the digests of unsigned transaction
    """
    _hash_prevouts = hash256(
        b"".join(bytes.fromhex(_in.source_txid)[::-1] + _in.source_output_index.to_bytes(4, "little") for _in in inputs)
    )
    _hash_sequence = hash256(b"".join(_in.sequence.to_bytes(4, "little") for _in in inputs))
    _hash_outputs = hash256(b"".join(tx_output.serialize() for tx_output in outputs))
    digests = []
    for i in range(len(inputs)):
        sighash = inputs[i].sighash
        # hash previous outs
        if not sighash & SIGHASH.ANYONECANPAY:
            # if anyone can pay is not set
            hash_prevouts = _hash_prevouts
        else:
            hash_prevouts = b"\x00" * 32
        # hash sequence
        if not sighash & SIGHASH.ANYONECANPAY and sighash & 0x1F != SIGHASH.SINGLE and sighash & 0x1F != SIGHASH.NONE:
            # if none of anyone can pay, single, none is set
            hash_sequence = _hash_sequence
        else:
            hash_sequence = b"\x00" * 32
        # hash outputs
        if sighash & 0x1F != SIGHASH.SINGLE and sighash & 0x1F != SIGHASH.NONE:
            # if neither single nor none
            hash_outputs = _hash_outputs
        elif sighash & 0x1F == SIGHASH.SINGLE and i < len(outputs):
            # if single and the input index is smaller than the number of outputs
            hash_outputs = hash256(outputs[i].serialize())
        else:
            hash_outputs = b"\x00" * 32
        digests.append(_preimage(inputs[i], tx_version, tx_locktime, hash_prevouts, hash_sequence, hash_outputs))
    return digests


def _otda_serialize_input(stream, inp: TransactionInput, idx: int, input_index: int, base_type: int) -> None:
    """Serialize a single input for the OTDA preimage."""
    # outpoint
    stream.write(bytes.fromhex(inp.source_txid)[::-1])
    stream.write(inp.source_output_index.to_bytes(4, "little"))
    # scriptSig: only for the signing input
    if idx == input_index:
        script_bytes = inp.locking_script.serialize()
        _write_varint(stream, len(script_bytes))
        stream.write(script_bytes)
    else:
        _write_varint(stream, 0)
    # sequence: zero for other inputs with NONE/SINGLE
    if idx != input_index and base_type in (int(SIGHASH.NONE), int(SIGHASH.SINGLE)):
        stream.write((0).to_bytes(4, "little"))
    else:
        stream.write(inp.sequence.to_bytes(4, "little"))


def _otda_serialize_outputs(stream, outputs: list[TransactionOutput], input_index: int, base_type: int) -> None:
    """Serialize outputs for the OTDA preimage based on sighash base type."""
    if base_type == int(SIGHASH.NONE):
        _write_varint(stream, 0)
        return
    if base_type == int(SIGHASH.SINGLE):
        out_count = input_index + 1
        _write_varint(stream, out_count)
        for i in range(out_count):
            if i < input_index:
                stream.write((0xFFFFFFFFFFFFFFFF).to_bytes(8, "little"))
                _write_varint(stream, 0)
            else:
                stream.write(outputs[i].serialize())
        return
    _write_varint(stream, len(outputs))
    for out in outputs:
        stream.write(out.serialize())


def _preimage_otda(
    input_index: int,
    inputs: list[TransactionInput],
    outputs: list[TransactionOutput],
    tx_version: int,
    tx_locktime: int,
) -> bytes:
    """
    OTDA (Original Transaction Digest Algorithm) preimage for Chronicle.
    This is the pre-ForkID original Bitcoin signature digest algorithm.
    Serializes the transaction directly (no hash commitments like BIP143).
    """
    sighash = inputs[input_index].sighash
    base_type = sighash & 0x1F

    stream = BytesIO()

    # nVersion
    stream.write(tx_version.to_bytes(4, "little"))

    # Serialize inputs (ANYONECANPAY: only include the signing input)
    if sighash & SIGHASH.ANYONECANPAY:
        tx_inputs = [(input_index, inputs[input_index])]
    else:
        tx_inputs = list(enumerate(inputs))

    _write_varint(stream, len(tx_inputs))
    for idx, inp in tx_inputs:
        _otda_serialize_input(stream, inp, idx, input_index, base_type)

    # Serialize outputs
    _otda_serialize_outputs(stream, outputs, input_index, base_type)

    # nLockTime
    stream.write(tx_locktime.to_bytes(4, "little"))

    # Sighash type (4 bytes LE)
    stream.write(sighash.to_bytes(4, "little"))

    return stream.getvalue()


def _write_varint(stream, n: int) -> None:
    """Write a Bitcoin varint to a stream."""
    if n < 0xFD:
        stream.write(n.to_bytes(1, "little"))
    elif n <= 0xFFFF:
        stream.write(b"\xfd")
        stream.write(n.to_bytes(2, "little"))
    elif n <= 0xFFFFFFFF:
        stream.write(b"\xfe")
        stream.write(n.to_bytes(4, "little"))
    else:
        stream.write(b"\xff")
        stream.write(n.to_bytes(8, "little"))


def tx_preimage(
    input_index: int,
    inputs: list[TransactionInput],
    outputs: list[TransactionOutput],
    tx_version: int,
    tx_locktime: int,
) -> bytes:
    """
    Calculates and returns the preimage for a specific input index.
    Routes to BIP143 or OTDA based on sighash flags.
    """
    sighash = inputs[input_index].sighash

    if SIGHASH.use_otda(sighash):
        return _preimage_otda(input_index, inputs, outputs, tx_version, tx_locktime)

    # BIP143 path
    # hash previous outs
    if not sighash & SIGHASH.ANYONECANPAY:
        hash_prevouts = hash256(
            b"".join(
                bytes.fromhex(_in.source_txid)[::-1] + _in.source_output_index.to_bytes(4, "little") for _in in inputs
            )
        )
    else:
        hash_prevouts = b"\x00" * 32

    # hash sequence
    if not sighash & SIGHASH.ANYONECANPAY and sighash & 0x1F != SIGHASH.SINGLE and sighash & 0x1F != SIGHASH.NONE:
        hash_sequence = hash256(b"".join(_in.sequence.to_bytes(4, "little") for _in in inputs))
    else:
        hash_sequence = b"\x00" * 32

    # hash outputs
    if sighash & 0x1F != SIGHASH.SINGLE and sighash & 0x1F != SIGHASH.NONE:
        hash_outputs = hash256(b"".join(tx_output.serialize() for tx_output in outputs))
    elif sighash & 0x1F == SIGHASH.SINGLE and input_index < len(outputs):
        hash_outputs = hash256(outputs[input_index].serialize())
    else:
        hash_outputs = b"\x00" * 32

    return _preimage(inputs[input_index], tx_version, tx_locktime, hash_prevouts, hash_sequence, hash_outputs)
