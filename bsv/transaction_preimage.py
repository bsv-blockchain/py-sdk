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


def tx_preimage(
    input_index: int,
    inputs: list[TransactionInput],
    outputs: list[TransactionOutput],
    tx_version: int,
    tx_locktime: int,
) -> bytes:
    """
    Calculates and returns the preimage for a specific input index.
    """
    sighash = inputs[input_index].sighash

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
