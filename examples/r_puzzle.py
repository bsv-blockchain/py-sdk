import asyncio
from typing import Optional

from bsv import (
    P2PKH,
    SIGHASH,
    BroadcastResponse,
    OpCode,
    Point,
    PrivateKey,
    Script,
    ScriptTemplate,
    Spend,
    Transaction,
    TransactionInput,
    TransactionOutput,
    WhatsOnChainBroadcaster,
    curve,
    curve_multiply,
    encode_pushdata,
    hash256,
    to_unlock_script_template,
    tx_preimage,
)

"""
This example demonstrates the implementation of a custom script template for constructing specialized locking and unlocking scripts. 
Specifically, it focuses on creating a script template for an R-Puzzle, a script that requires proof of knowledge of a value k for unlocking,
without actually revealing k.

For further details on R-Puzzles, visit: https://bsv.brc.dev/scripts/0017.
"""


class RPuzzle(ScriptTemplate):

    def __init__(self, puzzle_type: str = "raw"):
        """
        Constructs an R Puzzle template instance for a given puzzle type.

        :param puzzle_type: Denotes the type of puzzle to create ('raw', 'SHA1', 'SHA256', 'HASH256', 'RIPEMD160', 'HASH160')
        """
        assert puzzle_type in ["raw", "SHA1", "SHA256", "HASH256", "RIPEMD160", "HASH160"]
        self.type = puzzle_type

    def lock(self, value: bytes) -> Script:
        """
        Creates an R puzzle locking script for a given R value or R value hash.

        :param value: A byte array representing the R value or its hash.
        :returns: An R puzzle locking script.
        """
        chunks = [
            OpCode.OP_OVER,
            OpCode.OP_3,
            OpCode.OP_SPLIT,
            OpCode.OP_NIP,
            OpCode.OP_1,
            OpCode.OP_SPLIT,
            OpCode.OP_SWAP,
            OpCode.OP_SPLIT,
            OpCode.OP_DROP,
        ]
        if self.type != "raw":
            chunks.append(getattr(OpCode, f"OP_{self.type}"))
        chunks.append(encode_pushdata(value))
        chunks.append(OpCode.OP_EQUALVERIFY)
        chunks.append(OpCode.OP_CHECKSIG)
        return Script(b"".join(chunks))

    def unlock(
        self,
        k: int,
        private_key: Optional[PrivateKey] = PrivateKey(),
        sign_outputs: str = "all",
        anyone_can_pay: bool = False,
    ):
        """
        Creates a function that generates an R puzzle unlocking script along with its signature and length estimation.

        :param k: The K-value used to unlock the R-puzzle.
        :param private_key: The private key used for signing the transaction.
        :param sign_outputs: The signature scope for outputs ('all', 'none', 'single').
        :param anyone_can_pay: Flag indicating if the signature allows for other inputs to be added later.
        :returns: An object containing the `sign` and `estimate_length` functions.
        """

        def sign(tx: Transaction, input_index: int) -> Script:
            sighash = SIGHASH.FORKID
            if sign_outputs == "all":
                sighash |= SIGHASH.ALL
            elif sign_outputs == "none":
                sighash |= SIGHASH.NONE
            elif sign_outputs == "single":
                sighash |= SIGHASH.SINGLE
            if anyone_can_pay:
                sighash |= SIGHASH.ANYONECANPAY

            tx.inputs[input_index].sighash = sighash

            preimage = tx.preimage(input_index)

            sig = private_key.sign(preimage, hasher=hash256, k=k) + sighash.to_bytes(1, "little")
            pubkey_for_script = private_key.public_key().serialize()

            return Script(encode_pushdata(sig) + encode_pushdata(pubkey_for_script))

        def estimated_unlocking_byte_length() -> int:
            # public key (1+33) + signature (1+71)
            # Note: We add 1 to each element's length because of the associated OP_PUSH
            return 106

        return to_unlock_script_template(sign, estimated_unlocking_byte_length)


async def main():
    private_key = PrivateKey("L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9")
    private_key.public_key()

    k = PrivateKey().int()

    k_priv = PrivateKey()
    k = k_priv.int()
    r = k_priv.public_key().point().x  # R = k*G, R.x

    r_bytes = r.to_bytes(32, byteorder="big")
    if r_bytes[0] > 0x7F:
        r_bytes = b"\x00" + r_bytes

    source_tx = Transaction.from_hex(
        "0100000001d43b53af268f65ca069f74d136114649e0eaf937c670952b70c5ecbb0ad7ba01010000006b48304502210097930e1a4b7e4be3d3ee3f61f19ed1066bb02967f008eff35800d0a840c2e8b60220152ec14f254e666b1b22f4c9e87226c811b4e87f19158bfd2d06329fefffaf53c1210359b25103c255f3a9c2fbcd11a6ec842b21e6cb1bb9c27d2e8a3322aae0e6e8a0ffffffff0278000000000000001976a9147610cb8647332db7bb7f526360fde5f7842fa57988acbb7f0100000000001976a9147610cb8647332db7bb7f526360fde5f7842fa57988ac00000000"
    )

    tx1 = Transaction(
        [
            TransactionInput(
                source_transaction=source_tx,
                source_txid=source_tx.txid(),
                source_output_index=0,
                unlocking_script_template=P2PKH().unlock(private_key),
            )
        ],
        [
            TransactionOutput(locking_script=RPuzzle().lock(r_bytes), satoshis=100),
            TransactionOutput(locking_script=P2PKH().lock(private_key.address()), change=True),
        ],
    )

    tx1.fee()
    tx1.sign()

    res = await tx1.broadcast(WhatsOnChainBroadcaster("test"))
    if isinstance(res, BroadcastResponse):
        print("Tx1 has been broadcast:", res.txid)
    else:
        print("Broadcast failed. Error:", res.description)

    tx2 = Transaction(
        [
            TransactionInput(
                source_transaction=tx1,
                source_txid=tx1.txid(),
                source_output_index=0,
                unlocking_script_template=RPuzzle().unlock(k),
            )
        ],
        [TransactionOutput(locking_script=P2PKH().lock(private_key.address()), change=True)],
    )

    tx2.fee()
    tx2.sign()

    # Execute localy:
    spend = Spend(
        {
            "sourceTXID": tx2.inputs[0].source_txid,
            "sourceOutputIndex": tx2.inputs[0].source_output_index,
            "sourceSatoshis": tx1.outputs[0].satoshis,
            "lockingScript": tx1.outputs[0].locking_script,
            "transactionVersion": tx2.version,
            "otherInputs": [],
            "inputIndex": 0,
            "unlockingScript": tx2.inputs[0].unlocking_script,
            "outputs": tx2.outputs,
            "inputSequence": tx2.inputs[0].sequence,
            "lockTime": tx2.locktime,
        }
    )
    assert spend.validate()

    # Broadcast:
    res = await tx2.broadcast(WhatsOnChainBroadcaster("test"))
    if isinstance(res, BroadcastResponse):
        print("Tx2 has been broadcast:", res.txid)
    else:
        print("Broadcast failed. Error:", res.description)


asyncio.run(main())
