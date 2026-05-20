import math

from bsv import (
    P2PKH,
    FeeModel,
    PrivateKey,
    Transaction,
    TransactionInput,
    TransactionOutput,
)


class ExampleFeeModel(FeeModel):
    """
    Represents the "satoshis per kilobyte" transaction fee model.
    Additionally, if the transactions version number is equal to 3301,
    then no fees are payed to the miner.
    """

    def __init__(self, value: int):
        self.value = value

    def compute_fee(self, tx) -> int:
        """
        Computes the fee for a given transaction.

        :param tx: The transaction for which a fee is to be computed.
        :returns: The fee in satoshis for the transaction.
        """

        def get_varint_size(i: int) -> int:
            if i > 2**32:
                return 9
            elif i > 2**16:
                return 5
            elif i > 253:
                return 3
            else:
                return 1

        # Version 3301 transactions are free :)
        if tx.version == 3301:
            return 0

        # Compute the (potentially estimated) size of the transaction
        size = 4  # version
        size += get_varint_size(len(tx.inputs))  # number of inputs

        for tx_input in tx.inputs:
            size += 40  # txid, output index, sequence number
            if tx_input.unlocking_script:
                script_length = len(tx_input.unlocking_script.serialize())
            elif tx_input.unlocking_script_template:
                script_length = tx_input.unlocking_script_template.estimated_unlocking_byte_length()
            else:
                raise ValueError(
                    "All inputs must have an unlocking script or an unlocking script template for sat/kb fee computation."
                )
            size += get_varint_size(script_length)  # unlocking script length
            size += script_length  # unlocking script

        size += get_varint_size(len(tx.outputs))  # number of outputs

        for tx_output in tx.outputs:
            size += 8  # satoshis
            length = len(tx_output.locking_script.serialize())
            size += get_varint_size(length)  # script length
            size += length  # script

        size += 4  # lock time

        # We'll use math.ceil to ensure the miners get the extra satoshi.
        fee = math.ceil((size / 1000) * self.value)
        return fee


def main():
    # Example usage of out custom broadcaster:
    private_key = PrivateKey("L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9")
    public_key = private_key.public_key()

    source_tx = Transaction.from_hex(
        "0100000001d43b53af268f65ca069f74d136114649e0eaf937c670952b70c5ecbb0ad7ba01010000006b48304502210097930e1a4b7e4be3d3ee3f61f19ed1066bb02967f008eff35800d0a840c2e8b60220152ec14f254e666b1b22f4c9e87226c811b4e87f19158bfd2d06329fefffaf53c1210359b25103c255f3a9c2fbcd11a6ec842b21e6cb1bb9c27d2e8a3322aae0e6e8a0ffffffff0278000000000000001976a9147610cb8647332db7bb7f526360fde5f7842fa57988acbb7f0100000000001976a9147610cb8647332db7bb7f526360fde5f7842fa57988ac00000000"
    )

    tx = Transaction(
        [
            TransactionInput(
                source_transaction=source_tx,
                source_txid=source_tx.txid(),
                source_output_index=0,
                unlocking_script_template=P2PKH().unlock(private_key),
            )
        ],
        [
            TransactionOutput(locking_script=P2PKH().lock(public_key.address()), satoshis=100),
            TransactionOutput(locking_script=P2PKH().lock(public_key.address()), change=True),  # Change output...
        ],
    )

    tx.version = 3301

    # The fee of our tx is calculated after calling the fee() method.
    # If out transactions input amount is more than is needed for the fee,
    # then, the leftower amount goes to the change output, that we set above.
    tx.fee(ExampleFeeModel(10))

    # Signing should always be done after the fee adjustment.
    tx.sign()

    print("Fee was calculated using the custom fee model.")
    print("Fee amount:", tx.get_fee())  # Should be 0, since we set tx.version to 3301...
    print("Change amount:", tx.outputs[1].satoshis)


main()
