from bsv import Script, Spend

spend = Spend(
    {
        # Replace with the TXID of the transaction where you are spending from
        "sourceTXID": "00" * 32,
        # Replace with the output index you are redeeming
        "sourceOutputIndex": 0,
        # Replace with the number of satoshis in the output you are redeeming.
        "sourceSatoshis": 1,
        # Replace with the locking script you are spending.
        "lockingScript": Script.from_asm("OP_3 OP_ADD OP_7 OP_EQUAL"),
        # Replace with the version of the new spending transaction.
        "transactionVersion": 1,
        # Other inputs from the spending transaction that are needed for verification.
        # The SIGHASH flags used in signatures may not require this (if SIGHASH_ANYONECANPAY was used).
        # This is an ordered array of TransactionInputs with the input whose script we're currently evaluating missing.
        "otherInputs": [],
        # TransactionOutputs from the spending transaction that are needed for verification.
        # The SIGHASH flags used in signatures may nnt require this (if SIGHASH_NONE was used).
        # If SIGHASH_SINGLE is used, it's possible for this to be a sparse array, with only the index corresponding to
        # the inputIndex populated.
        "outputs": [],
        # This is the index of the input whose script we are currently evaluating.
        "inputIndex": 0,
        # This is the unlocking script that we are evaluating, to see if it unlocks the source output.
        "unlockingScript": Script.from_asm("OP_4"),
        # This is the sequence number of the input whose script we are currently evaluating.
        "inputSequence": 0xFFFFFFFF,
        # This is the lock time of the spending transaction.
        "lockTime": 0,
    }
)

valid = spend.validate()

print("Verified:", valid)
assert valid
