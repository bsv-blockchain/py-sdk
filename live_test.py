import asyncio
import logging
from bsv import (
    PrivateKey, P2PKH, Transaction, TransactionInput, TransactionOutput
)
from bsv.fee_models.live_policy import LivePolicy
from bsv.keys import PublicKey

logging.basicConfig(level=logging.INFO)
logging.getLogger("bsv.fee_models.live_policy").setLevel(logging.DEBUG)

async def main():
    """
    A live test script to send BSV.

    Instructions:
    1. Fund the SENDER_WIF with some BSV. You can get a WIF from a new wallet or use one you have.
    2. Go to a block explorer like https://whatsonchain.com and find a transaction
       where you received funds to the sender's address.
    3. Copy the 'raw transaction hex' of that transaction and paste it into SOURCE_TX_HEX.
    4. Update SOURCE_OUTPUT_INDEX to the correct index (usually 0 or 1) that corresponds
       to the UTXO you want to spend.
    5. Run the script: `python live_test.py`
    """

    # --- CONFIGURATION - PLEASE EDIT THESE VALUES ---

    # 1. The private key of the wallet that has funds.
    #    You can generate one using create_wallet.py, or use an existing one.
    SENDER_WIF = "Kwr1hjXs7E9uCKknaKLXDHoKMLZ37EbnNU7b4bHx6qLh2tPiwkNf"

    # 2. The address you want to send BSV to.
    RECIPIENT_ADDRESS = "1CaS8TVYPWdGhHukE3Q1nxqN1NMPQYUUnJ" # The address from your wallet_info.txt

    # 3. The raw hex of a transaction where you received BSV to the SENDER_WIF address.
    SOURCE_TX_HEX = '010000000309c18e11424ab71674d4bc9e390cc928ed27c001316ea607e6abd8e5fd996849010000006a473044022061b06684612b3d72e824430d93ccf09b04cd6872f5f116ea3214565938ecb0d802203178f8ecca4146852adee9ff5d8078aeb4fb9412c24cfe2694bcd9e3edd18de6412102a773b3a312dc7e0488d978b4fb2089ef466780cbdb639c49af97ffe06fca671cffffffff3bc3ce7935248145779ebdff453a22f9b39819155ba93bde35aba7944a8a64d4030000006a473044022033b1a478bd834349abb768e788dbbebd44f71bbe3bc618f689cd9e7c2defb35f022032582013de69e4fb62ad90b2a0299f21e76956f01032399ef3bc1445cf15331e41210387c8dc9c38330bec6118692b864da8f2a18e6cc732ba106c0d803dfbc74932ccffffffff3bc3ce7935248145779ebdff453a22f9b39819155ba93bde35aba7944a8a64d4040000006a473044022061d20e11129c9c4beb5eeee26652de855614011e05b2aa28b5f2b00a571c4fe902205c6795d9461a1d409c54b1586237d7f9f8ca5b847dbb6200ebb7e7a5dc16d9d141210387c8dc9c38330bec6118692b864da8f2a18e6cc732ba106c0d803dfbc74932ccffffffff02f59e0000000000001976a9146d2d67bed1863b2e39794df441532b5ed02f136588ac5b240000000000001976a914e2d61c65f720d6f8020b5211c3945f65ad7da3f988ac00000000'  # From https://whatsonchain.com/tx/831e5b10660ff612ec3a0f0ae15cc74573366c7423ee7efbe94a457b30a7f323

    # 4. The output index from the source transaction that you want to spend.
    SOURCE_OUTPUT_INDEX = 0  # This is the output that sent funds to 1AxH3ishqURaeNUvuQoqNQXELdDyBti52v

    # 5. Amount to send in satoshis (1 BSV = 100,000,000 satoshis)
    SATOSHIS_TO_SEND = 500  # A small amount for a test

    # --- END OF CONFIGURATION ---

    if "L1xx" in SENDER_WIF or "0100000001xx" in SOURCE_TX_HEX:
        print("ERROR: Please update the SENDER_WIF and SOURCE_TX_HEX variables in the script.")
        return

    sender_priv_key = PrivateKey(SENDER_WIF)
    sender_address = sender_priv_key.address()
    print(f"\nSender Address: {sender_address}")

    # Create a transaction object from the source hex
    source_tx = Transaction.from_hex(SOURCE_TX_HEX)

    # Create the transaction input from the UTXO we want to spend
    tx_input = TransactionInput(
        source_transaction=source_tx,
        source_txid=source_tx.txid(),
        source_output_index=SOURCE_OUTPUT_INDEX,
        unlocking_script_template=P2PKH().unlock(sender_priv_key),
    )

    # Create the output to the recipient
    tx_output_recipient = TransactionOutput(
        locking_script=P2PKH().lock(RECIPIENT_ADDRESS),
        satoshis=SATOSHIS_TO_SEND
    )

    # Create the change output back to the sender
    tx_output_change = TransactionOutput(
        locking_script=P2PKH().lock(sender_address),
        change=True
    )

    # Build, sign, and broadcast the transaction
    print("\nFetching live fee policy...")
    live_policy = LivePolicy.get_instance() # Use a safer fallback rate
    fee_rate = await live_policy.current_rate_sat_per_kb()
    print(f"Using fee rate: {fee_rate} sat/kB")

    tx = Transaction([tx_input], [tx_output_recipient, tx_output_change])
    await tx.fee(live_policy)  # Automatically calculate fee and adjust change

    tx.sign()

    print(f"\nBroadcasting transaction... Raw Hex: {tx.hex()}")
    response = await tx.broadcast()
    print(f"Broadcast Response: {response}")
    print(f"Transaction ID: {tx.txid()}")
    print(f"\nCheck on WhatsOnChain: https://whatsonchain.com/tx/{tx.txid()}")

if __name__ == "__main__":
    asyncio.run(main())
