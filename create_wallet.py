from bsv import PrivateKey


def main():
    """
    Generates a new BSV sender and receiver wallet and saves the info to wallet_info.txt.
    """
    # Generate sender address (Address A)
    priv_key_a = PrivateKey()
    wif_a = priv_key_a.wif()  # Wallet Import Format
    address_a = priv_key_a.address()

    # Generate receiver address (Address B)
    priv_key_b = PrivateKey()
    wif_b = priv_key_b.wif()
    address_b = priv_key_b.address()

    # Print out the keys and addresses
    print("\n===== SENDER INFORMATION =====")
    print(f"Private Key: {wif_a}")
    print(f"Address: {address_a}")

    print("\n===== RECEIVER INFORMATION =====")
    print(f"Private Key: {wif_b}")
    print(f"Address: {address_b}")

    # Save data to file for easy reference
    with open("wallet_info.txt", "w") as f:
        f.write(f"Sender Private Key: {wif_a}\n")
        f.write(f"Sender Address: {address_a}\n\n")
        f.write(f"Receiver Private Key: {wif_b}\n")
        f.write(f"Receiver Address: {address_b}\n")
    print("\nThis information has been saved to wallet_info.txt")

if __name__ == "__main__":
    main()