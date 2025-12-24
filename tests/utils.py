import os

def save_private_key_to_file(privkey, filepath):
    """Save a PrivateKey to a file in hex (NOT ENCRYPTED, for test/dev use only). If the file exists, do not overwrite."""
    if os.path.exists(filepath):
        print(f"File '{filepath}' already exists. Not overwriting.")
        return
    with open(filepath, "w") as f:
        f.write(privkey.hex())

def load_private_key_from_file(filepath):
    """Load a PrivateKey from a file in hex (NOT ENCRYPTED, for test/dev use only)."""
    from bsv.keys import PrivateKey
    with open(filepath, "r") as f:
        return PrivateKey.from_hex(f.read().strip())
