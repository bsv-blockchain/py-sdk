from typing import List

from bsv import PrivateKey

# Master private keys:
alice = PrivateKey()
bob = PrivateKey()

# Master public keys:
alice_pub = alice.public_key()
bob_pub = bob.public_key()

# To pay Alice, they agree on an invoice number and then Bob derives a key where he can pay Alice.
payment_key = alice_pub.derive_child(bob, "AMZN-44-1191213")

# The key can be converted to an address if desired...
print(payment_key.address())

# To unlock the coins, Alice derives the private key with the same invoice number, using Bob's public key.
payment_priv = alice.derive_child(bob_pub, "AMZN-44-1191213")

# The key can be converted to WIF if desired...
print(payment_priv.wif())

# To check, Alice can convert the private key back into an address.
assert payment_priv.public_key().address() == payment_key.address()
