from typing import List

from bsv import PrivateKey

# Master private keys:
alice = PrivateKey()
bob = PrivateKey()

# Master public keys:
alice_pub = alice.public_key()
bob_pub = bob.public_key()


# Sometimes, there is a legitimate reason to do "public key derivation" from a key,
# so that anyone can link a master key to a child key, like in BIP32.
# To accomplish this, rather than creating a new algorithm,
# we just use a private key that everyone already knows: the number 1.
print("Public keys:")
print(alice_pub.derive_child(PrivateKey(1), "1").hex())
print(alice_pub.derive_child(PrivateKey(1), "2").hex())
print(alice_pub.derive_child(PrivateKey(1), "Bitcoin SV").hex())
print(alice_pub.derive_child(PrivateKey(1), "2-tempo-1").hex())


# Because everyone knows the number 1, everyone can derive Alice's public keys
# with these invoice numbers.
# But only Alice can derive the corresponding private keys:
print("Private keys:")
print(alice.derive_child(PrivateKey(1).public_key(), "1").hex())
print(alice.derive_child(PrivateKey(1).public_key(), "2").hex())
print(alice.derive_child(PrivateKey(1).public_key(), "Bitcoin SV").hex())
print(alice.derive_child(PrivateKey(1).public_key(), "2-tempo-1").hex())
