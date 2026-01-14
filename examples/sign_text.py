from bsv import PrivateKey, verify_signed_text

private_key = PrivateKey("L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9")
text = "hello world"

# Sign arbitrary text with bitcoin private key.
address, signature = private_key.sign_text(text)

print("Message:", text)
print("Address:", address)
print("Signature:", signature)

# Verify locally:
print("Local verification result:", verify_signed_text(text, address, signature))

# You can also verify using a webpage: https://www.verifybitcoinmessage.com/
