from bsv.keys import PrivateKey

# Create a private key (or you can use an existing one)

private_key = PrivateKey()
#if you want to use a sepecific private key.
#private_key = PrivateKey("L1X1sP2C------------ur5LQHeJWDoW")

public_key = private_key.public_key()
address = public_key.address()

print(f"Original Private Key (WIF): {private_key.wif()}")
print(f"Original Address: {address}")

 # Create 5 shares, with a threshold of 3 required for recovery

this_threshold = 3
this_total_shares = 5
backup_shares = private_key.to_backup_shares(this_threshold, this_total_shares)
# Print the shares

print("\nGenerated Shares:")
for i, share in enumerate(backup_shares):
    print(f"Share {i + 1}: {share}")

# Select 3 of the 5 shares to recover the private key

selected_shares = [backup_shares[1], backup_shares[2], backup_shares[4]]
print(f"\nRecovering with shares:  {selected_shares}")

# Recover the private key
recovered_key = PrivateKey.from_backup_shares(selected_shares)

print(f"Recovered Private Key (WIF): {recovered_key.wif()}")
print(f"Recovered Address: {recovered_key.address()}")

# Verify the keys match
is_keys_match = private_key.wif() == recovered_key.wif()
print(f"\nOriginal and recovered keys match: {is_keys_match}")


#Check compatibility with Ts-sdk library


ts_privatekey = "Kyig4TeeVahiY8---------------QwPXRed57MiYUS"
# Original Address: 179UiTpk4mqjQv6CJ4NoZqxwURym4uwV4v
#these shares are created from the ts-sdk library.
ts_shares = {
    "Share1": "7bG9x34Mae9oJCFgdb4NqgDDf687hfUxpa2xhx66nQrB.4qtoDQ4vTL25YbmGKWU9qN8g4gYV9f1HLajXKtp5RXU1.3.436b37b4",
    "Share2": "AsMwU9H3LpTM1T11nU2i3dJHtXR1DyYXoJyfE8GKiMYN.9Euk7J9RuPYwtNvJSkK7Q5uNyq3v8HnSVBgTkxAL3zyx.3.436b37b4",
    "Share3": "4Zne9ueQgdE7xRt3WAB5AVwDEyxZ5DdvepAC41edPrhh.AxaokRsrRgsdLp37SdBgWF4RKX7hJmUDpJK7WdbFaK6s.3.436b37b4",
    "Share4": "2cjyXyvQrzrFdzXCBaiTpPuCwNDPUDg4XyXADrxgoJkX.63v3CxqFhy9SUNPusijUjcyzqhwBvNDvy2nJdQmWWm4y.3.436b37b4",
    "Share5": "HvZamWCw4bDe2iNaWJW9Sk4ESoBEufMxDMy4LLHUEKQj.HC5VmyQC3vtioq3t1rXtQgVupe47m8GeGFL8q2kBg48o.3.436b37b4"
}

selected_shares2 = [ts_shares["Share1"], ts_shares["Share2"], ts_shares["Share4"]]
print(f"\nRecovering with shares:  {selected_shares2}")

# Recover the private key
recovered_key2 = PrivateKey.from_backup_shares(selected_shares2)

print(f"Recovered Private Key (WIF): {recovered_key2.wif()}")
print(f"Recovered Address: {recovered_key2.address()}")

is_keys_match = ts_privatekey == recovered_key2.wif()
print(f"\nOriginal and recovered keys match: {is_keys_match}")

