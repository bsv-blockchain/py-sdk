# HD Wallet Module - BIP32/BIP39/BIP44 Implementation

This module provides equivalent functionality to Go-SDK's `compat/bip32` and `compat/bip39` packages. The Python SDK organizes HD wallet functionality in a single `bsv.hd` module rather than separate compatibility packages.

## Overview

The `bsv.hd` module implements:
- **BIP39**: Mnemonic phrase generation and seed derivation
- **BIP32**: Hierarchical Deterministic (HD) key derivation
- **BIP44**: Multi-account HD wallet structure

## Equivalence Mapping: Go-SDK ↔ Python-SDK

### BIP39 Functions

| Go-SDK (`compat/bip39`) | Python-SDK (`bsv.hd.bip39`) | Notes |
|-------------------------|----------------------------|-------|
| `NewEntropy(bitSize)` | `mnemonic_from_entropy()` (generates random if None) | Python generates 256-bit entropy by default |
| `NewMnemonic(entropy)` | `mnemonic_from_entropy(entropy, lang='en')` | Python supports multiple languages (en, zh-cn) |
| `NewSeed(mnemonic, password)` | `seed_from_mnemonic(mnemonic, lang='en', passphrase='', prefix='mnemonic')` | Python uses `passphrase` instead of `password` |
| `NewSeedWithErrorChecking(mnemonic, password)` | `seed_from_mnemonic()` (always validates) | Python always validates mnemonic |
| `IsMnemonicValid(mnemonic)` | `validate_mnemonic(mnemonic, lang='en')` | Python raises exception on invalid, returns None on valid |
| `EntropyFromMnemonic(mnemonic)` | Not directly exposed | Can be derived from mnemonic validation |
| `SetWordList(list)` | `WordList.load_wordlist(lang)` | Python uses language-based wordlists |
| `GetWordList()` | `WordList.load_wordlist(lang)` | Python returns language-specific list |

### BIP32 Functions

| Go-SDK (`compat/bip32`) | Python-SDK (`bsv.hd.bip32`) | Notes |
|-------------------------|----------------------------|-------|
| `NewMaster(seed, net)` | `master_xprv_from_seed(seed, network=Network.MAINNET)` | Python uses Network enum |
| `NewKeyFromString(xPriv)` | `Xprv(xprv)` | Constructor accepts string or bytes |
| `GenerateHDKeyFromMnemonic(mnemonic, password, net)` | `bip32_derive_xprv_from_mnemonic(mnemonic, lang, passphrase, prefix, path, network)` | Python supports custom paths |
| `GetHDKeyChild(hdKey, num)` | `xkey.ckd(index)` | Method on Xprv/Xpub objects |
| `GetHDKeyByPath(hdKey, chain, num)` | `ckd(xkey, path)` | Python uses string paths like "m/44'/0'/0'/0/1" |
| `GetPrivateKeyByPath(hdKey, chain, num)` | `xprv.private_key()` after derivation | Access private key from Xprv |
| `GetPublicKeyByPath(hdKey, chain, num)` | `xpub.public_key()` after derivation | Access public key from Xpub |
| `GetExtendedPublicKey(hdKey)` | `xprv.xpub()` | Convert Xprv to Xpub |
| `Child(num)` | `ckd(index)` | Method on extended key objects |

### Key Types

| Go-SDK | Python-SDK | Notes |
|--------|-----------|-------|
| `*ExtendedKey` | `Xprv` or `Xpub` | Python has separate classes for private/public |
| `ExtendedKey.String()` | `str(xprv)` or `str(xpub)` | String representation (base58) |
| `ExtendedKey.Child(num)` | `xkey.ckd(index)` | Child key derivation |

## Usage Examples

### BIP39: Generate Mnemonic and Seed

**Go-SDK:**
```go
import (
    "github.com/bsv-blockchain/go-sdk/compat/bip39"
)

// Generate entropy
entropy, _ := bip39.NewEntropy(256)

// Create mnemonic
mnemonic, _ := bip39.NewMnemonic(entropy)

// Generate seed
seed := bip39.NewSeed(mnemonic, "password")
```

**Python-SDK:**
```python
from bsv.hd import mnemonic_from_entropy, seed_from_mnemonic

# Generate mnemonic (entropy generated automatically)
mnemonic = mnemonic_from_entropy()

# Generate seed
seed = seed_from_mnemonic(mnemonic, passphrase="password")
```

### BIP32: Create Master Key and Derive Children

**Go-SDK:**
```go
import (
    "github.com/bsv-blockchain/go-sdk/compat/bip32"
    chaincfg "github.com/bsv-blockchain/go-sdk/transaction/chaincfg"
)

// Create master key from seed
masterKey, _ := bip32.NewMaster(seed, &chaincfg.MainNet)

// Derive child key
childKey, _ := bip32.GetHDKeyChild(masterKey, 0)

// Get private key
privKey, _ := bip32.GetPrivateKeyByPath(masterKey, 0, 0)
```

**Python-SDK:**
```python
from bsv.hd import master_xprv_from_seed, ckd
from bsv.constants import Network

# Create master key from seed
master_xprv = master_xprv_from_seed(seed, network=Network.MAINNET)

# Derive child key
child_xprv = master_xprv.ckd(0)

# Get private key
priv_key = child_xprv.private_key()
```

### BIP32: Derive from Mnemonic

**Go-SDK:**
```go
import (
    "github.com/bsv-blockchain/go-sdk/compat/bip32"
    chaincfg "github.com/bsv-blockchain/go-sdk/transaction/chaincfg"
)

masterKey, _ := bip32.GenerateHDKeyFromMnemonic(
    mnemonic, 
    "password", 
    &chaincfg.MainNet,
)

childKey, _ := bip32.GetHDKeyByPath(masterKey, 0, 0)
```

**Python-SDK:**
```python
from bsv.hd import bip32_derive_xprv_from_mnemonic, ckd
from bsv.constants import Network

# Derive master key from mnemonic
master_xprv = bip32_derive_xprv_from_mnemonic(
    mnemonic,
    lang='en',
    passphrase='password',
    network=Network.MAINNET
)

# Derive child using path
child_xprv = ckd(master_xprv, "m/0/0")
```

### BIP44: Multi-Account Wallet Structure

**Go-SDK:**
```go
// BIP44 path: m/44'/coin'/account'/change/address_index
// Go-SDK uses GetHDKeyByPath with chain and num
accountKey, _ := bip32.GetHDKeyByPath(masterKey, 0, 0)
```

**Python-SDK:**
```python
from bsv.hd import bip44_derive_xprv_from_mnemonic, ckd

# BIP44 path: m/44'/coin'/account'/change/address_index
# Python uses string paths
master_xprv = bip44_derive_xprv_from_mnemonic(mnemonic)

# Derive account
account_xprv = ckd(master_xprv, "m/44'/0'/0'")

# Derive receiving address
receiving_xprv = ckd(account_xprv, "m/0/0")
```

## Key Differences

### 1. Language Support
- **Go-SDK**: Single wordlist (English by default, can be changed)
- **Python-SDK**: Multiple language support (English, Chinese Simplified) via `lang` parameter

### 2. Path Derivation
- **Go-SDK**: Uses separate `chain` and `num` parameters or numeric indices
- **Python-SDK**: Uses string-based paths like `"m/44'/0'/0'/0/1"` (BIP32 standard notation)

### 3. Key Types
- **Go-SDK**: Single `ExtendedKey` type that can be private or public
- **Python-SDK**: Separate `Xprv` and `Xpub` classes with type safety

### 4. Error Handling
- **Go-SDK**: Returns `(result, error)` tuples
- **Python-SDK**: Raises exceptions on errors

### 5. Network Handling
- **Go-SDK**: Uses `chaincfg.Params` struct
- **Python-SDK**: Uses `Network` enum (MAINNET, TESTNET)

## Additional Python-SDK Features

The Python SDK provides additional convenience functions not present in Go-SDK's compat packages:

- `bip32_derive_xprvs_from_mnemonic()`: Derive multiple keys at once
- `bip32_derive_xkeys_from_xkey()`: Derive range of keys from extended key
- `bip44_derive_xprv_from_mnemonic()`: BIP44-specific derivation
- `bip44_derive_xprvs_from_mnemonic()`: BIP44 batch derivation
- `Xpub.from_xprv()`: Convert private to public extended key
- `xprv.address()`: Get address directly from extended key
- `xpub.address()`: Get address from extended public key

## Migration Guide

When migrating code from Go-SDK to Python-SDK:

1. **Replace imports:**
   - `compat/bip39` → `bsv.hd.bip39`
   - `compat/bip32` → `bsv.hd.bip32`

2. **Update function calls:**
   - `bip39.NewMnemonic()` → `mnemonic_from_entropy()`
   - `bip39.NewSeed()` → `seed_from_mnemonic()`
   - `bip32.NewMaster()` → `master_xprv_from_seed()`
   - `bip32.GetHDKeyChild()` → `xkey.ckd()`

3. **Handle errors:**
   - Go's `if err != nil` → Python's `try/except`

4. **Update types:**
   - `*ExtendedKey` → `Xprv` or `Xpub`
   - `chaincfg.Params` → `Network` enum

## References

- [BIP32 Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP44 Specification](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- [Go-SDK compat/bip32](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/compat/bip32)
- [Go-SDK compat/bip39](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/compat/bip39)

