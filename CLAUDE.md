# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

The BSV SDK is a comprehensive Python library for developing scalable applications on the BSV Blockchain. It provides a peer-to-peer approach adhering to SPV (Simplified Payment Verification) with focus on privacy and scalability.

**Repository**: https://github.com/bitcoin-sv/py-sdk
**Package name**: bsv-sdk
**Current version**: 1.0.8
**Python requirement**: >=3.9

## Development Commands

### Installation
```bash
pip install -r requirements.txt
```

### Testing
```bash
# Run full test suite with coverage
pytest --cov=bsv --cov-report=html

# Run specific test file
pytest tests/test_transaction.py

# Run tests with asyncio
pytest tests/bsv/auth/test_auth_peer_basic.py
```

### Building the Package
```bash
# Build distribution packages (requires python3 -m build)
make build

# Or directly:
python3 -m build
```

### Publishing (Maintainers Only)
```bash
make upload_test  # Upload to TestPyPI
make upload       # Upload to PyPI
```

## Code Architecture

### Module Organization

The `bsv` package is organized into functional submodules:

- **Core Transaction Components** (`bsv/transaction.py`, `bsv/transaction_input.py`, `bsv/transaction_output.py`)
  - `Transaction`: Main transaction class with serialization, signing, fee calculation, and broadcasting
  - Supports BEEF (Bitcoin Encapsulated Format) and EF (Extended Format) serialization
  - SPV validation through merkle paths

- **Script System** (`bsv/script/`)
  - `ScriptTemplate`: Abstract base for locking/unlocking scripts
  - Built-in templates: `P2PKH`, `P2PK`, `OpReturn`, `BareMultisig`, `RPuzzle`
  - `Script`: Low-level script operations
  - `Spend`: Script validation engine

- **Keys & Cryptography** (`bsv/keys.py`, `bsv/curve.py`, `bsv/hash.py`)
  - `PrivateKey`, `PublicKey`: ECDSA key management
  - Support for compressed/uncompressed keys
  - WIF format support

- **HD Wallets** (`bsv/hd/`)
  - Full BIP32/39/44 implementation
  - Hierarchical deterministic key derivation
  - Mnemonic phrase support (multiple languages via `hd/wordlist/`)

- **Authentication** (`bsv/auth/`)
  - `Peer`: Central authentication protocol implementation
  - `Certificate`: Certificate handling and verification
  - `SessionManager`: Session lifecycle management
  - `Transport`: Communication layer abstraction
  - PKI-based authentication between peers

- **Wallet** (`bsv/wallet/`)
  - `WalletInterface`: Abstract wallet interface
  - `WalletImpl`: Full wallet implementation
  - `KeyDeriver`: Protocol-based key derivation
  - `CachedKeyDeriver`: Optimized key derivation with caching

- **Broadcasting** (`bsv/broadcasters/`)
  - `Broadcaster`: Interface for transaction broadcasting
  - `arc.py`: ARC broadcaster implementation
  - `whatsonchain.py`: WhatsOnChain broadcaster
  - `default_broadcaster.py`: Default broadcaster selection

- **Chain Tracking** (`bsv/chaintrackers/`)
  - `ChainTracker`: Interface for chain state verification
  - `whatsonchain.py`: WhatsOnChain chain tracker
  - `default.py`: Default chain tracker

- **Storage** (`bsv/storage/`)
  - `Uploader`, `Downloader`: File upload/download utilities
  - Integration with blockchain storage

- **Keystore** (`bsv/keystore/`)
  - Key persistence and retention management
  - Local key-value store implementation

- **BEEF Support** (`bsv/beef/`)
  - `build_beef_v2_from_raw_hexes`: BEEF format construction
  - Transaction validation with merkle proofs

- **Utilities** (`bsv/utils.py`)
  - `Reader`, `Writer`: Binary serialization helpers
  - Varint encoding/decoding
  - Address utilities

### Important Design Patterns

**Lazy Imports**: The `bsv/__init__.py` is intentionally minimal to avoid circular imports. Import specific modules where needed:
```python
from bsv.keys import PrivateKey
from bsv.transaction import Transaction
```

**Async Operations**: Transaction broadcasting and verification are async:
```python
await tx.broadcast()
await tx.verify(chaintracker)
```

**Template Pattern**: Script types use templates that provide `lock()` and `unlock()` methods:
```python
script_template = P2PKH()
locking_script = script_template.lock(address)
unlocking_template = script_template.unlock(private_key)
```

**Source Transactions**: Inputs require source transactions for fee calculation and verification. The SDK tracks UTXOs through linked source transactions rather than external UTXO databases.

**SIGHASH Handling**: Each transaction input has a `sighash` field (defaults to `SIGHASH.ALL | SIGHASH.FORKID`) used during signing.

## Testing Structure

Tests are organized in two locations:
1. **Root-level tests** (`tests/`): Classic test structure with direct imports
2. **Nested tests** (`tests/bsv/`): Mirror the `bsv/` package structure

Test organization by feature:
- `tests/bsv/primitives/`: Core cryptographic primitives
- `tests/bsv/transaction/`: Transaction building and validation
- `tests/bsv/auth/`: Full authentication protocol test suite
- `tests/bsv/wallet/`: Wallet implementation tests
- `tests/bsv/storage/`: Storage system tests
- `tests/bsv/broadcasters/`: Broadcaster integration tests

**Running single test**: Use standard pytest patterns:
```bash
pytest tests/bsv/auth/test_auth_peer_basic.py::test_function_name
pytest -k "test_pattern"
```

## Code Style

- **PEP 8 compliance**: Follow Python standard style guide
- **Type hints**: Use where appropriate (not comprehensive in current codebase)
- **Docstrings**: Document functions, classes, and modules
- **Comments**: Annotate complex logic

## Development Practices

- **Test-Driven Development**: Write tests before or alongside implementation where smart, quick, and reasonable. This helps ensure correctness and prevents regressions.
- Run `pytest --cov=bsv --cov-report=html` to verify test coverage before committing
- All PRs should maintain or improve current test coverage

## BRC-106 Compliance (Script ASM Format)

The SDK implements Assembly (ASM) representation of Bitcoin Script via `Script.from_asm()` and `Script.to_asm()` methods.

**BRC-106 Standard**: https://github.com/bitcoin-sv/BRCs/blob/master/scripts/0106.md

Key requirements from BRC-106:
- Use full English names for op-codes (e.g., "OP_FALSE" not "OP_0")
- Output should always use the most human-readable format
- Multiple input names should parse to the same hex value
- Ensure deterministic translation across different SDKs (Py-SDK, TS-SDK, Go-SDK)

**Current Implementation** (bsv/script/script.py:140-191):
- `from_asm()`: Accepts both "OP_FALSE" and "OP_0", converts to b'\x00'
- `to_asm()`: Currently outputs "OP_0" for b'\x00' (see OPCODE_VALUE_NAME_DICT override at constants.py:343)

**Note**: The current `to_asm()` output may need adjustment to fully comply with BRC-106's human-readability requirement (should output "OP_FALSE" instead of "OP_0").

### Working with ASM
```python
# Parse ASM string to Script
script = Script.from_asm("OP_DUP OP_HASH160 abcd1234 OP_EQUALVERIFY OP_CHECKSIG")

# Convert Script to ASM representation
asm_string = script.to_asm()

# Access script chunks
for chunk in script.chunks:
    print(chunk)  # Prints opcode name or hex data
```

## Important Notes

- The SDK uses `coincurve` for ECDSA operations (not pure Python)
- Encryption uses `pycryptodomex` (not standard `pycryptodome`)
- Network operations require `aiohttp` for async HTTP
- Tests require `pytest-asyncio` for async test support
- Coverage configuration excludes tests and setup.py (see `.coveragerc`)
- Git branches: `master` is main branch, `develop-port` is development branch

## Common Patterns

### Creating and Broadcasting a Transaction
```python
priv_key = PrivateKey(wif_string)
source_tx = Transaction.from_hex(hex_string)

tx_input = TransactionInput(
    source_transaction=source_tx,
    source_txid=source_tx.txid(),
    source_output_index=0,
    unlocking_script_template=P2PKH().unlock(priv_key)
)

tx_output = TransactionOutput(
    locking_script=P2PKH().lock(priv_key.address()),
    change=True
)

tx = Transaction([tx_input], [tx_output])
tx.fee()  # Calculate and distribute fees
tx.sign()  # Sign all inputs
await tx.broadcast()  # Broadcast to network
```

### Working with BEEF Format
```python
# Parse BEEF
tx = Transaction.from_beef(beef_hex)

# Create BEEF
beef_bytes = tx.to_beef()
```

### Script Templates
```python
# P2PKH
p2pkh = P2PKH()
lock_script = p2pkh.lock(address_string)
unlock_template = p2pkh.unlock(private_key)

# OP_RETURN
op_return = OpReturn()
data_script = op_return.lock(['Hello', b'World'])

# Multisig
multisig = BareMultisig()
lock_script = multisig.lock([pubkey1, pubkey2, pubkey3], threshold=2)
unlock_template = multisig.unlock([privkey1, privkey2])
```
