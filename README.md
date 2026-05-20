# BSV SDK

[![build](https://github.com/bsv-blockchain/py-sdk/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/bsv-blockchain/py-sdk/actions/workflows/build.yml)
[![Coverage](https://img.shields.io/badge/coverage-84.6%25-green)](https://github.com/bsv-blockchain/py-sdk/actions/workflows/build.yml)
[![PyPI version](https://img.shields.io/pypi/v/bsv-sdk)](https://pypi.org/project/bsv-sdk)
[![Python versions](https://img.shields.io/pypi/pyversions/bsv-sdk)](https://pypi.org/project/bsv-sdk)

Welcome to the BSV Blockchain Libraries Project, the comprehensive Python SDK designed to provide an updated and unified layer for developing scalable applications on the BSV Blockchain. This SDK addresses the limitations of previous tools by offering a fresh, peer-to-peer approach, adhering to SPV, and ensuring privacy and scalability.
## Table of Contents

1. [Objective](#objective)
2. [Getting Started](#getting-started)
3. [Features & Deliverables](#features--deliverables)
4. [Documentation](#documentation)
5. [Testing & Quality](#testing--quality)
6. [Tutorial](#tutorial)
7. [Contribution Guidelines](#contribution-guidelines)
8. [Support & Contacts](#support--contacts)

## Objective

The BSV Blockchain Libraries Project aims to structure and maintain a middleware layer of the BSV Blockchain technology stack. By facilitating the development and maintenance of core libraries, it serves as an essential toolkit for developers looking to build on the BSV Blockchain.

## Getting Started

### Requirements

Python 3.10 or higher
pip package manager

### Installation

```bash
pip install bsv-sdk
```

### Development Setup

For contributors and developers, install with test and dev dependencies:

```bash
pip install -e .[test,dev]
```

This installs the package in development mode along with all testing and development dependencies.

### Basic Usage

```python
import asyncio
from bsv import (
    PrivateKey, P2PKH, Transaction, TransactionInput, TransactionOutput
)


# Replace with your private key (WIF format)
PRIVATE_KEY = 'KyEox4cjFbwR---------VdgvRNQpDv11nBW2Ufak'

# Replace with your source tx which contains UTXO that you want to spend (raw hex format)
SOURCE_TX_HEX = '01000000018128b0286d9c6c7b610239bfd8f6dcaed43726ca57c33aa43341b2f360430f23020000006b483045022100b6a60f7221bf898f48e4a49244e43c99109c7d60e1cd6b1f87da30dce6f8067f02203cac1fb58df3d4bf26ea2aa54e508842cb88cc3b3cec9b644fb34656ff3360b5412102cdc6711a310920d8fefbe8ee73b591142eaa7f8668e6be44b837359bfa3f2cb2ffffffff0201000000000000001976a914dd2898df82e086d729854fc0d35a449f30f3cdcc88acce070000000000001976a914dd2898df82e086d729854fc0d35a449f30f3cdcc88ac00000000'

async def create_and_broadcast_transaction():
    priv_key = PrivateKey(PRIVATE_KEY)
    source_tx = Transaction.from_hex(SOURCE_TX_HEX)

    tx_input = TransactionInput(
        source_transaction=source_tx,
        source_txid=source_tx.txid(),
        source_output_index=1,
        unlocking_script_template=P2PKH().unlock(priv_key),
    )

    tx_output = TransactionOutput(
        locking_script=P2PKH().lock(priv_key.address()),
        change=True
    )

    tx = Transaction([tx_input], [tx_output], version=1)

    tx.fee()
    tx.sign()

    await tx.broadcast()

    print(f"Transaction ID: {tx.txid()}")
    print(f"Raw hex: {tx.hex()}")

if __name__ == "__main__":
    asyncio.run(create_and_broadcast_transaction())
```

For a more detailed tutorial and advanced examples, check our [Documentation](#documentation).

## Features & Deliverables

### Advanced Transaction Building:

* Support for P2PKH, P2PK, OP_RETURN, and BareMultisig scripts
* Automated fee calculation and change output management
* Custom script development
* Support for various SIGHASH types


### HD Wallet Capabilities:

* Full BIP32/39/44 implementation for hierarchical deterministic wallets
* Multiple language support for mnemonic phrases (English, Chinese)
* Advanced key derivation and management


### SPV & Validation:

* Built-in SPV verification with BEEF format support
* Merkle proof validation
* Efficient transaction broadcast with Arc
* Support for chain tracking and verification


### Wallet Infrastructure:

* Complete wallet implementation with BIP270 payment protocols
* Action serializers for creating, signing, and broadcasting transactions
* Substrate support for various wallet backends (HTTP, Wire protocol)
* Key derivation with caching for performance


### Authentication & Security:

* Peer-to-peer authentication with certificate management
* Session handling with automatic renewal
* Multiple transport protocols (HTTP, simplified transports)
* Encrypted communications with AES-GCM


### Script Interpreter:

* Full Bitcoin script execution engine
* Comprehensive opcode support (arithmetic, crypto, stack operations)
* Configurable script flags for different validation modes
* Thread-based execution for complex scripts


### Storage & Overlay Services:

* Upload/download interfaces with encryption support
* Overlay network tools (SHIP broadcaster, lookup resolver)
* Historian for tracking overlay data
* Host reputation tracking
* Registry client for overlay management


### Identity & Registry:

* Identity client with certificate management
* Contacts manager for identity relationships
* Registry services for overlay network coordination
* Headers client for blockchain synchronization


### Enhanced Cryptography & Protocols:

* Schnorr signatures for advanced signing schemes
* DRBG (Deterministic Random Bit Generator)
* BSM (Bitcoin Signed Message) compatibility
* ECIES encryption compatibility
* TOTP (Time-based One-Time Password) 2FA support
* BIP-276 payment destination encoding
* PushDrop token protocol implementation
* Teranode broadcaster support


## Documentation

Detailed documentation of the SDK with code examples can be found at [BSV Skills Center](https://docs.bsvblockchain.org/guides/sdks/py).

- [Dynamic fee models](./docs/fee_models.md)

You can also refer to the [User Test Report](./docs/Py-SDK%20User%20Test%20Report.pdf) for insights and feedback provided by
[Yenpoint](https://yenpoint.jp/).

## Testing & Quality

This project maintains high code quality standards with comprehensive test coverage:

- **5,400+ tests** covering core functionality
- **84.6%+ code coverage** across the entire codebase
- Automated testing with GitHub Actions CI/CD
- Python 3.10, 3.11, 3.12, and 3.13 supported

### Running Tests & Coverage

```bash
# Install test dependencies
pip install -e .[test]

# Run all tests
pytest

# Run tests with coverage analysis (includes branch coverage)
pytest --cov=bsv --cov-branch --cov-report=html --cov-report=term

# View detailed coverage report
xdg-open htmlcov/index.html
```

We welcome contributions that improve test coverage, especially in currently under-tested areas.

### Chronicle Live Tests

The SDK includes a comprehensive live test suite for the Chronicle network upgrade, located in `tests/bsv/live/`. These tests validate real transaction building, signing, script execution, and broadcasting across all sighash flag combinations and script types.

#### Mock Tests (no network required)

250 tests that build real `Transaction` objects, sign them with real keys, and validate every input through the `Spend` script interpreter — without touching the network:

```bash
# Run all mock live tests
pytest tests/bsv/live/ -v -m "not testnet"
```

| Test File | Tests | Coverage |
|-----------|-------|----------|
| `test_live_sighash_matrix.py` | 102 | All 12 sighash flags x 2 tx versions x P2PKH/P2PK/Multisig |
| `test_live_chronicle_opcodes.py` | 43 | 10 restored opcodes (OP_VER, OP_VERIF, OP_2MUL, OP_SUBSTR, etc.) x BIP143 + OTDA |
| `test_live_standard_opcodes.py` | 93 | Stack, arithmetic, bitwise, crypto, flow control opcodes |
| `test_live_malleability.py` | 12 | 6 malleability restrictions x v1-rejects/v2-relaxes pairs |

#### Testnet Broadcast Tests (requires funded key)

98 tests that broadcast real transactions to BSV testnet via ARC, verifying end-to-end correctness:

```bash
# Set funded testnet private key
export FUNDED_TESTNET_WIF="cYourTestnetWifHere"

# Run testnet broadcast tests
pytest tests/bsv/live/test_live_testnet.py -v
```

#### Mainnet broadcast tests (optional, real funds)

Same structure as testnet, but uses mainnet APIs and `.utxo_pool_mainnet.json`. **Costs real BSV**; use a dedicated key.

```bash
export FUNDED_MAINNET_WIF="YourMainnetWifHere"
pytest tests/bsv/live/test_live_mainnet.py -v -m mainnet
```

**How it works:**

1. **UTXO Fan-out**: A single funded UTXO is split into ~130 small outputs via a fan-out transaction
2. **Two-step transactions**: For non-P2PKH scripts (P2PK, Multisig, custom opcodes), a setup tx converts the P2PKH UTXO into the test script type, then a second tx spends it with the target sighash
3. **Spend pre-validation**: Every test tx is validated through the `Spend` interpreter before broadcasting
4. **UTXO persistence**: The UTXO pool is saved to `.utxo_pool.json` between test runs. Failed broadcasts automatically return UTXOs to the pool
5. **ARC headers**: Uses `X-SkipScriptValidation` header to bypass ARC's script validator (which may lag behind the node's Chronicle support)

| Test Class | Tests | Coverage |
|------------|-------|----------|
| `TestTestnetP2PKH` | 24 | P2PKH x 12 sighash flags x 2 tx versions |
| `TestTestnetP2PK` | 24 | P2PK x 12 sighash flags x 2 tx versions |
| `TestTestnetMultisig` | 24 | 2-of-3 BareMultisig x 12 sighash flags x 2 tx versions |
| `TestTestnetChronicleOpcodes` | 20 | 10 Chronicle opcodes x BIP143 + OTDA paths |
| `TestTestnetStandardOpcodes` | 7 | ADD, SUB, MUL, CAT, HASH160, IF/ELSE, CHECKSIGVERIFY |

**Sighash flags tested** (all 12):

| Flag | Value | Algorithm |
|------|-------|-----------|
| `ALL_FORKID` | 0x41 | BIP143 |
| `NONE_FORKID` | 0x42 | BIP143 |
| `SINGLE_FORKID` | 0x43 | BIP143 |
| `ALL_ANYONECANPAY_FORKID` | 0xC1 | BIP143 |
| `NONE_ANYONECANPAY_FORKID` | 0xC2 | BIP143 |
| `SINGLE_ANYONECANPAY_FORKID` | 0xC3 | BIP143 |
| `ALL_FORKID_CHRONICLE` | 0x61 | OTDA |
| `NONE_FORKID_CHRONICLE` | 0x62 | OTDA |
| `SINGLE_FORKID_CHRONICLE` | 0x63 | OTDA |
| `ALL_ANYONECANPAY_FORKID_CHRONICLE` | 0xE1 | OTDA |
| `NONE_ANYONECANPAY_FORKID_CHRONICLE` | 0xE2 | OTDA |
| `SINGLE_ANYONECANPAY_FORKID_CHRONICLE` | 0xE3 | OTDA |

## Beginner Tutorial
#### [Step-by-Step BSV Tutorial: Sending BSV and NFTs](./docs/beginner_tutorial.md)

This beginner-friendly guide will walk you through sending BSV (Bitcoin SV) and creating NFTs using the BSV Python SDK. We'll take it step-by-step so you can learn at your own pace.

## Contribution Guidelines

We're always looking for contributors to help us improve the project. Whether it's bug reports, feature requests, or pull requests - all
contributions are welcome.

1. **Fork & Clone**: Fork this repository and clone it to your local machine.
2. **Set Up**: Install in development mode with test dependencies:
   ```bash
   pip install -e .[test]
   ```
3. **Make Changes**: Create a new branch and make your changes.
4. **Test**: Ensure all tests pass and check code coverage:
   ```bash
   # Run tests with coverage report
   pytest --cov=bsv --cov-report=html --cov-report=term

   # View detailed HTML coverage report
   open htmlcov/index.html  # or xdg-open htmlcov/index.html on Linux
   ```

   Help us improve coverage by adding tests for uncovered areas!
5. **Commit**: Commit your changes and push to your fork.
6. **Pull Request**: Open a pull request from your fork to this repository.

For more details, check the [contribution guidelines](./CONTRIBUTING.md).

## Support & Contacts
Project Owners: Thomas Giacomo and Darren Kellenschwiler
Development Team Lead: sCrypt
Maintainer: Ken Sato @ Yenpoint inc. & Yosuke Sato @ Yenpoint inc.
For questions, bug reports, or feature requests, please open an issue on GitHub or contact us directly.
## License

The license for the code in this repository is the Open BSV License. Refer to [LICENSE.txt](./LICENSE.txt) for the license text.

Thank you for being a part of the BSV Blockchain ecosystem. Let's build the future of BSV Blockchain together!
