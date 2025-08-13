# BSV SDK

[![build](https://github.com/bitcoin-sv/py-sdk/actions/workflows/build.yml/badge.svg)](https://github.com/bitcoin-sv/py-sdk/actions/workflows/build.yml)
[![PyPI version](https://img.shields.io/pypi/v/bsv-sdk)](https://pypi.org/project/bsv-sdk)
[![Python versions](https://img.shields.io/pypi/pyversions/bsv-sdk)](https://pypi.org/project/bsv-sdk)


Welcome to the BSV Blockchain Libraries Project, the comprehensive Python SDK designed to provide an updated and unified layer for developing scalable applications on the BSV Blockchain. This SDK addresses the limitations of previous tools by offering a fresh, peer-to-peer approach, adhering to SPV, and ensuring privacy and scalability.
## Table of Contents

1. [Objective](#objective)
2. [Getting Started](#getting-started)
3. [Features & Deliverables](#features--deliverables)
4. [Documentation](#documentation)
5. [Tutorial](#Tutorial)
5. [Contribution Guidelines](#contribution-guidelines)
6. [Support & Contacts](#support--contacts)

## Objective

The BSV Blockchain Libraries Project aims to structure and maintain a middleware layer of the BSV Blockchain technology stack. By facilitating the development and maintenance of core libraries, it serves as an essential toolkit for developers looking to build on the BSV Blockchain.

## Getting Started

### Requirements

Python 3.9 or higher
pip package manager

### Installation

```bash
pip install bsv-sdk
```

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


## Documentation

Detailed documentation of the SDK with code examples can be found at [BSV Skills Center](https://docs.bsvblockchain.org/guides/sdks/py).

You can also refer to the [User Test Report](./docs/Py-SDK%20User%20Test%20Report.pdf) for insights and feedback provided by
[Yenpoint](https://yenpoint.jp/).

## Beginner Tutorial
#### [Step-by-Step BSV Tutorial: Sending BSV and NFTs](./docs/beginner_tutorial.md)

This beginner-friendly guide will walk you through sending BSV (Bitcoin SV) and creating NFTs using the BSV Python SDK. We'll take it step-by-step so you can learn at your own pace.

## Contribution Guidelines

We're always looking for contributors to help us improve the project. Whether it's bug reports, feature requests, or pull requests - all
contributions are welcome.

1. **Fork & Clone**: Fork this repository and clone it to your local machine.
2. **Set Up**: Run `pip install -r requirements.txt` to install all dependencies.
3. **Make Changes**: Create a new branch and make your changes.
4. **Test**: Ensure all tests pass by running `pytest --cov=bsv --cov-report=html`.
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
