# CHANGELOG

All notable changes to this project will be documented in this file. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Table of Contents

- [Unreleased](#unreleased)
- [1.0.11 - 2025-11-23](#1011---2025-11-23)
- [1.0.10 - 2025-10-30](#1010---2025-10-30)
- [1.0.9 - 2025-09-30](#109---2025-09-30)
- [1.0.8 - 2025-08-13](#108---2025-08-13)
- [1.0.7.1- 2025-07-28](#1071---2025-07-28)
- [1.0.7- 2025-07-28](#107---2025-07-28)
- [1.0.6.1- 2025-07-03](#1061---2025-07-03)
- [1.0.6- 2025-06-30](#106---2025-06-30)
- [1.0.5- 2025-05-30](#105---2025-05-30)
- [1.0.4- 2025-04-28](#104---2025-04-28)
- [1.0.3 - 2025-03-26](#103---2025-03-26)
- [1.0.2 - 2025-02-28](#102---2025-02-28)
- [1.0.1 - 2025-01-09](#101---2025-01-09)
- [1.0.1 - 2025-01-09](#101---2025-01-09)
- [1.0.0 - 2024-12-23](#100---2024-12-23)
- [0.5.2 - 2024-09-02](#052---2024-09-02)
- [0.1.0 - 2024-04-09](#010---2024-04-09)

---
## [1.0.12] - 2025-11-25

### Added
- Complete Wallet infrastructure with serializers, substrates, and implementations for full wallet functionality
- Authentication system including peer authentication, certificates, session management, and HTTP transport
- BEEF (Background Evaluation Extended Format) transaction format support with builder, serializer, and validator
- Script interpreter with comprehensive opcode support, stack operations, and script execution engine
- Storage interfaces and implementations for data upload/download with encryption support
- Overlay tools including lookup resolver, SHIP broadcaster, historian, and host reputation tracker
- Registry client for overlay network management
- Identity client with contacts manager for identity and contact management
- Headers client for blockchain header synchronization
- Keystore with local key-value store implementation supporting encrypted storage
- Additional cryptographic primitives: Schnorr signatures, DRBG (Deterministic Random Bit Generator), AES-GCM encryption
- Compatibility modules for BSM (Bitcoin Signed Message) and ECIES encryption
- TOTP (Time-based One-Time Password) support for two-factor authentication
- BIP-276 payment destination encoding support
- PushDrop token protocol implementation
- Teranode broadcaster support

### Changed
- Refactored `bsv/utils.py` monolithic module into organized submodules under `bsv/utils/` for better maintainability
- Enhanced broadcaster implementations with improved error handling and status categorization
- Updated chain trackers with block headers service integration
- Improved transaction handling with extended BEEF support and validation
- Reorganized entire test suite into `tests/bsv/` structure with comprehensive coverage tests (455 files changed, 74,468+ additions)

### Notes
- **No breaking changes** - All existing APIs remain fully compatible
- Legacy tests continue to pass but have been superseded by new comprehensive test structure
- Test organization now follows a more modular and maintainable structure under `tests/bsv/`
- Added extensive test coverage across all modules ensuring code quality and reliability

---
## [1.0.11] - 2025-11-23

### Changed
- Converted `LivePolicy` fee model from asynchronous to synchronous implementation
- Replaced `default_http_client()` (async) with `default_sync_http_client()` (sync) in `LivePolicy`
- **`Transaction.fee()` can now be called from both synchronous and asynchronous functions without any special handling**
- Removed unused `asyncio` and `inspect` imports from `transaction.py`
- Simplified `Transaction.fee()` implementation by removing async helper methods

### Fixed
- Updated all `LivePolicy` tests to use synchronous mocks instead of `AsyncMock`
- Fixed `test_transaction_fee_with_default_rate` to use explicit fee model for deterministic testing
- Removed `asyncio.run()` calls from `LivePolicy` test suite

### Notes
- This change is transparent to users - `tx.fee()` works seamlessly in both sync and async contexts without any API changes
- You can call `tx.fee()` inside `async def` functions or regular `def` functions - it works the same way
- All existing code and documentation remain compatible with no modifications required

---
## [1.0.10] - 2025-10-30

### Changed
- Updated Script ASM output to use BRC-106 compliant format (outputs `OP_FALSE` instead of `OP_0` for better human readability)
- Converted `test_arc_ef_or_rawhex.py` from unittest.TestCase to pytest style for better async test handling

### Fixed
- Added missing test dependencies to requirements.txt: `ecdsa~=0.19.0` and `pytest-cov~=6.0.0`
- Fixed pytest configuration by adding `asyncio_default_fixture_loop_scope` to eliminate deprecation warnings
- Updated test expectations in `test_scripts.py` to match BRC-106 compliant ASM output
- Resolved all pytest warnings for a clean test output (154 tests passing with zero warnings)


---
## [1.0.9] - 2025-09-30

### Added
- Integrated `LivePolicy` for dynamic fee computations with caching and fallback mechanisms.
 [ts-sdk#343](https://github.com/bsv-blockchain/ts-sdk/pull/343).

---
## [1.0.8] - 2025-08-13

### Security
- Applied measures for vulnerability reported on [ts-sdk#334](https://github.com/bsv-blockchain/ts-sdk/issues/334).


---
## [1.0.7.1] - 2025-07-28

### Changed
- Incremented version in `__init__.py` to 1.0.7.1.

### Security
- Updated `aiohttp` and `setuptools` dependencies to use minimum version constraints.
- Redacted private key in threshold signature example for security.

---
## [1.0.7] - 2025-07-28

### Fixed
- Implemented default broadcasters for GorillaPool mainnet and testnet.
- - Updated examples to use new broadcaster functions.

### Added
- Introduced `default_broadcaster` with configurable options for testnet and custom ARC configurations.
- Added function to set API key from constant.py for Taal mainnet and testnet (`taal_broadcaster`, `taal_testnet_broadcaster`).



## [1.0.6.1] - 2025-07-03

### Fixed
Bug Fix default_http_client and add async ARC broadcasting example 

- Replaced `default_sync_http_client` with `DefaultHttpClient` in `default_http_client`.
- Introduced a new `test_async_arc.py` example demonstrating asynchronous ARC broadcasting and transaction status checking.

## [1.0.6] - 2025-06-30

### Added
- Introduced `SyncHttpClient` for synchronous HTTP operations
- Extended ARC broadcaster with synchronous methods: `sync_broadcast`, `check_transaction_status`, and `categorize_transaction_status`
- Updated ARC configuration to include optional `SyncHttpClient` support
- Added examples, tests, and utilities for synchronous transactions

### Changed
- Updated `SyncHttpClient` to inherit from `HttpClient` for consistency
- Refactored `fetch` into higher-level HTTP methods: `get` and `post`
- Simplified ARC broadcaster by using `get` and `post` methods for sync operations
- Enhanced error handling and response processing in ARC transactions
- Updated tests and examples to align with refactored `SyncHttpClient`

---
## [1.0.5] - 2025-05-30

### Added
Introducing an implementation of Shamir's Secret Sharing scheme for securely splitting and recovering private keys. 

The update includes the following:

- KeyShares, Polynomial, and PointInFiniteField classes to manage key splitting logic

- Integrity verification for share validation

- Robust error handling during reconstruction

- Comprehensive unit tests

- Examples demonstrating the use and behavior of the implemented methods

The implementation is designed to follow the functionality and interface of the existing TypeScript SDK. Compatibility has been verified.


---
## [1.0.4] - 2025-04-28

### Fixed
Remove debug print statement from MerklePath.trim() method and unnecessary import statement

### Added
add step-by-step guide for sending BSV & minting NFTs

Adds a beginner-friendly tutorial that covers:
* environment setup and dependency installation
* key / address generation
* sending BSV transactions
* creating & broadcasting 1Sat Ordinals NFTs
* explanation of inputs, outputs and key terms

### Changed
Enable regular hex format broadcasting when source transactions are unavailable
Enhance the ARC broadcaster to dynamically select between EF and regular hex formats based on the availability of source transactions. This update addresses scenarios such as receiving raw hex via P2P payment destination Paymail capabilities.
Additionally, unit tests have been added to cover this feature.


---
## [1.0.3] - 2025-03-26

### Fixed
Previously, the default fee rate was hardcoded to 10 satoshis per kilobyte. This update allows users to configure the default fee rate via the TRANSACTION_FEE_RATE variable in constants.py or through the environment file.

### Added
A test for the default fee rate has also been added.

### Changed
Optimized transaction preimage calculation by refactoring the tx_preimage function to directly compute the preimage for a specified input, avoiding unnecessary computation for all inputs
Achieved a 3× performance improvement in scenarios with 250 inputs, based on benchmarking


## [1.0.2] - 2025-02-28

### Added
- BIP32_DERIVATION_PATH environment variable for customizing default derivation paths
- Dedicated BIP32 derivation functions with clearer interface
- BIP44-specific functions that build on the BIP32 foundation
- Comprehensive tests for HD wallet key derivation consistency
- Enhanced error messages for hardened key derivation attempts from xpub keys

### Fixed
- PUSHDATA opcode length parsing now uses unsigned integer reading methods (read_uint8, read_uint16_le, read_uint32_le) instead of signed integer methods to prevent incorrect chunk parsing with large data lengths
- Proper handling of edge cases in Script parsing including length 0 and incomplete length specifications
- Serialization/deserialization consistency for various PUSHDATA operations

### Changed
- Refined HD wallet key derivation interface while maintaining backward compatibility
- Improved error messages for invalid derivation attempts
- Marked legacy derivation functions as deprecated while maintaining compatibility


---
## [1.0.1] - 2025-01-09

### Added
- Enhanced WhatsOnChainBroadcaster network handling:
 - Added support for Network enum initialization (Network.MAINNET/Network.TESTNET)
 - Added robust backward compatibility for string network parameters ('main'/'test'/'mainnet'/'testnet')
 - Added input validation and clear error messages for invalid network parameters
 - Added type hints and docstrings for better code clarity
- Added comprehensive test suite for WhatsOnChainBroadcaster:
 - Added test cases for Network enum initialization
 - Added test cases for string-based network parameters
 - Added validation tests for invalid network inputs
 - Added URL construction validation tests

---


## [1.0.0] - 2024-12-23

### Added
- Fixed miner-related bugs.
- Improved documentation and updated the PyPI version.
- Implemented bug fixes and improvements based on feedback from the Yenpoint user test.

---

## [0.5.2] - 2024-09-02

### Added
- Basic functions developed by the Script team.

---

## [0.1.0] - 2024-04-09

### Added
- Initial release.

---

### Template for New Releases

Replace `X.X.X` with the new version number and `YYYY-MM-DD` with the release date:

