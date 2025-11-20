#!/usr/bin/env python3
"""Fix duplicated string literals in test files."""

import re

# Map of file paths to their duplicated strings and constant names
FIXES = [
    {
        "file": "/home/sneakyfox/SDK/py-sdk/tests/bsv/aes_gcm_test_coverage.py",
        "string": "AES-GCM not available",
        "constant": "SKIP_AES_GCM"
    },
    {
        "file": "/home/sneakyfox/SDK/py-sdk/tests/bsv/beef_test_coverage.py",
        "string": "BEEF module not available",
        "constant": "SKIP_BEEF"
    },
    {
        "file": "/home/sneakyfox/SDK/py-sdk/tests/bsv/broadcasters_test_coverage.py",
        "string": "WhatsOnChainBroadcaster not available",
        "constant": "SKIP_WOC_BROADCASTER"
    },
    {
        "file": "/home/sneakyfox/SDK/py-sdk/tests/bsv/chaintrackers_test_coverage.py",
        "string": "WhatsOnChainTracker not available",
        "constant": "SKIP_WOC_TRACKER"
    },
    {
        "file": "/home/sneakyfox/SDK/py-sdk/tests/bsv/curve_test_coverage.py",
        "string": "Curve operations not available",
        "constant": "SKIP_CURVE"
    },
    {
        "file": "/home/sneakyfox/SDK/py-sdk/tests/bsv/ecdsa_test_coverage.py",
        "string": "ECDSA module not available",
        "constant": "SKIP_ECDSA"
    },
    {
        "file": "/home/sneakyfox/SDK/py-sdk/tests/bsv/encrypted_message_test_coverage.py",
        "string": "Encryption functions not available",
        "constant": "SKIP_ENCRYPTION"
    },
    {
        "file": "/home/sneakyfox/SDK/py-sdk/tests/bsv/fee_models_test_coverage.py",
        "string": "SatoshisPerKilobyte not available",
        "constant": "SKIP_SATOSHIS_PER_KB"
    },
    {
        "file": "/home/sneakyfox/SDK/py-sdk/tests/bsv/headers_client_test_coverage.py",
        "string": "HeadersClient requires parameters",
        "constant": "SKIP_HEADERS_CLIENT"
    },
    {
        "file": "/home/sneakyfox/SDK/py-sdk/tests/bsv/merkle_tree_parent_test_coverage.py",
        "string": "merkle_tree_parent not available",
        "constant": "SKIP_MERKLE_TREE_PARENT"
    },
    {
        "file": "/home/sneakyfox/SDK/py-sdk/tests/bsv/network_test_coverage.py",
        "string": "get_network_config not available",
        "constant": "SKIP_NETWORK_CONFIG"
    },
    {
        "file": "/home/sneakyfox/SDK/py-sdk/tests/bsv/outpoint_test_coverage.py",
        "string": "Outpoint not available",
        "constant": "SKIP_OUTPOINT"
    },
    {
        "file": "/home/sneakyfox/SDK/py-sdk/tests/bsv/primitives_test_coverage.py",
        "string": "Primitives not available",
        "constant": "SKIP_PRIMITIVES"
    },
    {
        "file": "/home/sneakyfox/SDK/py-sdk/tests/bsv/rpc_test_coverage.py",
        "string": "RPC client not available",
        "constant": "SKIP_RPC"
    },
    {
        "file": "/home/sneakyfox/SDK/py-sdk/tests/bsv/sighash_test_coverage.py",
        "string": "Requires valid transaction",
        "constant": "SKIP_VALID_TX"
    },
    {
        "file": "/home/sneakyfox/SDK/py-sdk/tests/bsv/signature_test_coverage.py",
        "string": 'b"test message"',
        "constant": "TEST_MESSAGE",
        "is_bytes": True
    },
    {
        "file": "/home/sneakyfox/SDK/py-sdk/tests/bsv/signed_message_test_coverage.py",
        "string": "sign_message not available",
        "constant": "SKIP_SIGN_MESSAGE"
    },
    {
        "file": "/home/sneakyfox/SDK/py-sdk/tests/bsv/spv_test_coverage.py",
        "string": "SPV module not available",
        "constant": "SKIP_SPV"
    },
    {
        "file": "/home/sneakyfox/SDK/py-sdk/tests/bsv/storage_test_coverage.py",
        "string": "MemoryStorage operations not available",
        "constant": "SKIP_MEMORY_STORAGE"
    },
    {
        "file": "/home/sneakyfox/SDK/py-sdk/tests/bsv/totp_test_coverage.py",
        "string": "generate_totp not available",
        "constant": "SKIP_TOTP"
    },
]

def fix_file(file_path, string_literal, constant_name, is_bytes=False):
    """Fix duplicated string literals in a file."""
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Check if constant already exists
        if constant_name in content:
            print(f"Skipping {file_path} - constant already exists")
            return
        
        # Find import pytest line and add constant after it
        if is_bytes:
            constant_def = f"\n# Constants\n{constant_name} = {string_literal}\n"
        else:
            constant_def = f"\n# Constants for skip messages\n{constant_name} = \"{string_literal}\"\n"
        
        # Insert after import pytest
        content = re.sub(
            r'(import pytest\n)',
            r'\1' + constant_def,
            content,
            count=1
        )
        
        # Replace all occurrences of the string literal
        if is_bytes:
            # For bytes, replace the literal directly
            content = content.replace(string_literal, constant_name)
        else:
            # For strings in pytest.skip()
            content = content.replace(f'pytest.skip("{string_literal}")', f'pytest.skip({constant_name})')
            # Also handle single quotes
            content = content.replace(f"pytest.skip('{string_literal}')", f'pytest.skip({constant_name})')
        
        # Write back
        with open(file_path, 'w') as f:
            f.write(content)
        
        print(f"Fixed {file_path}")
        
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"Error fixing {file_path}: {e}")

def main():
    for fix in FIXES:
        fix_file(
            fix["file"],
            fix["string"],
            fix["constant"],
            fix.get("is_bytes", False)
        )

if __name__ == '__main__':
    main()

