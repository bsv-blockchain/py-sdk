#!/usr/bin/env python3
"""Mass fix unused variables in test files."""

import re
import os

# Comprehensive list of unused variable fixes
# Format: (file, line, old_var, new_var, pattern_type)
FIXES = [
    # AES GCM test file
    ('tests/bsv/aes_gcm_test_coverage.py', 76, 'decrypted', '_', 'assign'),
    ('tests/bsv/aes_gcm_test_coverage.py', 93, 'decrypted', '_', 'assign'),
    ('tests/bsv/aes_gcm_test_coverage.py', 135, 'encrypted', '_', 'assign'),
    
    # Auth fetch coverage
    ('tests/bsv/auth/clients/test_auth_fetch_coverage.py', 205, 'result', '_', 'assign'),
    ('tests/bsv/auth/clients/test_auth_fetch_coverage.py', 299, 'result', '_', 'assign'),
    ('tests/bsv/auth/clients/test_auth_fetch_coverage.py', 328, 'result', '_', 'assign'),
    
    # Auth integration
    ('tests/bsv/auth/clients/test_auth_fetch_integration.py', 149, 'nonce_b64', '_', 'assign'),
    
    # Auth server
    ('tests/bsv/auth/test_auth_server_full.py', 111, 'requested_certs', '_', 'assign'),
    
    # Metanet desktop auth
    ('tests/bsv/auth/test_metanet_desktop_auth.py', 231, 'params', '_', 'assign'),
    ('tests/bsv/auth/test_metanet_desktop_auth.py', 574, 'request_payload', '_', 'assign'),
    ('tests/bsv/auth/test_metanet_desktop_auth.py', 625, 'auth_result', '_', 'assign'),
    ('tests/bsv/auth/test_metanet_desktop_auth.py', 689, 'args', '_', 'assign'),
    ('tests/bsv/auth/test_metanet_desktop_auth.py', 1227, 'peer', '_', 'assign'),
    
    # Certificate coverage
    ('tests/bsv/auth/test_verifiable_certificate_coverage.py', 269, 'verifiable_cert_no_verifier', '_', 'assign'),
    
    # Base58
    ('tests/bsv/base58_test_coverage.py', 87, 'result', '_', 'assign'),
    
    # BEEF tests
    ('tests/bsv/beef/test_beef_builder_methods.py', 9, 'btx', '_', 'assign'),
    ('tests/bsv/beef/test_beef_comprehensive.py', 313, 'beef2', '_', 'assign'),
    ('tests/bsv/beef/test_beef_hardening.py', 152, 'beef', '_', 'unpack'),
    ('tests/bsv/beef/test_beef_hardening.py', 171, 'beef', '_', 'unpack'),
    ('tests/bsv/beef/test_beef_hardening.py', 253, 'beef', '_', 'unpack'),
    ('tests/bsv/beef/test_beef_parity.py', 9, 'beef', '_', 'unpack'),
    ('tests/bsv/beef/test_beef_parity.py', 9, 'subject', '_', 'unpack'),
    ('tests/bsv/beef/test_kvstore_beef_e2e.py', 415, 'header_root', '_', 'assign'),
    ('tests/bsv/beef/test_kvstore_beef_e2e.py', 466, 'kv', '_', 'assign'),
]

def fix_unused_var(filepath, line_num, old_var, new_var, pattern_type='assign'):
    """Fix unused variable at specific line."""
    full_path = f'/home/sneakyfox/SDK/py-sdk/{filepath}'
    if not os.path.exists(full_path):
        return False, "File not found"
    
    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        line_idx = line_num - 1
        if line_idx < 0 or line_idx >= len(lines):
            return False, "Line out of range"
        
        original = lines[line_idx]
        
        # Different patterns for different contexts
        if pattern_type == 'assign':
            # Simple assignment: var = something
            modified = re.sub(r'\b' + re.escape(old_var) + r'\b', new_var, original, count=1)
        elif pattern_type == 'unpack':
            # Unpacking: var1, var2 = something
            modified = re.sub(r'\b' + re.escape(old_var) + r'\b', new_var, original)
        else:
            modified = re.sub(r'\b' + re.escape(old_var) + r'\b', new_var, original, count=1)
        
        if modified != original:
            lines[line_idx] = modified
            with open(full_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            return True, "Fixed"
        
        return False, "No change needed"
    except Exception as e:
        return False, str(e)

def main():
    print("Mass fixing unused variables...")
    fixed_count = 0
    failed = []
    
    for filepath, line_num, old_var, new_var, pattern_type in FIXES:
        success, msg = fix_unused_var(filepath, line_num, old_var, new_var, pattern_type)
        if success:
            fixed_count += 1
            print(f"✓ {filepath}:{line_num}")
        else:
            failed.append((filepath, line_num, msg))
            print(f"✗ {filepath}:{line_num} - {msg}")
    
    print(f"\n✓ Fixed {fixed_count} issues")
    if failed:
        print(f"✗ Failed {len(failed)} issues")

if __name__ == '__main__':
    main()

