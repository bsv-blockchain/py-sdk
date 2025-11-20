#!/usr/bin/env python3
"""Batch 3 - remaining safe unused variables."""

import re

FIXES_BATCH_3 = [
    # auth tests (5 issues)
    ('tests/bsv/auth/test_metanet_desktop_auth.py', 231, 'params', '_'),
    ('tests/bsv/auth/test_metanet_desktop_auth.py', 574, 'request_payload', '_'),
    ('tests/bsv/auth/test_metanet_desktop_auth.py', 625, 'auth_result', '_'),
    
    # auth fetch coverage (3)
    ('tests/bsv/auth/clients/test_auth_fetch_coverage.py', 205, 'result', '_'),
    ('tests/bsv/auth/clients/test_auth_fetch_coverage.py', 299, 'result', '_'),
    ('tests/bsv/auth/clients/test_auth_fetch_coverage.py', 328, 'result', '_'),
    
    # beef hardening (3)
    ('tests/bsv/beef/test_beef_hardening.py', 152, 'beef', '_'),
    ('tests/bsv/beef/test_beef_hardening.py', 171, 'beef', '_'),
    ('tests/bsv/beef/test_beef_hardening.py', 253, 'beef', '_'),
    
    # address test (3)
    ('tests/bsv/address_test_coverage.py', 138, 'network', '_'),
    ('tests/bsv/address_test_coverage.py', 156, 'network', '_'),
    ('tests/bsv/address_test_coverage.py', 173, 'testnet_prefix', '_'),
    
    # aes_cbc test (2)
    ('tests/bsv/aes_cbc_test_coverage.py', 102, 'decrypted', '_'),
    ('tests/bsv/aes_cbc_test_coverage.py', 165, 'encrypted', '_'),
    
    # beef parity (2)
    ('tests/bsv/beef/test_beef_parity.py', 9, 'beef', '_beef'),
    ('tests/bsv/beef/test_beef_parity.py', 9, 'subject', '_subject'),
]

# Also add more from other files
MORE_FIXES = [
    # chaintracker test
    ('tests/bsv/chaintracker_test_coverage.py', 98, 'header', '_'),
    ('tests/bsv/chaintracker_test_coverage.py', 115, 'header', '_'),
    
    # fee model test
    ('tests/bsv/fee_model_test_coverage.py', 67, 'fee', '_'),
    ('tests/bsv/fee_model_test_coverage.py', 84, 'fee', '_'),
    
    # primitives hash test
    ('tests/bsv/primitives/test_hash_coverage.py', 45, 'result', '_'),
    ('tests/bsv/primitives/test_hash_coverage.py', 62, 'result', '_'),
    
    # primitives symmetric test
    ('tests/bsv/primitives/test_symmetric_coverage.py', 58, 'result', '_'),
    ('tests/bsv/primitives/test_symmetric_coverage.py', 75, 'result', '_'),
]

ALL_FIXES = FIXES_BATCH_3 + MORE_FIXES

def fix_var(filepath, line_num, old_var, new_var):
    """Fix variable."""
    full_path = f'/home/sneakyfox/SDK/py-sdk/{filepath}'
    
    try:
        with open(full_path, 'r') as f:
            lines = f.readlines()
        
        line_idx = line_num - 1
        if 0 <= line_idx < len(lines):
            original = lines[line_idx]
            # Handle assignments
            modified = re.sub(r'\b' + re.escape(old_var) + r'\b', new_var, original, count=1)
            
            if modified != original:
                lines[line_idx] = modified
                with open(full_path, 'w') as f:
                    f.writelines(lines)
                return True
        return False
    except:
        return False

def main():
    print("Batch 3 fixer running...")
    fixed = sum(1 for f, l, o, n in ALL_FIXES if fix_var(f, l, o, n))
    print(f"✅ Fixed: {fixed}/{len(ALL_FIXES)}")
    print(f"Progress: ~{289 + fixed}/780 ({((289 + fixed)/780)*100:.1f}%)")
    return fixed

if __name__ == '__main__':
    main()

