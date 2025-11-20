#!/usr/bin/env python3
"""Massive unused variable fixer for all remaining test files."""

import re

# Comprehensive list of ALL remaining unused variables in test files
FIXES = [
    # tests/bsv/beef/test_kvstore_beef_e2e.py (remaining 2 from line 415, 466 that weren't fixed)
    ('tests/bsv/beef/test_kvstore_beef_e2e.py', 415, 'header_root', '_'),
    ('tests/bsv/beef/test_kvstore_beef_e2e.py', 466, 'kv', '_'),
    
    # tests/bsv/keystore/test_kvstore_beef_parsing.py (all remaining)
    # These might already be fixed, will check

    # tests/bsv/script/interpreter/test_opcode_parser_coverage.py (remaining 2)
    ('tests/bsv/script/interpreter/test_opcode_parser_coverage.py', 193, 'op', '_'),
    ('tests/bsv/script/interpreter/test_opcode_parser_coverage.py', 208, 'op', '_'),
    
    # tests/bsv/auth/test_metanet_desktop_auth.py (remaining 2)
    ('tests/bsv/auth/test_metanet_desktop_auth.py', 604, 'response', '_'),
    ('tests/bsv/auth/test_metanet_desktop_auth.py', 647, 'response', '_'),
    
    # tests/bsv/beef/test_beef_hardening.py (remaining if any)
    # These might be fixed
    
    # tests/bsv/beef/test_beef_parity.py (special case - need to be careful)
    # Skip for now as these might be intentional
    
    # Additional files from the analysis
    ('tests/bsv/broadcasters_test_coverage.py', 44, 'response', '_'),
    ('tests/bsv/broadcasters_test_coverage.py', 78, 'response', '_'),
    ('tests/bsv/broadcasters_test_coverage.py', 134, 'response', '_'),
    
    # More from various files
    ('tests/bsv/chaintracker_test_coverage.py', 97, 'result', '_'),
    ('tests/bsv/chaintracker_test_coverage.py', 114, 'result', '_'),
    
    ('tests/bsv/fee_model_test_coverage.py', 66, 'result', '_'),
    ('tests/bsv/fee_model_test_coverage.py', 83, 'result', '_'),
    
    ('tests/bsv/primitives/test_hash_coverage.py', 44, 'hash_result', '_'),
    ('tests/bsv/primitives/test_hash_coverage.py', 61, 'hash_result', '_'),
    
    ('tests/bsv/primitives/test_symmetric_coverage.py', 57, 'encrypted', '_'),
    ('tests/bsv/primitives/test_symmetric_coverage.py', 74, 'decrypted', '_'),
    
    ('tests/bsv/script/test_script_coverage.py', 98, 'script', '_'),
    ('tests/bsv/script/test_script_coverage.py', 115, 'script', '_'),
    
    ('tests/bsv/transaction/test_transaction_coverage.py', 145, 'tx', '_'),
    ('tests/bsv/transaction/test_transaction_coverage.py', 162, 'tx', '_'),
]

def fix_unused_var(filepath, line_num, old_var, new_var):
    """Fix unused variable by replacing it."""
    full_path = f'/home/sneakyfox/SDK/py-sdk/{filepath}'
    
    try:
        with open(full_path, 'r') as f:
            lines = f.readlines()
        
        line_idx = line_num - 1
        if 0 <= line_idx < len(lines):
            original = lines[line_idx]
            # Use word boundary to ensure we don't replace partial matches
            modified = re.sub(r'\b' + re.escape(old_var) + r'\b', new_var, original, count=1)
            
            if modified != original:
                lines[line_idx] = modified
                with open(full_path, 'w') as f:
                    f.writelines(lines)
                return True
        return False
    except Exception as e:
        print(f'Error fixing {filepath}:{line_num} - {e}')
        return False

def main():
    print("Massive unused variable fixer running...")
    print(f"Total fixes to attempt: {len(FIXES)}\n")
    
    fixed = 0
    for filepath, line_num, old_var, new_var in FIXES:
        if fix_unused_var(filepath, line_num, old_var, new_var):
            fixed += 1
            if fixed % 10 == 0:
                print(f"✓ {fixed} fixed...")
    
    print(f"\n✅ Fixed: {fixed}/{len(FIXES)}")
    print(f"Progress: ~{301 + fixed}/780 ({((301 + fixed)/780)*100:.1f}%)")
    return fixed

if __name__ == '__main__':
    main()

