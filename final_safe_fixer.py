#!/usr/bin/env python3
"""Final safe fixer - batch fix all remaining safe issues."""

import re
import os

# Comprehensive list of all safe unused variable fixes
# Format: (file, line, old_var, new_var)
SAFE_FIXES = [
    # tests/bsv/beef/test_kvstore_beef_e2e.py (9 issues)
    ('tests/bsv/beef/test_kvstore_beef_e2e.py', 857, 'spends', '_'),
    ('tests/bsv/beef/test_kvstore_beef_e2e.py', 873, 'meta_cert', '_'),
    ('tests/bsv/beef/test_kvstore_beef_e2e.py', 886, 'result', '_'),
    ('tests/bsv/beef/test_kvstore_beef_e2e.py', 915, 'meta_result', '_'),
    ('tests/bsv/beef/test_kvstore_beef_e2e.py', 980, 'kv_result', '_'),
    ('tests/bsv/beef/test_kvstore_beef_e2e.py', 1024, 'result', '_'),
    ('tests/bsv/beef/test_kvstore_beef_e2e.py', 1053, 'action_result', '_'),
    
    # tests/bsv/keystore/test_kvstore_beef_parsing.py (9 issues)
    ('tests/bsv/keystore/test_kvstore_beef_parsing.py', 54, 'beef_bytes', '_'),
    ('tests/bsv/keystore/test_kvstore_beef_parsing.py', 64, 'result', '_'),
    ('tests/bsv/keystore/test_kvstore_beef_parsing.py', 105, 'result', '_'),
    ('tests/bsv/keystore/test_kvstore_beef_parsing.py', 121, 'spends', '_'),
    ('tests/bsv/keystore/test_kvstore_beef_parsing.py', 135, 'result', '_'),
    ('tests/bsv/keystore/test_kvstore_beef_parsing.py', 148, 'result', '_'),
    ('tests/bsv/keystore/test_kvstore_beef_parsing.py', 161, 'result', '_'),
    ('tests/bsv/keystore/test_kvstore_beef_parsing.py', 179, 'result', '_'),
    ('tests/bsv/keystore/test_kvstore_beef_parsing.py', 197, 'result', '_'),
    
    # tests/bsv/http_client_test_coverage.py (8 issues)  
    ('tests/bsv/http_client_test_coverage.py', 54, 'response', '_'),
    ('tests/bsv/http_client_test_coverage.py', 71, 'response', '_'),
    ('tests/bsv/http_client_test_coverage.py', 88, 'response', '_'),
    ('tests/bsv/http_client_test_coverage.py', 102, 'response', '_'),
    ('tests/bsv/http_client_test_coverage.py', 116, 'response', '_'),
    ('tests/bsv/http_client_test_coverage.py', 130, 'response', '_'),
    ('tests/bsv/http_client_test_coverage.py', 156, 'response', '_'),
    ('tests/bsv/http_client_test_coverage.py', 184, 'response', '_'),
    
    # tests/bsv/identity/test_contacts_manager_coverage.py (6 issues)
    ('tests/bsv/identity/test_contacts_manager_coverage.py', 123, 'result', '_'),
    ('tests/bsv/identity/test_contacts_manager_coverage.py', 134, 'result', '_'),
    ('tests/bsv/identity/test_contacts_manager_coverage.py', 156, 'result', '_'),
    ('tests/bsv/identity/test_contacts_manager_coverage.py', 168, 'result', '_'),
    ('tests/bsv/identity/test_contacts_manager_coverage.py', 180, 'result', '_'),
    ('tests/bsv/identity/test_contacts_manager_coverage.py', 216, 'result', '_'),
    
    # tests/bsv/network/test_woc_client_coverage.py (6 issues)
    ('tests/bsv/network/test_woc_client_coverage.py', 42, 'tx', '_'),
    ('tests/bsv/network/test_woc_client_coverage.py', 60, 'balance', '_'),
    ('tests/bsv/network/test_woc_client_coverage.py', 78, 'utxos', '_'),
    ('tests/bsv/network/test_woc_client_coverage.py', 96, 'history', '_'),
    ('tests/bsv/network/test_woc_client_coverage.py', 114, 'headers', '_'),
    ('tests/bsv/network/test_woc_client_coverage.py', 132, 'merkle', '_'),
]

def fix_unused_var_safe(filepath, line_num, old_var, new_var):
    """Safely fix unused variable."""
    full_path = f'/home/sneakyfox/SDK/py-sdk/{filepath}'
    
    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        line_idx = line_num - 1
        if line_idx < 0 or line_idx >= len(lines):
            return False, "Line out of range"
        
        original = lines[line_idx]
        # Simple word boundary replacement
        modified = re.sub(r'\b' + re.escape(old_var) + r'\b', new_var, original, count=1)
        
        if modified != original:
            lines[line_idx] = modified
            with open(full_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            return True, "Fixed"
        
        return False, "No change"
    except Exception as e:
        return False, str(e)

def main():
    print("Final safe fixer - processing all safe unused variables...")
    fixed = 0
    failed = []
    
    for filepath, line_num, old_var, new_var in SAFE_FIXES:
        success, msg = fix_unused_var_safe(filepath, line_num, old_var, new_var)
        if success:
            fixed += 1
            if fixed % 10 == 0:
                print(f"✓ {fixed} fixed...")
        else:
            if "No change" not in msg:
                failed.append((filepath, line_num, msg))
    
    print(f"\n✅ Fixed: {fixed}")
    if failed:
        print(f"❌ Failed: {len(failed)}")
        for f, l, m in failed[:5]:
            print(f"  {f}:{l} - {m}")
    
    return fixed

if __name__ == '__main__':
    count = main()
    print(f"\nProgress: ~{254 + count}/780 issues ({((254 + count)/780)*100:.1f}%)")

