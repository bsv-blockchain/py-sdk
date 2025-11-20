#!/usr/bin/env python3
"""Mega batch fixer - handle many issues at once."""

import re
import os
from pathlib import Path

def read_file_safe(filepath):
    """Safely read a file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.readlines(), None
    except Exception as e:
        return None, str(e)

def write_file_safe(filepath, lines):
    """Safely write a file."""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        return True, None
    except Exception as e:
        return False, str(e)

def fix_line(line, old_var, new_var):
    """Fix a variable in a line."""
    return re.sub(r'\b' + re.escape(old_var) + r'\b', new_var, line, count=1)

# Comprehensive list of ALL remaining test file unused variables
# Generated from sonar issues
TEST_FILE_FIXES = [
    ('tests/bsv/broadcaster_test_coverage.py', 48, 'result', '_'),
    ('tests/bsv/broadcaster_test_coverage.py', 64, 'result', '_'),
    ('tests/bsv/chaintracker_test_coverage.py', 42, 'result', '_'),
    ('tests/bsv/chaintracker_test_coverage.py', 53, 'result', '_'),
    ('tests/bsv/ecdsa/test_ecdsa_coverage.py', 37, 'sig', '_'),
    ('tests/bsv/encrypted_message_test_coverage.py', 34, 'message', '_'),
    ('tests/bsv/fee_model_test_coverage.py', 82, 'rate', '_'),
    ('tests/bsv/hd/test_bip32.py', 22, 'child', '_'),
    ('tests/bsv/hd/test_key_shares.py', 110, 'shares', '_'),
    ('tests/bsv/http_client_test_coverage.py', 35, 'result', '_'),
    ('tests/bsv/http_client_test_coverage.py', 63, 'result', '_'),
    ('tests/bsv/http_client_test_coverage.py', 77, 'result', '_'),
    ('tests/bsv/http_client_test_coverage.py', 91, 'result', '_'),
    ('tests/bsv/http_client_test_coverage.py', 105, 'result', '_'),
    ('tests/bsv/http_client_test_coverage.py', 119, 'result', '_'),
    ('tests/bsv/http_client_test_coverage.py', 145, 'result', '_'),
    ('tests/bsv/http_client_test_coverage.py', 159, 'result', '_'),
    ('tests/bsv/http_client_test_coverage.py', 173, 'result', '_'),
    ('tests/bsv/http_client_test_coverage.py', 187, 'result', '_'),
]

def main():
    print("Mega batch fixer running...")
    fixed = 0
    failed = []
    
    for filepath, line_num, old_var, new_var in TEST_FILE_FIXES:
        full_path = f'/home/sneakyfox/SDK/py-sdk/{filepath}'
        
        lines, err = read_file_safe(full_path)
        if err:
            failed.append((filepath, line_num, f"Read error: {err}"))
            continue
        
        line_idx = line_num - 1
        if line_idx < 0 or line_idx >= len(lines):
            failed.append((filepath, line_num, "Line out of range"))
            continue
        
        original = lines[line_idx]
        modified = fix_line(original, old_var, new_var)
        
        if modified != original:
            lines[line_idx] = modified
            success, err = write_file_safe(full_path, lines)
            if success:
                fixed += 1
                print(f"✓ {filepath}:{line_num}")
            else:
                failed.append((filepath, line_num, f"Write error: {err}"))
        else:
            failed.append((filepath, line_num, "No change needed"))
    
    print(f"\n✓ Fixed: {fixed}")
    print(f"✗ Failed: {len(failed)}")
    
    return fixed

if __name__ == '__main__':
    main()

