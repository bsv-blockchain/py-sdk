#!/usr/bin/env python3
"""Final comprehensive fixer for all remaining unused test variables."""

import re
import os

# Complete list from the parsed output
ALL_FIXES = [
    # tests/bsv/beef/test_kvstore_beef_e2e.py
    ('tests/bsv/beef/test_kvstore_beef_e2e.py', 415, 'header_root'),
    ('tests/bsv/beef/test_kvstore_beef_e2e.py', 466, 'kv'),
    ('tests/bsv/beef/test_kvstore_beef_e2e.py', 857, 'spends'),
    ('tests/bsv/beef/test_kvstore_beef_e2e.py', 961, 'beef'),
    ('tests/bsv/beef/test_kvstore_beef_e2e.py', 975, 'beef'),
    ('tests/bsv/beef/test_kvstore_beef_e2e.py', 1001, 'beef'),
    ('tests/bsv/beef/test_kvstore_beef_e2e.py', 1024, 'result'),
    ('tests/bsv/beef/test_kvstore_beef_e2e.py', 1053, 'action_result'),
    
    # tests/bsv/keystore/test_kvstore_beef_parsing.py
    ('tests/bsv/keystore/test_kvstore_beef_parsing.py', 54, 'beef_bytes'),
    ('tests/bsv/keystore/test_kvstore_beef_parsing.py', 64, 'result'),
    ('tests/bsv/keystore/test_kvstore_beef_parsing.py', 105, 'result'),
    ('tests/bsv/keystore/test_kvstore_beef_parsing.py', 150, 'result'),
    ('tests/bsv/keystore/test_kvstore_beef_parsing.py', 201, 'result'),
    ('tests/bsv/keystore/test_kvstore_beef_parsing.py', 137, 'result'),
    ('tests/bsv/keystore/test_kvstore_beef_parsing.py', 163, 'result'),
    ('tests/bsv/keystore/test_kvstore_beef_parsing.py', 182, 'result'),
    ('tests/bsv/keystore/test_kvstore_beef_parsing.py', 121, 'spends'),
    
    # tests/bsv/http_client_test_coverage.py
    ('tests/bsv/http_client_test_coverage.py', 54, 'response'),
    ('tests/bsv/http_client_test_coverage.py', 71, 'response'),
    ('tests/bsv/http_client_test_coverage.py', 88, 'response'),
    ('tests/bsv/http_client_test_coverage.py', 105, 'response'),
    ('tests/bsv/http_client_test_coverage.py', 136, 'response'),
    ('tests/bsv/http_client_test_coverage.py', 159, 'response'),
    ('tests/bsv/http_client_test_coverage.py', 187, 'response'),
    ('tests/bsv/http_client_test_coverage.py', 119, 'response'),
    
    # tests/bsv/script/interpreter/test_opcode_parser_coverage.py
    ('tests/bsv/script/interpreter/test_opcode_parser_coverage.py', 59, 'size'),
    ('tests/bsv/script/interpreter/test_opcode_parser_coverage.py', 72, 'size'),
    ('tests/bsv/script/interpreter/test_opcode_parser_coverage.py', 118, 'opcode'),
    ('tests/bsv/script/interpreter/test_opcode_parser_coverage.py', 133, 'opcode'),
    ('tests/bsv/script/interpreter/test_opcode_parser_coverage.py', 148, 'opcode'),
    ('tests/bsv/script/interpreter/test_opcode_parser_coverage.py', 163, 'opcode'),
    ('tests/bsv/script/interpreter/test_opcode_parser_coverage.py', 178, 'opcode'),
]

def fix_unused_var(filepath, line_num, var_name):
    """Fix unused variable by replacing with underscore."""
    full_path = f'/home/sneakyfox/SDK/py-sdk/{filepath}'
    
    if not os.path.exists(full_path):
        return False, "File not found"
    
    try:
        with open(full_path, 'r') as f:
            lines = f.readlines()
        
        line_idx = line_num - 1
        if line_idx < 0 or line_idx >= len(lines):
            return False, "Line out of range"
        
        original = lines[line_idx]
        # Replace variable name with underscore
        modified = re.sub(r'\b' + re.escape(var_name) + r'\b', '_', original, count=1)
        
        if modified != original:
            lines[line_idx] = modified
            with open(full_path, 'w') as f:
                f.writelines(lines)
            return True, "Fixed"
        
        return False, "No match"
    except Exception as e:
        return False, str(e)

def main():
    print(f"Fixing {len(ALL_FIXES)} unused variables...")
    fixed = 0
    failed = []
    
    for filepath, line_num, var_name in ALL_FIXES:
        success, msg = fix_unused_var(filepath, line_num, var_name)
        if success:
            fixed += 1
            if fixed % 20 == 0:
                print(f"✓ {fixed} fixed...")
        else:
            if "No match" not in msg:
                failed.append((filepath, line_num, var_name, msg))
    
    print(f"\n✅ Fixed: {fixed}/{len(ALL_FIXES)}")
    if failed:
        print(f"❌ Failed: {len(failed)}")
        for f, l, v, m in failed[:5]:
            print(f"  {f}:{l} ({v}) - {m}")
    
    print(f"\nProgress: ~{301 + fixed}/780 ({((301 + fixed)/780)*100:.1f}%)")
    return fixed

if __name__ == '__main__':
    main()

