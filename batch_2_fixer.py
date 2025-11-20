#!/usr/bin/env python3
"""Batch 2 - more safe test file fixes."""

import re

FIXES_BATCH_2 = [
    # script/interpreter tests (7 issues)
    ('tests/bsv/script/interpreter/test_opcode_parser_coverage.py', 59, 'size', '_'),
    ('tests/bsv/script/interpreter/test_opcode_parser_coverage.py', 72, 'size', '_'),
    ('tests/bsv/script/interpreter/test_opcode_parser_coverage.py', 118, 'opcode', '_'),
    ('tests/bsv/script/interpreter/test_opcode_parser_coverage.py', 133, 'opcode', '_'),
    ('tests/bsv/script/interpreter/test_opcode_parser_coverage.py', 148, 'opcode', '_'),
    ('tests/bsv/script/interpreter/test_opcode_parser_coverage.py', 163, 'opcode', '_'),
    ('tests/bsv/script/interpreter/test_opcode_parser_coverage.py', 178, 'opcode', '_'),
    
    # aes_gcm tests (remaining 3)
    ('tests/bsv/aes_gcm_test_coverage.py', 76, 'decrypted', '_'),
    ('tests/bsv/aes_gcm_test_coverage.py', 93, 'decrypted', '_'),
    ('tests/bsv/aes_gcm_test_coverage.py', 135, 'encrypted', '_'),
    
    # broadcasters tests (3)
    ('tests/bsv/broadcasters_test_coverage.py', 45, 'result', '_'),
    ('tests/bsv/broadcasters_test_coverage.py', 79, 'result', '_'),
    ('tests/bsv/broadcasters_test_coverage.py', 135, 'result', '_'),
    
    # storage tests (3)
    ('tests/bsv/storage/test_storage.py', 44, 'original_fetch', '_'),
    ('tests/bsv/storage/test_storage.py', 84, 'original_fetch', '_'),
    ('tests/bsv/storage/test_storage.py', 152, 'original_fetch', '_'),
    
    # script chunks (3)
    ('tests/bsv/utils/test_script_chunks_coverage.py', 96, 'chunk', '_'),
    ('tests/bsv/utils/test_script_chunks_coverage.py', 112, 'chunk', '_'),
    ('tests/bsv/utils/test_script_chunks_coverage.py', 132, 'chunks', '_'),
    
    # wallet wire integration (3)
    ('tests/bsv/wallet/substrates/test_wallet_wire_integration.py', 28, 'protocol', '_'),
    ('tests/bsv/wallet/substrates/test_wallet_wire_integration.py', 55, 'protocol', '_'),
    ('tests/bsv/wallet/substrates/test_wallet_wire_integration.py', 78, 'protocol', '_'),
    
    # wallet impl coverage (3)
    ('tests/bsv/wallet/test_wallet_impl_coverage.py', 93, 'result', '_'),
    ('tests/bsv/wallet/test_wallet_impl_coverage.py', 106, 'result', '_'),
    ('tests/bsv/wallet/test_wallet_impl_coverage.py', 121, 'result', '_'),
    
    # broadcaster test (2)
    ('tests/bsv/broadcaster_test_coverage.py', 70, 'result', '_'),
    ('tests/bsv/broadcaster_test_coverage.py', 107, 'result', '_'),
    
    # compat/bsm (2)
    ('tests/bsv/compat/test_bsm.py', 60, 'compressed', '_'),
    ('tests/bsv/compat/test_bsm.py', 62, 'recovery_id', '_'),
]

def fix_var(filepath, line_num, old_var, new_var):
    """Fix variable."""
    full_path = f'/home/sneakyfox/SDK/py-sdk/{filepath}'
    
    try:
        with open(full_path, 'r') as f:
            lines = f.readlines()
        
        line_idx = line_num - 1
        if 0 <= line_idx < len(lines):
            original = lines[line_idx]
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
    print("Batch 2 fixer running...")
    fixed = sum(1 for f, l, o, n in FIXES_BATCH_2 if fix_var(f, l, o, n))
    print(f"✅ Fixed: {fixed}/{len(FIXES_BATCH_2)}")
    print(f"Progress: ~{269 + fixed}/780 ({((269 + fixed)/780)*100:.1f}%)")
    return fixed

if __name__ == '__main__':
    main()

