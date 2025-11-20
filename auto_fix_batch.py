#!/usr/bin/env python3
"""Auto-fix batch of simple issues."""

import re
import os

# List of files and lines with unused variables to fix
UNUSED_VAR_FIXES = [
    ('tests/vectors/auth/generate_auth_vectors.py', 15, 'msg', '_'),
    ('tests/vectors/auth/generate_auth_vectors.py', 15, 'ctx', '_'),
    ('tests/vectors/auth/generate_auth_vectors.py', 24, 'originator', '_'),
    ('tests/vectors/auth/generate_auth_vectors.py', 24, 'ctx', '_'),
    ('tests/vectors/auth/generate_auth_vectors.py', 24, 'args', '_'),
    ('tests/vectors/generate_woc_vector.py', 10, 'api_key', '_'),
]

def fix_unused_var(filepath, line_num, old_var, new_var):
    """Replace unused variable at specific line."""
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
        # Replace variable name with _
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
    print("Auto-fixing batch of issues...")
    fixed_count = 0
    
    for filepath, line_num, old_var, new_var in UNUSED_VAR_FIXES:
        success, msg = fix_unused_var(filepath, line_num, old_var, new_var)
        if success:
            fixed_count += 1
            print(f"✓ {filepath}:{line_num} - {old_var} -> {new_var}")
        else:
            print(f"✗ {filepath}:{line_num} - {msg}")
    
    print(f"\nFixed {fixed_count} issues")

if __name__ == '__main__':
    main()

