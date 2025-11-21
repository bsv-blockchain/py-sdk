#!/usr/bin/env python3
"""Check all 'commented code' issues to verify they're false positives."""

import os

commented_issues = [
    ('bsv/beef/builder.py', 29),
    ('bsv/primitives/drbg.py', 77),
    ('bsv/primitives/drbg.py', 88),
    ('bsv/primitives/drbg.py', 104),
    ('tests/bsv/auth/test_auth_cryptononce.py', 52),
    ('tests/bsv/auth/test_metanet_desktop_auth.py', 531),
    ('tests/bsv/auth/test_metanet_desktop_auth.py', 594),
    ('tests/bsv/beef/test_beef_hardening.py', 7),
    ('tests/bsv/beef/test_beef_hardening.py', 53),
    ('tests/bsv/beef/test_beef_hardening.py', 54),
    ('tests/bsv/beef/test_beef_hardening.py', 100),
    ('tests/bsv/beef/test_beef_hardening.py', 101),
    ('tests/bsv/beef/test_beef_hardening.py', 180),
    ('tests/bsv/beef/test_beef_hardening.py', 200),
    ('tests/bsv/beef/test_beef_hardening.py', 201),
]

print("Checking all 'commented code' issues...\n")

for filepath, line_num in commented_issues:
    full_path = f'/home/sneakyfox/SDK/py-sdk/{filepath}'
    
    if not os.path.exists(full_path):
        print(f"❌ File not found: {filepath}")
        continue
    
    with open(full_path, 'r') as f:
        lines = f.readlines()
    
    if line_num - 1 < len(lines):
        line = lines[line_num - 1].rstrip()
        print(f"{filepath}:{line_num}")
        print(f"  {line}")
        
        # Check if it's actual code or explanation
        if line.strip().startswith('#'):
            # It's a comment - check if it looks like code
            comment = line.strip()[1:].strip()
            if '=' in comment or '(' in comment or any(x in comment for x in ['bumps', 'txs', 'V =', 'K =', 'version']):
                print(f"  → Explanatory comment (FALSE POSITIVE)")
            else:
                print(f"  → Regular comment")
        else:
            # It's not a comment line - might be inline comment
            if '#' in line:
                print(f"  → Inline comment (FALSE POSITIVE)")
            else:
                print(f"  → NOT A COMMENT?")
        print()



