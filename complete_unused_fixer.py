#!/usr/bin/env python3
"""Complete unused variable fixer - extract and fix ALL remaining."""

import re
import os

# Parse all_issues_minor.txt completely
with open('all_issues_minor.txt', 'r') as f:
    content = f.read()

all_unused = []
for block in content.split('-' * 80):
    if not block.strip():
        continue
    
    lines = [l.strip() for l in block.strip().split('\n') if l.strip()]
    if len(lines) < 3:
        continue
    
    filepath = lines[0]
    if not filepath.startswith('tests/'):
        continue
    
    # Find line number
    line_num = None
    for line in lines:
        if line.startswith('Line:') or line.startswith('L'):
            line_num = line.replace('Line:', '').replace('L', '').strip()
            try:
                line_num = int(line_num)
                break
            except:
                pass
    
    # Find description with unused variable
    for line in lines:
        if 'unused' in line.lower() and 'variable' in line.lower():
            # Extract variable name
            match = re.search(r'variable "([^"]+)"', line) or re.search(r"variable '([^']+)'", line)
            if match and line_num:
                var_name = match.group(1)
                all_unused.append((filepath, line_num, var_name))
                break

print(f'Total unused variables found: {len(all_unused)}\n')

# Fix them all
fixed = 0
skipped = 0
errors = 0

for filepath, line_num, var_name in all_unused:
    full_path = f'/home/sneakyfox/SDK/py-sdk/{filepath}'
    
    if not os.path.exists(full_path):
        skipped += 1
        continue
    
    try:
        with open(full_path, 'r') as f:
            lines = f.readlines()
        
        line_idx = line_num - 1
        if line_idx < 0 or line_idx >= len(lines):
            skipped += 1
            continue
        
        original = lines[line_idx]
        # Replace variable with underscore (word boundary)
        modified = re.sub(r'\b' + re.escape(var_name) + r'\b', '_', original, count=1)
        
        if modified != original:
            lines[line_idx] = modified
            with open(full_path, 'w') as f:
                f.writelines(lines)
            fixed += 1
            if fixed % 10 == 0:
                print(f"✓ {fixed} fixed...")
        else:
            skipped += 1
    except Exception as e:
        errors += 1
        if errors <= 3:
            print(f"Error: {filepath}:{line_num} - {e}")

print(f'\n=== RESULTS ===')
print(f'✅ Fixed: {fixed}')
print(f'⏭️  Skipped: {skipped}')
print(f'❌ Errors: {errors}')
print(f'\nProgress: ~{307 + fixed}/780 ({((307 + fixed)/780)*100:.1f}%)')

