#!/usr/bin/env python3
"""Fix ALL remaining unused variables and parameters from 'other' category."""

import re
import os

# Parse all issues for unused local variables and parameters
all_unused = []

for severity in ['major', 'minor', 'info']:
    filename = f'all_issues_{severity}.txt'
    if not os.path.exists(filename):
        continue
    
    with open(filename, 'r') as f:
        lines = f.readlines()
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        # Check if it's a file path
        if line and '.py' in line and ('bsv/' in line or 'tests/' in line):
            filepath = line
            
            # Look ahead for description
            j = i + 1
            line_num = None
            var_name = None
            
            while j < len(lines) and j < i + 15:
                next_line = lines[j].strip()
                
                # Find line number
                if (next_line.startswith('Line:') or next_line.startswith('L')) and not line_num:
                    line_num = next_line.replace('Line:', '').replace('L', '').strip()
                    try:
                        line_num = int(line_num)
                    except:
                        line_num = None
                
                # Find unused variable/parameter description
                if ('Remove the unused' in next_line or 'Replace the unused' in next_line) and line_num:
                    # Extract variable name
                    match = re.search(r'variable "([^"]+)"', next_line) or \
                            re.search(r"variable '([^']+)'", next_line) or \
                            re.search(r'parameter "([^"]+)"', next_line) or \
                            re.search(r"parameter '([^']+)'", next_line)
                    
                    if match:
                        var_name = match.group(1)
                        all_unused.append((filepath, line_num, var_name))
                    break
                
                if next_line.startswith('---'):
                    break
                j += 1
        i += 1

print(f'Total unused variables/parameters found: {len(all_unused)}\n')

# Fix them all
fixed = 0
skipped = 0
errors = []

for filepath, line_num, var_name in all_unused:
    full_path = f'/home/sneakyfox/SDK/py-sdk/{filepath}'
    
    if not os.path.exists(full_path):
        skipped += 1
        continue
    
    try:
        with open(full_path, 'r') as f:
            file_lines = f.readlines()
        
        line_idx = line_num - 1
        if line_idx < 0 or line_idx >= len(file_lines):
            skipped += 1
            continue
        
        original = file_lines[line_idx]
        # Replace with underscore (word boundary)
        modified = re.sub(r'\b' + re.escape(var_name) + r'\b', '_', original, count=1)
        
        if modified != original:
            file_lines[line_idx] = modified
            with open(full_path, 'w') as f:
                f.writelines(file_lines)
            fixed += 1
            if fixed % 10 == 0:
                print(f'✓ {fixed} fixed...')
        else:
            skipped += 1
    except Exception as e:
        errors.append((filepath, line_num, str(e)))

print(f'\n=== RESULTS ===')
print(f'✅ Fixed: {fixed}')
print(f'⏭️  Skipped/Already Fixed: {skipped}')
print(f'❌ Errors: {len(errors)}')

if errors:
    print(f'\nFirst 3 errors:')
    for fp, ln, err in errors[:3]:
        print(f'  {fp}:{ln} - {err}')

print(f'\n📊 Progress: ~{368 + fixed}/780 ({((368 + fixed)/780)*100:.1f}%)')

