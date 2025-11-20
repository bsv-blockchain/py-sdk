#!/usr/bin/env python3
"""Parse actual unused variables from issues file."""

import re
import os

# Parse all_issues_minor.txt for unused variables in test files
with open('all_issues_minor.txt', 'r') as f:
    lines = f.readlines()

current_file = None
unused_vars = []

i = 0
while i < len(lines):
    line = lines[i].strip()
    
    # Check if this is a file path
    if line.startswith('tests/') and '.py' in line:
        current_file = line
        # Look ahead for line number and description
        j = i + 1
        line_num = None
        desc = None
        
        while j < len(lines) and j < i + 10:
            next_line = lines[j].strip()
            if next_line.startswith('Line:') or next_line.startswith('L'):
                line_num = next_line.replace('Line:', '').replace('L', '').strip()
            elif 'unused' in next_line.lower() and 'variable' in next_line.lower():
                desc = next_line
                # Extract variable name
                match = re.search(r'variable "([^"]+)"', desc) or re.search(r"variable '([^']+)'", desc)
                if match and line_num:
                    var_name = match.group(1)
                    unused_vars.append((current_file, int(line_num), var_name, desc))
                break
            elif next_line.startswith('---'):
                break
            j += 1
    i += 1

print(f'Found {len(unused_vars)} unused test variables\n')

# Group by file
from collections import defaultdict
by_file = defaultdict(list)
for f, l, v, d in unused_vars:
    by_file[f].append((l, v, d))

# Show top files
print('Files with most unused vars:')
for file in sorted(by_file.keys(), key=lambda x: len(by_file[x]), reverse=True)[:15]:
    issues = by_file[file]
    print(f'\n{file} ({len(issues)} issues):')
    for line, var, desc in issues[:5]:
        print(f'  L{line}: {var}')
        # Check if file exists
        full_path = f'{file}'
        if not os.path.exists(full_path):
            print(f'    [FILE NOT FOUND]')
    if len(issues) > 5:
        print(f'  ... {len(issues)-5} more')

