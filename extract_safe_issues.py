#!/usr/bin/env python3
"""Extract all remaining safe issues to fix."""

import re
import os

# Parse unused parameters
unused_params = []
with open('all_issues_major.txt', 'r') as f:
    content = f.read()

for block in content.split('-' * 80):
    if 'unused' in block.lower() and 'parameter' in block.lower():
        lines = [l.strip() for l in block.strip().split('\n') if l.strip()]
        if len(lines) >= 3:
            filepath = lines[0]
            line_part = [l for l in lines if 'Line:' in l or l.startswith('L')]
            desc = lines[2]
            
            # Extract parameter name
            match = re.search(r'parameter "([^"]+)"', desc) or \
                    re.search(r"parameter '([^']+)'", desc) or \
                    re.search(r'Remove.*parameter (\w+)', desc)
            
            if match and line_part:
                param = match.group(1)
                line_num = line_part[0].replace('Line:', '').strip().replace('L', '')
                unused_params.append((filepath, int(line_num), param))

print(f'=== UNUSED PARAMETERS ({len(unused_params)}) ===')
for f, l, p in unused_params:
    print(f'{f}:{l} - {p}')

# Parse empty blocks
print(f'\n=== EMPTY BLOCKS ===')
for filename in ['all_issues_minor.txt', 'all_issues_info.txt']:
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            content = f.read()
        
        for block in content.split('-' * 80):
            if 'empty' in block.lower():
                lines = [l.strip() for l in block.strip().split('\n') if l.strip()]
                if len(lines) >= 3:
                    print(f'{lines[0]}')
                    line_part = [l for l in lines if 'Line:' in l or l.startswith('L')]
                    if line_part:
                        print(f'  {line_part[0]}: {lines[2][:60]}')

# Get more unused variables
print(f'\n=== CHECKING REMAINING UNUSED VARS ===')
remaining_unused = []
with open('all_issues_minor.txt', 'r') as f:
    content = f.read()

for block in content.split('-' * 80):
    if 'unused' in block.lower() and 'variable' in block.lower() and 'tests/' in block:
        lines = [l.strip() for l in block.strip().split('\n') if l.strip()]
        if len(lines) >= 3:
            filepath = lines[0]
            line_part = [l for l in lines if 'Line:' in l or l.startswith('L')]
            desc = lines[2]
            
            match = re.search(r'variable "([^"]+)"', desc) or re.search(r"variable '([^']+)'", desc)
            if match and line_part:
                var = match.group(1)
                line_num = line_part[0].replace('Line:', '').strip().replace('L', '')
                remaining_unused.append((filepath, int(line_num), var))

print(f'Found {len(remaining_unused)} remaining unused test variables')
print(f'\nTop 10 files with most issues:')
from collections import defaultdict
by_file = defaultdict(int)
for f, l, v in remaining_unused:
    by_file[f] += 1

for file in sorted(by_file.keys(), key=lambda x: by_file[x], reverse=True)[:10]:
    print(f'  {by_file[file]:3d} - {file}')

