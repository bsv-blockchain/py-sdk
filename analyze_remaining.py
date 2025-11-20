#!/usr/bin/env python3
"""Analyze remaining safe fixes."""

import re
from collections import defaultdict

with open('all_issues_minor.txt', 'r') as f:
    content = f.read()

test_issues = []
for block in content.split('-' * 80):
    if 'tests/' in block and 'unused' in block.lower():
        lines = [l.strip() for l in block.strip().split('\n') if l.strip()]
        if len(lines) >= 3:
            filename = lines[0]
            line = lines[1].replace('Line: ', '')
            desc = lines[2]
            # Extract variable name
            match = re.search(r'variable "([^"]+)"', desc)
            if not match:
                match = re.search(r"variable '([^']+)'", desc)
            if match:
                var_name = match.group(1)
                test_issues.append((filename, line, var_name))

print(f'Found {len(test_issues)} test file unused variable issues\n')

# Group by file
by_file = defaultdict(list)
for f, line, var in test_issues:
    by_file[f].append((line, var))

print('Top 20 files needing fixes:')
for file in sorted(by_file.keys(), key=lambda x: len(by_file[x]), reverse=True)[:20]:
    issues = by_file[file]
    print(f'  {len(issues):2d} - {file}')
    for line, var in issues[:3]:
        print(f'      {line}: {var}')
    if len(issues) > 3:
        print(f'      ... {len(issues)-3} more')

