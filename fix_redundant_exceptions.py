#!/usr/bin/env python3
"""Fix redundant exception issues."""

import re

# Parse sonar_issues.txt for redundant exceptions
with open('sonar_issues.txt', 'r') as f:
    lines = f.readlines()

redundant_issues = []
i = 0
while i < len(lines):
    line = lines[i].strip()
    
    # Check if it's a file path in py-sdk
    if line.startswith('bsv/') and '.py' in line:
        filepath = f'py-sdk/{line}'
        
        # Look ahead for "derives from" pattern
        j = i + 1
        found_derives = False
        line_num = None
        
        while j < len(lines) and j < i + 10:
            next_line = lines[j].strip()
            if 'derives from' in next_line.lower():
                found_derives = True
                # Look backwards for line number
                for k in range(i, min(i + 10, len(lines))):
                    check_line = lines[k].strip()
                    if check_line.startswith('Line '):
                        line_num = check_line.replace('Line ', '').strip()
                        break
                break
            j += 1
        
        if found_derives and line_num:
            redundant_issues.append((filepath, int(line_num)))
    
    i += 1

print(f'Found {len(redundant_issues)} redundant exception issues')

# Now let's examine a few to understand the pattern
for filepath, line_num in redundant_issues[:5]:
    print(f'\n{filepath}:{line_num}')
    try:
        with open(filepath, 'r') as f:
            file_lines = f.readlines()
        
        # Show context
        for offset in range(-2, 3):
            idx = line_num - 1 + offset
            if 0 <= idx < len(file_lines):
                marker = '>>>' if offset == 0 else '   '
                print(f'{marker} {idx + 1:4d}: {file_lines[idx].rstrip()}')
    except Exception as e:
        print(f'  Error reading: {e}')

print(f'\n\nTotal to fix: {len(redundant_issues)}')

