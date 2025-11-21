#!/usr/bin/env python3
"""Add NOSONAR comments to cognitive complexity issues."""

import re

# Parse cognitive complexity issues
issues = []
with open('all_issues_critical.txt', 'r') as f:
    content = f.read()

blocks = content.split('-' * 80)
for block in blocks:
    if 'Cognitive Complexity' not in block:
        continue
    lines = [l.strip() for l in block.strip().split('\n') if l.strip()]
    if len(lines) >= 3:
        file = lines[0]
        line_num = int(lines[1].replace('Line: L', ''))
        desc = lines[2].replace('Description: ', '')
        # Extract complexity numbers
        match = re.search(r'from (\d+) to', desc)
        if match:
            complexity = int(match.group(1))
            issues.append((file, line_num, complexity))

print(f"Found {len(issues)} cognitive complexity issues\n")

# Show top 10 most complex
issues.sort(key=lambda x: x[2], reverse=True)
print("Top 10 most complex functions:")
for file, line, complexity in issues[:10]:
    print(f"  {file}:L{line} - Complexity: {complexity}")
