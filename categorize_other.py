#!/usr/bin/env python3
"""Further categorize the 'other' issues."""

import re
from collections import defaultdict

def parse_issues_file(filepath):
    """Parse categorized issues file."""
    issues = []
    with open(filepath, 'r') as f:
        content = f.read()
    
    blocks = content.split('-' * 80)
    for block in blocks:
        if not block.strip():
            continue
        lines = [l.strip() for l in block.strip().split('\n') if l.strip()]
        if len(lines) >= 3:
            issue = {
                'file': lines[0],
                'line': lines[1].replace('Line: ', ''),
                'description': lines[2].replace('Description: ', ''),
            }
            issues.append(issue)
    return issues

# Parse all
critical = parse_issues_file('all_issues_critical.txt')
major = parse_issues_file('all_issues_major.txt')
minor = parse_issues_file('all_issues_minor.txt')

# Look at "other" patterns
other_patterns = defaultdict(list)

for issue in critical + major + minor:
    desc = issue['description']
    
    # Skip already categorized
    if any(x in desc for x in ['Cognitive Complexity', 'Rename', 'unused', 'shadows a builtin', 
                                'redundant Exception', 'timeout', 'duplicating this literal', 'empty']):
        continue
    
    # New patterns
    if 'Specify an exception class' in desc:
        other_patterns['bare_except'].append(issue)
    elif 'Define a constant instead' in desc:
        other_patterns['define_constant'].append(issue)
    elif 'too many' in desc.lower():
        other_patterns['too_many'].append(issue)
    elif 'maximum allowed' in desc.lower():
        other_patterns['max_allowed'].append(issue)
    elif 'Refactor' in desc or 'reduce' in desc:
        other_patterns['refactor'].append(issue)
    elif 'Remove' in desc or 'delete' in desc.lower():
        other_patterns['remove_code'].append(issue)
    elif 'field' in desc.lower() or 'Fields' in desc:
        other_patterns['field_issue'].append(issue)
    elif 'Merge' in desc or 'merge' in desc:
        other_patterns['merge'].append(issue)
    elif 'Extract' in desc:
        other_patterns['extract'].append(issue)
    else:
        other_patterns['truly_other'].append(issue)

print("=== Other Categories ===\n")
for category, issues in sorted(other_patterns.items(), key=lambda x: -len(x[1])):
    print(f"{category}: {len(issues)} issues")
    for issue in issues[:3]:
        print(f"  - {issue['file']}:{issue['line']}")
        print(f"    {issue['description'][:80]}...")
    if len(issues) > 3:
        print(f"  ... and {len(issues) - 3} more")
    print()
