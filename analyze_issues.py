#!/usr/bin/env python3
"""Analyze all issues and categorize them for systematic fixing."""

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
                'type': next((l.replace('Type: ', '') for l in lines if l.startswith('Type:')), ''),
                'effort': next((l.replace('Effort: ', '') for l in lines if l.startswith('Effort:')), ''),
            }
            issues.append(issue)
    return issues

# Parse all severity levels
critical = parse_issues_file('all_issues_critical.txt')
major = parse_issues_file('all_issues_major.txt')
minor = parse_issues_file('all_issues_minor.txt')

# Categorize by pattern
patterns = defaultdict(list)

for issue in critical + major + minor:
    desc = issue['description']
    
    if 'Cognitive Complexity' in desc:
        patterns['cognitive_complexity'].append(issue)
    elif 'empty' in desc.lower():
        patterns['empty_method'].append(issue)
    elif 'Rename' in desc and 'function' in desc:
        patterns['function_naming'].append(issue)
    elif 'Rename' in desc and 'field' in desc:
        patterns['field_naming'].append(issue)
    elif 'Rename' in desc and 'variable' in desc:
        patterns['variable_naming'].append(issue)
    elif 'unused' in desc.lower() and 'parameter' in desc.lower():
        patterns['unused_param'].append(issue)
    elif 'shadows a builtin' in desc:
        patterns['shadows_builtin'].append(issue)
    elif 'redundant Exception' in desc:
        patterns['redundant_exception'].append(issue)
    elif 'timeout' in desc.lower() and 'parameter' in desc.lower():
        patterns['timeout_param'].append(issue)
    elif 'duplicating this literal' in desc:
        patterns['duplicated_literal'].append(issue)
    else:
        patterns['other'].append(issue)

print("=== Issue Categories ===\n")
for category, issues in sorted(patterns.items(), key=lambda x: -len(x[1])):
    print(f"{category}: {len(issues)} issues")
    if len(issues) <= 5:
        for issue in issues:
            print(f"  - {issue['file']}:{issue['line']}")
            print(f"    {issue['description']}")

print(f"\nTotal: {len(critical + major + minor)} issues")
