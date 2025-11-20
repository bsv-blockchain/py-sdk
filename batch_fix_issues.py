#!/usr/bin/env python3
"""Batch fix remaining SonarQube issues - handles common patterns."""

import re
import os
from pathlib import Path

def read_issues_file(severity):
    """Read all issues for a given severity."""
    file_path = f'/home/sneakyfox/SDK/py-sdk/all_issues_{severity}.txt'
    if not os.path.exists(file_path):
        return []
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    issues = []
    for block in content.split('-' * 80):
        if not block.strip():
            continue
        lines = [l.strip() for l in block.strip().split('\n') if l.strip()]
        if len(lines) >= 3:
            issue = {
                'filename': lines[0],
                'line': lines[1].replace('Line: ', ''),
                'description': lines[2].replace('Description: ', ''),
            }
            issues.append(issue)
    
    return issues

def count_fixable_patterns():
    """Count how many issues match fixable patterns."""
    patterns = {
        'Remove unused local variable': 0,
        'Remove the unused local variable': 0,
        'Remove the unused function parameter': 0,
        'Replace the unused local variable': 0,
        'Rename this local variable': 0,
        'Rename this parameter': 0,
        'Rename this field': 0,
        'Rename field': 0,
        'Rename function': 0,
        'Rename class': 0,
        'Remove this redundant': 0,
        'Merge this if statement': 0,
        'Remove this commented out code': 0,
        'Replace this comprehension': 0,
        'Add replacement fields or use a normal string': 0,
        'Complete the task associated to this "TODO"': 0,
        'Use secure mode and padding': 0,
    }
    
    all_severities = ['critical', 'major', 'minor', 'info']
    total = 0
    
    for severity in all_severities:
        issues = read_issues_file(severity)
        for issue in issues:
            desc = issue['description']
            for pattern in patterns:
                if pattern.lower() in desc.lower():
                    patterns[pattern] += 1
                    total += 1
                    break
    
    print(f"Total issues: {total}")
    print(f"\n=== Fixable Pattern Counts ===")
    for pattern, count in sorted(patterns.items(), key=lambda x: x[1], reverse=True):
        if count > 0:
            print(f"  {count:3d} - {pattern}")
    
    return patterns

def list_complex_refactorings():
    """List cognitive complexity issues that need manual refactoring."""
    issues = read_issues_file('critical')
    
    complexity_issues = []
    for issue in issues:
        if 'Cognitive Complexity' in issue['description']:
            complexity_issues.append(issue)
    
    print(f"\n=== Cognitive Complexity Issues: {len(complexity_issues)} ===")
    for issue in complexity_issues[:20]:  # Show first 20
        print(f"  {issue['filename']}:{issue['line']} - {issue['description'][:60]}")
    
    return complexity_issues

if __name__ == '__main__':
    print("Analyzing remaining issues...\n")
    patterns = count_fixable_patterns()
    complexity = list_complex_refactorings()
    
    print(f"\n=== Summary ===")
    print(f"Total cognitive complexity issues: {len(complexity)}")
    print(f"Total other fixable issues: {sum(patterns.values())}")

