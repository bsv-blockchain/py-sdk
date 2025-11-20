#!/usr/bin/env python3
"""Comprehensive fixer for remaining SonarQube issues."""

import re
import os
from pathlib import Path

def read_all_issues():
    """Read all issues from severity files."""
    all_issues = []
    for severity in ['critical', 'major', 'minor']:
        file_path = f'/home/sneakyfox/SDK/py-sdk/all_issues_{severity}.txt'
        if not os.path.exists(file_path):
            continue
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        for block in content.split('-' * 80):
            if not block.strip():
                continue
            lines = [l.strip() for l in block.strip().split('\n') if l.strip()]
            if len(lines) >= 3:
                issue = {
                    'filename': lines[0],
                    'line': lines[1].replace('Line: ', ''),
                    'description': lines[2].replace('Description: ', ''),
                    'severity': severity
                }
                all_issues.append(issue)
    
    return all_issues

def categorize_issues(issues):
    """Categorize issues by type for batch fixing."""
    categories = {
        'unused_var_remove': [],
        'unused_var_replace': [],
        'unused_param': [],
        'naming_snake_case': [],
        'f_string': [],
        'redundant_exception': [],
        'cognitive_complexity': [],
        'ctx_parameter': [],
        'other': []
    }
    
    for issue in issues:
        desc = issue['description'].lower()
        
        if 'remove the unused local variable' in desc or 'remove the unused function parameter' in desc:
            categories['unused_var_remove'].append(issue)
        elif 'replace the unused local variable' in desc:
            categories['unused_var_replace'].append(issue)
        elif 'rename this' in desc and 'match the regular expression' in desc:
            categories['naming_snake_case'].append(issue)
        elif 'add replacement fields or use a normal string' in desc:
            categories['f_string'].append(issue)
        elif 'remove this redundant exception' in desc:
            categories['redundant_exception'].append(issue)
        elif 'cognitive complexity' in desc:
            categories['cognitive_complexity'].append(issue)
        elif 'remove parameter ctx or provide default' in desc:
            categories['ctx_parameter'].append(issue)
        else:
            categories['other'].append(issue)
    
    return categories

def extract_variable_name(description):
    """Extract variable name from description."""
    match = re.search(r'["\']([^"\']+)["\']', description)
    if match:
        return match.group(1)
    return None

def fix_unused_variable_in_file(filepath, line_num, var_name, replace_mode=False):
    """Fix unused variable at specific line."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        line_idx = int(line_num.replace('L', '')) - 1
        if line_idx < 0 or line_idx >= len(lines):
            return False, "Line out of range"
        
        original = lines[line_idx]
        
        if replace_mode:
            # Replace variable with _
            modified = re.sub(r'\b' + re.escape(var_name) + r'\b', '_', original, count=1)
        else:
            # Try to understand context and remove or comment
            if f'{var_name} =' in original:
                # Assignment - remove the line if it's standalone
                if original.strip().startswith(var_name):
                    modified = ''  # Remove line
                else:
                    # Part of larger expression, replace with _
                    modified = re.sub(r'\b' + re.escape(var_name) + r'\b', '_', original, count=1)
            else:
                # Not an assignment, replace with _
                modified = re.sub(r'\b' + re.escape(var_name) + r'\b', '_', original, count=1)
        
        if modified != original:
            if modified:  # Only update if not empty
                lines[line_idx] = modified
            else:
                # Remove the line entirely
                del lines[line_idx]
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            return True, "Fixed"
        
        return False, "No change"
    except Exception as e:
        return False, str(e)

def main():
    print("Reading all issues...")
    issues = read_all_issues()
    print(f"Total issues: {len(issues)}")
    
    print("\nCategorizing...")
    categories = categorize_issues(issues)
    
    print("\n=== Issue Categories ===")
    for cat_name, cat_issues in categories.items():
        if cat_issues:
            print(f"{cat_name}: {len(cat_issues)} issues")
    
    # Show samples from unused_var_remove
    print("\n=== Sample Unused Variables (first 20) ===")
    for issue in categories['unused_var_remove'][:20]:
        var_name = extract_variable_name(issue['description'])
        print(f"{issue['filename']}:{issue['line']} - '{var_name}'")
    
    # Show samples from naming issues
    print("\n=== Sample Naming Issues (first 10) ===")
    for issue in categories['naming_snake_case'][:10]:
        var_name = extract_variable_name(issue['description'])
        print(f"{issue['filename']}:{issue['line']} - '{var_name}'")

if __name__ == '__main__':
    main()

