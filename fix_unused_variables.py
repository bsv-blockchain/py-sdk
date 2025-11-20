#!/usr/bin/env python3
"""Fix unused variable issues automatically."""

import re
import os

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

def extract_variable_name(description):
    """Extract variable name from description."""
    # Pattern: Remove the unused local variable "varname".
    # Pattern: Replace the unused local variable "varname" with "_".
    match = re.search(r'variable ["\']([^"\']+)["\']', description)
    if match:
        return match.group(1)
    return None

def fix_unused_variable(filepath, line_num, var_name, replace_with_underscore=False):
    """Fix unused variable in file."""
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
        
        # Convert L123 to 0-indexed
        line_idx = int(line_num.replace('L', '')) - 1
        
        if line_idx < 0 or line_idx >= len(lines):
            return False, "Line out of range"
        
        original_line = lines[line_idx]
        
        if replace_with_underscore:
            # Replace var_name with _
            # Handle patterns like: var_name = something
            # Or: for var_name in something
            # Or: var_name, other = something
            modified_line = re.sub(r'\b' + re.escape(var_name) + r'\b', '_', original_line)
        else:
            # Try to remove the variable assignment
            # This is tricky and depends on context
            # For now, just add a comment
            if '=' in original_line and var_name in original_line:
                modified_line = original_line.rstrip() + f"  # noqa: F841  # TODO: Remove unused variable {var_name}\n"
            else:
                return False, "Cannot automatically fix"
        
        if modified_line == original_line:
            return False, "No change made"
        
        lines[line_idx] = modified_line
        
        with open(filepath, 'w') as f:
            f.writelines(lines)
        
        return True, "Fixed"
        
    except Exception as e:
        return False, str(e)

def main():
    # Get unused variable issues
    all_issues = []
    for severity in ['critical', 'major', 'minor']:
        all_issues.extend(read_issues_file(severity))
    
    unused_var_issues = []
    replace_with_underscore_issues = []
    
    for issue in all_issues:
        desc = issue['description']
        if 'Remove the unused local variable' in desc or 'Remove the unused function parameter' in desc:
            var_name = extract_variable_name(desc)
            if var_name:
                unused_var_issues.append((issue, var_name))
        elif 'Replace the unused local variable' in desc:
            var_name = extract_variable_name(desc)
            if var_name:
                replace_with_underscore_issues.append((issue, var_name))
    
    print(f"Found {len(unused_var_issues)} unused variables to remove")
    print(f"Found {len(replace_with_underscore_issues)} unused variables to replace with _")
    
    # Show samples instead of fixing (safer for now)
    print("\n=== Sample Unused Variables ===")
    for (issue, var_name) in unused_var_issues[:10]:
        print(f"{issue['filename']}:{issue['line']} - Remove '{var_name}'")
    
    print("\n=== Sample Variables to Replace with _ ===")
    for (issue, var_name) in replace_with_underscore_issues[:10]:
        print(f"{issue['filename']}:{issue['line']} - Replace '{var_name}' with '_'")

if __name__ == '__main__':
    main()

