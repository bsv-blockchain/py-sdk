#!/usr/bin/env python3
"""Parse ALL SonarQube issues - correctly handles multiple issues per file."""

import re
from dataclasses import dataclass
from typing import List, Dict
from collections import defaultdict

@dataclass
class SonarIssue:
    filename: str
    description: str
    line: str
    severity: str
    issue_type: str
    effort: str
    
    def __str__(self):
        return f"{self.filename}:{self.line} [{self.severity}] {self.description}"

def parse_sonar_issues(filepath: str) -> List[SonarIssue]:
    """Parse ALL issues - handles multiple issues per file."""
    issues = []
    
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    i = 0
    current_file = None
    
    while i < len(lines):
        line = lines[i].strip()
        
        # Check if this is a filename
        if line and (line.startswith('bsv/') or line.startswith('tests/')):
            current_file = line
            i += 1
            continue
        
        # Check if this is likely a description (non-empty, meaningful text)
        if current_file and line and len(line) > 10:
            # Skip known metadata lines
            if line in ['Adaptability', 'Maintainability', 'Consistency', 'Intentionality',
                       'Testability', 'Reliability', 'Clarity',
                       'Open', 'Not assigned', 'High', 'Medium', 'Low',
                       'architecture', 'brain-overload', 'convention', 'unused', 
                       'typing', 'confusing', 'suspicious']:
                i += 1
                continue
            
            # Skip pure numbers and tags
            if re.match(r'^\d+$', line):
                i += 1
                continue
            
            # This looks like a description
            description = line
            
            # Scan ahead to collect metadata for this issue
            line_num = ""
            severity = ""
            issue_type = ""
            effort = ""
            
            j = i + 1
            found_complete_issue = False
            
            while j < len(lines) and j < i + 50:
                check = lines[j].strip()
                
                # Check for line number
                if re.match(r'^L\d+$', check):
                    line_num = check
                
                # Check for severity
                elif check in ['Critical', 'Major', 'Minor', 'Info', 'Blocker']:
                    severity = check
                    # Severity is usually the last metadata item for an issue
                    found_complete_issue = True
                
                # Check for issue type
                elif check in ['Code Smell', 'Bug', 'Vulnerability']:
                    issue_type = check
                
                # Check for effort
                elif 'effort' in check:
                    effort = check
                
                # Stop if we hit another filename or another description
                if check and (check.startswith('bsv/') or check.startswith('tests/')):
                    break
                
                # If we found complete issue metadata, check if next non-empty line is new issue
                if found_complete_issue:
                    # Look ahead one more to see if next is a new description
                    k = j + 1
                    while k < len(lines) and not lines[k].strip():
                        k += 1
                    if k < len(lines):
                        next_line = lines[k].strip()
                        # If it's a filename or looks like a description, we're done
                        if (next_line.startswith('bsv/') or next_line.startswith('tests/') or
                            (len(next_line) > 10 and next_line not in ['Adaptability', 'Maintainability'])):
                            break
                
                j += 1
            
            # Add issue if we have minimum required data
            if line_num and severity:
                issues.append(SonarIssue(
                    filename=current_file,
                    description=description,
                    line=line_num,
                    severity=severity,
                    issue_type=issue_type,
                    effort=effort
                ))
            
            # Move past this issue
            i = j if found_complete_issue else i + 1
        else:
            i += 1
    
    return issues

def main():
    issues_file = '/home/sneakyfox/SDK/py-sdk/sonar_issues.txt'
    
    print("Parsing ALL sonar issues (v2)...")
    issues = parse_sonar_issues(issues_file)
    
    print(f"\nTotal issues found: {len(issues)}")
    
    # Categorize by severity
    categorized = defaultdict(list)
    for issue in issues:
        categorized[issue.severity].append(issue)
    
    # Print summary
    severity_order = ['Blocker', 'Critical', 'Major', 'Minor', 'Info']
    
    print("\n=== Issues by Severity ===")
    for severity in severity_order:
        if severity in categorized:
            count = len(categorized[severity])
            print(f"{severity}: {count} issues")
            
            # Save to file
            output_file = f'/home/sneakyfox/SDK/py-sdk/all_issues_{severity.lower()}.txt'
            with open(output_file, 'w') as f:
                for issue in categorized[severity]:
                    f.write(f"{issue.filename}\n")
                    f.write(f"Line: {issue.line}\n")
                    f.write(f"Description: {issue.description}\n")
                    f.write(f"Type: {issue.issue_type}\n")
                    f.write(f"Effort: {issue.effort}\n")
                    f.write("-" * 80 + "\n")
    
    print(f"\n=== First 10 Issues ===")
    for i, issue in enumerate(issues[:10], 1):
        print(f"{i}. {issue}")
    
    # Count by file to verify
    file_counts = defaultdict(int)
    for issue in issues:
        file_counts[issue.filename] += 1
    
    print(f"\n=== Files with most issues (top 10) ===")
    sorted_files = sorted(file_counts.items(), key=lambda x: x[1], reverse=True)
    for filename, count in sorted_files[:10]:
        print(f"  {count:3d} issues - {filename}")

if __name__ == '__main__':
    main()

