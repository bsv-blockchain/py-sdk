#!/usr/bin/env python3
"""Parse ALL SonarQube issues from sonar_issues.txt - handles multiple issues per file."""

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
    """Parse ALL sonar issues from file - handles multiple issues per file."""
    issues = []
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Split by file path markers (lines starting with bsv/ or tests/)
    lines = content.split('\n')
    
    current_file = None
    i = 0
    
    while i < len(lines):
        line = lines[i].strip()
        
        # Check if this is a filename
        if line and (line.startswith('bsv/') or line.startswith('tests/')):
            current_file = line
            i += 1
            continue
        
        # If we have a file and this is a description line (non-empty, not metadata)
        if current_file and line and not line.startswith('L') and line not in [
            'Adaptability', 'Maintainability', 'Consistency', 'Intentionality',
            'Code Smell', 'Bug', 'Vulnerability', 'Critical', 'Major', 'Minor', 'Info',
            'Open', 'Not assigned', 'High', 'Medium', 'Low'
        ] and not re.match(r'^\d+$', line) and 'effort' not in line and 'ago' not in line:
            # This is likely a description
            description = line
            
            # Look ahead for line number and severity
            line_num = ""
            severity = ""
            issue_type = ""
            effort = ""
            
            j = i + 1
            while j < len(lines) and j < i + 30:
                check_line = lines[j].strip()
                
                if check_line.startswith('L') and re.match(r'^L\d+$', check_line):
                    line_num = check_line
                elif check_line in ['Critical', 'Major', 'Minor', 'Info', 'Blocker']:
                    severity = check_line
                elif check_line in ['Code Smell', 'Bug', 'Vulnerability']:
                    issue_type = check_line
                elif 'effort' in check_line:
                    effort = check_line
                    # After finding effort, we've found the complete issue
                    break
                
                # Stop if we hit another filename
                if check_line and (check_line.startswith('bsv/') or check_line.startswith('tests/')):
                    break
                    
                j += 1
            
            # Add issue if we have minimum required info
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
                i = j
                continue
        
        i += 1
    
    return issues

def categorize_by_severity(issues: List[SonarIssue]) -> Dict[str, List[SonarIssue]]:
    """Group issues by severity level."""
    categorized = defaultdict(list)
    
    for issue in issues:
        categorized[issue.severity].append(issue)
    
    return categorized

def main():
    issues_file = '/home/sneakyfox/SDK/py-sdk/sonar_issues.txt'
    
    print("Parsing ALL sonar issues...")
    issues = parse_sonar_issues(issues_file)
    
    print(f"\nTotal issues found: {len(issues)}")
    
    categorized = categorize_by_severity(issues)
    
    # Print summary by severity
    severity_order = ['Blocker', 'Critical', 'Major', 'Minor', 'Info']
    
    print("\n=== Issues by Severity ===")
    for severity in severity_order:
        if severity in categorized:
            print(f"\n{severity}: {len(categorized[severity])} issues")
            
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
            
            print(f"  Saved to: {output_file}")
    
    # Show samples
    print("\n=== Sample Issues (first 5) ===")
    for i, issue in enumerate(issues[:5], 1):
        print(f"{i}. {issue}")

if __name__ == '__main__':
    main()

