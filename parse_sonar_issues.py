#!/usr/bin/env python3
"""Parse SonarQube issues from sonar_issues.txt and categorize by severity."""

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
    """Parse the sonar issues file and return a list of Issue objects."""
    issues = []
    
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        # Check if this is a filename line (starts with bsv/ or tests/)
        if line and (line.startswith('bsv/') or line.startswith('tests/')):
            filename = line
            
            # Next line should be the description
            i += 1
            if i >= len(lines):
                break
            description = lines[i].strip()
            
            # Look for the line number (format: L<number>)
            line_num = ""
            severity = ""
            issue_type = ""
            effort = ""
            
            # Scan ahead to find all metadata
            j = i + 1
            while j < len(lines) and j < i + 20:  # Look ahead max 20 lines
                current = lines[j].strip()
                
                if current.startswith('L') and len(current) > 1 and current[1:].replace('L', '').isdigit():
                    line_num = current
                elif current in ['Critical', 'Major', 'Minor', 'Info', 'Blocker']:
                    severity = current
                elif current in ['Code Smell', 'Bug', 'Vulnerability']:
                    issue_type = current
                elif 'effort' in current:
                    effort = current
                
                # Stop when we hit the next filename or end marker
                if current and (current.startswith('bsv/') or current.startswith('tests/') or 'of 787 shown' in current):
                    break
                    
                j += 1
            
            # Only add if we have minimum required info
            if description and severity:
                issues.append(SonarIssue(
                    filename=filename,
                    description=description,
                    line=line_num,
                    severity=severity,
                    issue_type=issue_type,
                    effort=effort
                ))
            
            # Move to where we stopped scanning
            i = j
        else:
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
    
    print("Parsing sonar issues...")
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
            output_file = f'/home/sneakyfox/SDK/py-sdk/issues_{severity.lower()}.txt'
            with open(output_file, 'w') as f:
                for issue in categorized[severity]:
                    f.write(f"{issue.filename}\n")
                    f.write(f"Line: {issue.line}\n")
                    f.write(f"Description: {issue.description}\n")
                    f.write(f"Type: {issue.issue_type}\n")
                    f.write(f"Effort: {issue.effort}\n")
                    f.write("-" * 80 + "\n")
            
            print(f"  Saved to: {output_file}")
    
    # Print some sample issues from each severity
    print("\n=== Sample Issues ===")
    for severity in severity_order:
        if severity in categorized and categorized[severity]:
            print(f"\n{severity} (showing first 3):")
            for issue in categorized[severity][:3]:
                print(f"  - {issue.filename}:{issue.line}")
                print(f"    {issue.description}")

if __name__ == '__main__':
    main()

