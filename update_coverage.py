#!/usr/bin/env python3
"""
Script to update README.md with current test coverage percentage.
Automatically extracts coverage from coverage.xml if available, or accepts percentage as argument.
"""

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def extract_coverage_from_xml(xml_path: Path = Path("coverage.xml")) -> dict:
    """Extract coverage percentages from coverage.xml file."""
    if not xml_path.exists():
        return None

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        line_rate = float(root.attrib.get('line-rate', 0))
        branch_rate = float(root.attrib.get('branch-rate', 0))
        return {
            'line_rate': line_rate * 100,
            'branch_rate': branch_rate * 100
        }
    except (ET.ParseError, ValueError, KeyError) as e:
        print(f"Error parsing coverage.xml: {e}")
        return None


def update_readme_coverage(coverage_data: dict):
    """Update the README.md file with the new coverage percentages."""
    readme_path = Path("README.md")

    if not readme_path.exists():
        print(f"README.md not found at {readme_path}")
        return False

    content = readme_path.read_text(encoding='utf-8')

    # Use line coverage for badge (maintains backward compatibility)
    line_coverage_float = coverage_data['line_rate']
    branch_coverage_float = coverage_data['branch_rate']

    # Determine badge color based on line coverage percentage
    if line_coverage_float >= 90:
        color = "brightgreen"
    elif line_coverage_float >= 80:
        color = "green"
    elif line_coverage_float >= 70:
        color = "yellowgreen"
    elif line_coverage_float >= 60:
        color = "yellow"
    else:
        color = "red"

    # Format percentages to one decimal place
    formatted_line_percentage = f"{line_coverage_float:.1f}"
    formatted_branch_percentage = f"{branch_coverage_float:.1f}"

    # Update the coverage badge at the top (more flexible pattern)
    # Matches: ![Coverage](https://img.shields.io/badge/coverage-85.7%25-green)
    badge_pattern = r'!\[Coverage\]\(https://img\.shields\.io/badge/coverage-[\d.]+%25-[a-z]+\)'
    new_badge = f'![Coverage](https://img.shields.io/badge/coverage-{formatted_line_percentage}%25-{color})'

    if re.search(badge_pattern, content):
        content = re.sub(badge_pattern, new_badge, content)
        print(f"Updated coverage badge: {formatted_line_percentage}% (line coverage)")
    else:
        print(f"Warning: Coverage badge pattern not found in README")

    # Update the coverage percentage in the Testing & Quality section
    # Matches: **85.7%+ code coverage** across the entire codebase
    coverage_text_pattern = r'\*\*(\d+(?:\.\d+)?)%\+ code coverage\*\* across the entire codebase'
    new_coverage_text = f'**{formatted_line_percentage}%+ code coverage** across the entire codebase'

    if re.search(coverage_text_pattern, content):
        content = re.sub(coverage_text_pattern, new_coverage_text, content)
        print(f"Updated coverage text: {formatted_line_percentage}%+")
    else:
        print(f"Warning: Coverage text pattern not found in README")

    # Add branch coverage information if available
    if branch_coverage_float > 0:
        print(f"Branch coverage: {formatted_branch_percentage}%")
        # Could add branch coverage badge or text in future updates

    # Write the updated content back to the file
    readme_path.write_text(content, encoding='utf-8')
    print(f"Successfully updated README.md with line coverage: {formatted_line_percentage}%")
    return True


def main():
    coverage_data = None

    # Try to extract from coverage.xml first
    coverage_from_xml = extract_coverage_from_xml()
    if coverage_from_xml is not None:
        coverage_data = coverage_from_xml
        print(f"Extracted line coverage from coverage.xml: {coverage_data['line_rate']:.1f}%")
        print(f"Extracted branch coverage from coverage.xml: {coverage_data['branch_rate']:.1f}%")
    elif len(sys.argv) >= 2:
        # Fall back to command line argument (assume line coverage only)
        try:
            line_percentage = float(sys.argv[1])
            coverage_data = {'line_rate': line_percentage, 'branch_rate': 0.0}
            print(f"Using command line coverage: {line_percentage}% (line coverage only)")
        except ValueError:
            print(f"Invalid coverage percentage: {sys.argv[1]}")
            sys.exit(1)
    else:
        print("Usage: python update_coverage.py [line_coverage_percentage]")
        print("  If coverage_percentage is not provided, will try to extract from coverage.xml")
        sys.exit(1)

    success = update_readme_coverage(coverage_data)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
