#!/usr/bin/env python3
"""
Script to update README.md with current test coverage percentage.
"""

import re
import sys
from pathlib import Path


def update_readme_coverage(coverage_percentage: str):
    """Update the README.md file with the new coverage percentage."""
    readme_path = Path("README.md")

    if not readme_path.exists():
        print(f"README.md not found at {readme_path}")
        return False

    content = readme_path.read_text(encoding='utf-8')

    # Determine badge color based on coverage percentage
    coverage_float = float(coverage_percentage)
    if coverage_float >= 90:
        color = "brightgreen"
    elif coverage_float >= 80:
        color = "green"
    elif coverage_float >= 70:
        color = "yellowgreen"
    elif coverage_float >= 60:
        color = "yellow"
    else:
        color = "red"

    # Update the coverage badge at the top
    badge_pattern = r'!\[Coverage\]\(https://img\.shields\.io/badge/coverage-[\d.]+%25-[a-z]+\)'
    new_badge = f'![Coverage](https://img.shields.io/badge/coverage-{coverage_percentage}%25-{color})'

    content = re.sub(badge_pattern, new_badge, content)

    # Update the coverage percentage in the Testing & Quality section
    coverage_text_pattern = r'\*\*(\d+(?:\.\d+)?)%\+ code coverage\*\* across the entire codebase'
    new_coverage_text = f'**{coverage_percentage}%+ code coverage** across the entire codebase'

    content = re.sub(coverage_text_pattern, new_coverage_text, content)

    # Write the updated content back to the file
    readme_path.write_text(content, encoding='utf-8')
    print(f"Updated README.md with coverage percentage: {coverage_percentage}%")
    return True


def main():
    if len(sys.argv) != 2:
        print("Usage: python update_coverage.py <coverage_percentage>")
        sys.exit(1)

    coverage_percentage = sys.argv[1]

    # Validate that it's a number
    try:
        float(coverage_percentage)
    except ValueError:
        print(f"Invalid coverage percentage: {coverage_percentage}")
        sys.exit(1)

    success = update_readme_coverage(coverage_percentage)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
