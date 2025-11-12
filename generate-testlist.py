#!/usr/bin/env python3
"""
Generate a list of all Python tests with clickable links.
Creates timestamped test-manual-review-YYYYMMDD-HHMMSS.md files
to avoid overwriting manually reviewed files.
"""

import re
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional
from datetime import datetime


@dataclass
class TestCase:
    """Represents a single test case."""
    file_path: str
    test_name: str
    line_number: int
    full_name: str


def parse_py_tests_with_lines(py_root: Path) -> List[TestCase]:
    """Parse Python test files directly to get line numbers."""
    test_cases = []

    # Find all test files
    test_files = list(py_root.glob('tests/**/test_*.py'))
    
    # Sort test files for consistent ordering
    test_files.sort(key=lambda f: str(f))

    for test_file in test_files:
        rel_path = str(test_file.relative_to(py_root / 'tests'))

        try:
            content = test_file.read_text(encoding='utf-8')
            lines = content.split('\n')

            # Pattern for: def test_something(...) or async def test_something(...)
            test_pattern = r'^\s*(?:async\s+)?def\s+(test_[a-zA-Z0-9_]+)\s*\('

            for line_idx, line in enumerate(lines, start=1):
                match = re.match(test_pattern, line)
                if match:
                    test_name = match.group(1)
                    test_cases.append(TestCase(
                        file_path=rel_path,
                        test_name=test_name,
                        line_number=line_idx,
                        full_name=test_name
                    ))
        except Exception as e:
            print(f"Error reading {test_file}: {e}")

    return test_cases


def generate_python_tests_list(py_tests: List[TestCase], py_root: Path, output_file: Path = None) -> str:
    """Generate a markdown list of all Python tests with clickable links."""
    
    # If output_file is provided, calculate relative paths from it
    # Otherwise use paths relative to py_root
    if output_file:
        output_dir = output_file.parent
        py_base = py_root / "tests"
    else:
        py_base = Path("tests")
    
    # Sort tests by file path, then by line number for consistent ordering
    sorted_tests = sorted(py_tests, key=lambda t: (t.file_path, t.line_number))
    
    lines = [
        "# Python Tests List",
        "",
        f"This file lists all {len(sorted_tests)} Python tests with clickable links to their locations.",
        "",
        "| # | Test Name | File | Status | Notes |",
        "|---|-----------|-----|--------|-------|",
    ]
    
    for idx, test in enumerate(sorted_tests, start=1):
        test_name = test.test_name.replace('|', '\\|')
        
        # Create clickable file:line link
        if output_file:
            py_full_path = py_base / test.file_path
            try:
                py_relative = str(py_full_path.relative_to(output_dir))
            except ValueError:
                # If paths are on different drives (Windows), use absolute with file://
                py_relative = f"file:///{py_full_path.as_posix()}"
        else:
            py_relative = f"tests/{test.file_path}"
        
        # Format: [file:line](path#Lline) - works in VS Code/Cursor markdown preview
        file_link = f"[{test.file_path}:{test.line_number}]({py_relative}#L{test.line_number})"
        
        lines.append(f"| {idx} | `{test_name}` | {file_link} | — | |")
    
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("**Note:** Click on file paths to open them at the exact line number in VS Code or Cursor.")
    lines.append("")
    lines.append("**Status Legend:**")
    lines.append("- ✓ = Test is sufficient")
    lines.append("- ✗ = Test needs improvement or is insufficient")
    lines.append("- — = Not yet reviewed")
    lines.append("")
    
    return '\n'.join(lines)


def main():
    """Main function to generate Python test list."""
    # Script is in py-sdk directory
    py_root = Path(__file__).parent.resolve()
    
    print("Parsing Python tests with line numbers...")
    py_tests = parse_py_tests_with_lines(py_root)
    print(f"Found {len(py_tests)} Python tests")
    
    # Write Python tests list file with timestamp to avoid overwriting manual reviews
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    python_tests_file = py_root / f'test-manual-review-{timestamp}.md'
    
    print("\nGenerating Python tests list...")
    python_tests_markdown = generate_python_tests_list(py_tests, py_root, python_tests_file)
    
    python_tests_file.write_text(python_tests_markdown)
    print(f"Python tests list written to: {python_tests_file}")
    print(f"\nTotal tests: {len(py_tests)}")


if __name__ == '__main__':
    main()

