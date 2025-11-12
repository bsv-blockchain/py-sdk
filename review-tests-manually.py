#!/usr/bin/env python3
"""
Interactive manual review helper for Python tests.
Reads test-manual-review.md and allows marking tests as sufficient or insufficient with notes.
"""

import re
import sys
import subprocess
import webbrowser
from pathlib import Path
from typing import List, Dict, Optional, Tuple


class TestReview:
    """Represents a test with review status."""
    def __init__(self, number: int, name: str, file_link: str, status: Optional[str] = None, notes: str = ""):
        self.number = number
        self.name = name
        self.file_link = file_link
        self.status = status  # "✓" (green tick) or "✗" (red x) or None
        self.notes = notes
    
    def to_markdown_row(self) -> str:
        """Convert to markdown table row."""
        status_display = self.status if self.status else "—"
        notes_display = self.notes.replace('|', '\\|') if self.notes else ""
        return f"| {self.number} | `{self.name}` | {self.file_link} | {status_display} | {notes_display} |"


def parse_markdown_file(file_path: Path) -> List[TestReview]:
    """Parse the test-manual-review.md file and extract test information."""
    tests = []
    
    if not file_path.exists():
        print(f"Error: File {file_path} does not exist.")
        print("Please run ../generate-matching-tests.py from the SDK root to create the file.")
        sys.exit(1)
    
    content = file_path.read_text(encoding='utf-8')
    lines = content.split('\n')
    
    # Find the table header and start parsing rows
    in_table = False
    for line in lines:
        # Skip header separator line
        if line.strip().startswith('|---'):
            in_table = True
            continue
        
        # Parse table rows
        if in_table and line.strip().startswith('|'):
            # Extract columns: | # | Test Name | File | [Status] | [Notes] |
            parts = [p.strip() for p in line.split('|')]
            if len(parts) >= 4:
                try:
                    number = int(parts[1])
                    # Test name is in backticks, remove them
                    name = parts[2].strip('`')
                    file_link = parts[3]
                    
                    # Check if status and notes columns exist
                    status = parts[4] if len(parts) > 4 and parts[4] not in ['—', ''] else None
                    if status == '—':
                        status = None
                    notes = parts[5] if len(parts) > 5 else ""
                    
                    tests.append(TestReview(number, name, file_link, status, notes))
                except (ValueError, IndexError):
                    # Skip malformed rows
                    continue
    
    return tests


def write_markdown_file(file_path: Path, tests: List[TestReview]):
    """Write the updated tests back to the markdown file."""
    lines = [
        "# Python Tests List",
        "",
        f"This file lists all {len(tests)} Python tests with clickable links to their locations.",
        "",
        "| # | Test Name | File | Status | Notes |",
        "|---|-----------|-----|--------|-------|",
    ]
    
    for test in tests:
        lines.append(test.to_markdown_row())
    
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
    
    file_path.write_text('\n'.join(lines), encoding='utf-8')


def extract_file_path_from_link(link: str) -> str:
    """Extract the file path from a markdown link."""
    # Link format: [file:line](path#Lline)
    match = re.search(r'\[([^\]]+)\]\(([^\)]+)\)', link)
    if match:
        return match.group(2).split('#')[0]  # Remove #Lline part
    return ""


def extract_line_number_from_link(link: str) -> Optional[int]:
    """Extract the line number from a markdown link."""
    # Link format: [file:line](path#Lline)
    match = re.search(r'#L(\d+)', link)
    if match:
        return int(match.group(1))
    return None


def get_test_link(file_link: str) -> str:
    """Generate a clickable file:// URI for the test (line numbers not supported in file:// URIs)."""
    file_path = extract_file_path_from_link(file_link)
    line_number = extract_line_number_from_link(file_link)
    
    if not file_path:
        return file_link
    
    # Convert to absolute path
    py_root = Path(__file__).parent.resolve()
    if file_path.startswith('py-sdk/tests/'):
        rel_path = file_path.replace('py-sdk/tests/', 'tests/')
        full_path = py_root.parent / rel_path
    elif file_path.startswith('tests/'):
        full_path = py_root / file_path
    else:
        full_path = py_root / 'tests' / file_path
    
    # Convert to absolute path string
    abs_path = str(full_path.resolve())
    
    # Create file:// URI (file:// URIs don't support line numbers in the standard format)
    # Note: file:// URIs need three slashes: file:///path
    # If line number is needed, it will be handled by Cursor, not the file:// URI
    return f"file://{abs_path}"


def get_test_file_path(file_link: str) -> Tuple[Optional[Path], Optional[int]]:
    """Get the absolute file path and line number from a markdown link.
    Returns: (file_path, line_number) tuple."""
    file_path = extract_file_path_from_link(file_link)
    line_number = extract_line_number_from_link(file_link)
    
    if not file_path:
        return None, None
    
    # Convert to absolute path
    py_root = Path(__file__).parent.resolve()
    if file_path.startswith('py-sdk/tests/'):
        rel_path = file_path.replace('py-sdk/tests/', 'tests/')
        full_path = py_root.parent / rel_path
    elif file_path.startswith('tests/'):
        full_path = py_root / file_path
    else:
        full_path = py_root / 'tests' / file_path
    
    return full_path.resolve(), line_number


def open_test_file(file_link: str) -> bool:
    """Attempt to open the test file in an editor at the specified line number.
    Tries cursor, code, and webbrowser in that order.
    Returns True if successfully opened, False otherwise."""
    file_path, line_number = get_test_file_path(file_link)
    
    if not file_path:
        return False
    
    # Resolve to absolute path and verify it exists
    abs_path_obj = file_path.resolve()
    if not abs_path_obj.exists():
        return False
    
    abs_path = str(abs_path_obj)
    
    # Get the workspace root (py-sdk directory) for relative paths
    py_root = Path(__file__).parent.resolve()
    
    # Try to get relative path from workspace root
    try:
        rel_path = str(abs_path_obj.relative_to(py_root))
    except ValueError:
        # If file is outside workspace, use absolute path
        rel_path = abs_path
    
    # Use cursor with --reuse-window and --goto flags
    # Note: cursor may return non-zero exit codes even on success, so we assume success if no exception
    try:
        if line_number:
            # Try relative path first (better for workspace files)
            if rel_path != abs_path:
                subprocess.run(['cursor', '--reuse-window', '--goto', f"{rel_path}:{line_number}"], 
                              check=False, stdout=subprocess.DEVNULL, 
                              stderr=subprocess.DEVNULL, timeout=5, cwd=py_root)
                # Assume success if no exception (cursor may return non-zero even on success)
                return True
            # Fall back to absolute path
            subprocess.run(['cursor', '--reuse-window', '--goto', f"{abs_path}:{line_number}"], 
                          check=False, stdout=subprocess.DEVNULL, 
                          stderr=subprocess.DEVNULL, timeout=5, cwd=py_root)
            # Assume success if no exception
            return True
        else:
            if rel_path != abs_path:
                subprocess.run(['cursor', '--reuse-window', rel_path], 
                              check=False, stdout=subprocess.DEVNULL, 
                              stderr=subprocess.DEVNULL, timeout=5, cwd=py_root)
                # Assume success if no exception
                return True
            subprocess.run(['cursor', '--reuse-window', abs_path], 
                          check=False, stdout=subprocess.DEVNULL, 
                          stderr=subprocess.DEVNULL, timeout=5, cwd=py_root)
            # Assume success if no exception
            return True
    except (FileNotFoundError, subprocess.SubprocessError, subprocess.TimeoutExpired):
        pass
    
    # Fall back to webbrowser for file:// URI (without line number, as file:// doesn't support it)
    try:
        file_path = extract_file_path_from_link(file_link)
        if file_path:
            py_root = Path(__file__).parent.resolve()
            if file_path.startswith('py-sdk/tests/'):
                rel_path = file_path.replace('py-sdk/tests/', 'tests/')
                full_path = py_root.parent / rel_path
            elif file_path.startswith('tests/'):
                full_path = py_root / file_path
            else:
                full_path = py_root / 'tests' / file_path
            abs_path = str(full_path.resolve())
            file_uri = f"file://{abs_path}"
            webbrowser.open(file_uri)
            return True
    except Exception:
        pass
    
    return False


def display_test(test: TestReview, total: int):
    """Display test information in the terminal."""
    print("\n" + "="*80)
    print(f"Test {test.number} of {total}")
    print("="*80)
    print(f"Test Name: {test.name}")
    
    # Get file path and line number for display (avoid printing file:// URI which triggers auto-open)
    file_path, line_number = get_test_file_path(test.file_link)
    if file_path:
        if line_number:
            print(f"Test File: {file_path}:{line_number}")
        else:
            print(f"Test File: {file_path}")
    else:
        print(f"Test Link: {test.file_link}")
    
    # Automatically open the test file in editor
    if open_test_file(test.file_link):
        print("(Opened in editor)")
    else:
        print("(Could not open in editor)")
    
    if test.status:
        status_text = "✓ Sufficient" if test.status == "✓" else "✗ Insufficient"
        print(f"Current Status: {status_text}")
    else:
        print("Current Status: Not reviewed")
    
    if test.notes:
        print(f"Current Notes: {test.notes}")
    print("="*80)


def get_review_input() -> Tuple[Optional[str], Optional[str], str]:
    """Get review input from user.
    Returns: (status, action, notes_or_action)
    - status: "✓", "✗", or None
    - action: "QUIT", "PREVIOUS", "SKIP", "REPROMPT", or None
    - notes_or_action: notes string if marking as insufficient, otherwise same as action
    """
    print("\nOptions:")
    print("  [p]ass - Mark test as sufficient (green tick)")
    print("  [s]kip - Skip this test (no change)")
    print("  [b]ack - Go back to previous test")
    print("  [q]uit - Save and exit")
    print("  (anything else) - Mark as insufficient with your input as notes")
    
    choice = input("\nEnter choice: ").strip()
    
    # Handle empty input - reprompt
    if not choice:
        print("Empty input. Please enter a valid choice.")
        return None, "REPROMPT", ""
    
    choice_lower = choice.lower()
    
    if choice_lower in ['q', 'quit']:
        return None, "QUIT", "QUIT"
    
    if choice_lower in ['b', 'back']:
        return None, "PREVIOUS", "PREVIOUS"
    
    if choice_lower in ['s', 'skip']:
        return None, "SKIP", "SKIP"
    
    if choice_lower in ['p', 'pass']:
        return "✓", None, ""
    
    # Any other input = mark as insufficient with input as notes
    return "✗", None, choice


def main():
    """Main interactive review loop."""
    # Script is now in py-sdk directory, so use current directory
    py_root = Path(__file__).parent.resolve()
    review_file = py_root / 'test-manual-review.md'
    
    print("Python Test Manual Review Helper")
    print("="*80)
    
    # Parse existing tests
    tests = parse_markdown_file(review_file)
    
    if not tests:
        print("No tests found in the file.")
        return
    
    print(f"Loaded {len(tests)} tests for review.")
    print(f"Reading from and writing to: {review_file}")
    print("="*80)
    
    # Find first unreviewed test (status is None or "—")
    current_index = 0
    for i, test in enumerate(tests):
        if test.status is None or test.status == "—":
            current_index = i
            print(f"Starting at first unreviewed test: Test {test.number}")
            break
    
    while current_index < len(tests):
        test = tests[current_index]
        display_test(test, len(tests))
        
        # Get user input
        status, action, notes_or_action = get_review_input()
        
        if action == "QUIT":
            # Auto-save before quitting
            write_markdown_file(review_file, tests)
            print("Changes saved!")
            break
        elif action == "REPROMPT":
            # Empty input - just continue the loop to reprompt
            continue
        elif action == "PREVIOUS":
            if current_index > 0:
                current_index -= 1
            else:
                print("Already at the first test.")
            continue
        elif action == "SKIP":
            current_index += 1
            continue
        
        # Update test
        if status:
            test.status = status
            # If marking as insufficient, set notes from user input
            if status == "✗" and notes_or_action:
                test.notes = notes_or_action
            
            # Auto-save after each change
            write_markdown_file(review_file, tests)
            
            # Auto-advance to next test after marking
            current_index += 1
    
    print(f"\nReview session complete. Reviewed {current_index} of {len(tests)} tests.")
    print(f"Review file updated: {review_file}")


if __name__ == '__main__':
    main()

