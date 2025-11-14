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
        print("Please run generate-testlist.py from the SDK root to create the file.")
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
    Uses cursor with goto functionality.
    Returns True if successfully opened, False otherwise."""
    file_path, line_number = get_test_file_path(file_link)

    if not file_path:
        return False

    # Resolve to absolute path and verify it exists
    abs_path_obj = file_path.resolve()
    if not abs_path_obj.exists():
        print(f"File does not exist: {abs_path_obj}")
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

    # Use cursor with -r (reuse-window) and -g (goto) flags
    # Cursor is asynchronous, so we can't reliably detect success/failure
    # We'll try the command and assume it worked if no exception occurs
    try:
        if line_number:
            # Try relative path first (better for workspace files)
            if rel_path != abs_path:
                result = subprocess.run(['cursor', '-r', '-g', f"{rel_path}:{line_number}"],
                                       check=False, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, timeout=5, cwd=py_root)
                return True
            # Fall back to absolute path
            result = subprocess.run(['cursor', '-r', '-g', f"{abs_path}:{line_number}"],
                                   check=False, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=5, cwd=py_root)
            return True
        else:
            if rel_path != abs_path:
                result = subprocess.run(['cursor', '-r', rel_path],
                                       check=False, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, timeout=5, cwd=py_root)
                return True
            result = subprocess.run(['cursor', '-r', abs_path],
                                   check=False, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=5, cwd=py_root)
            return True
    except (FileNotFoundError, subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
        print(f"Failed to open file in editor: {e}")
        return False

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
        # print("(Opened in editor)") 
        pass
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


def find_test_class(file_path: Path, test_name: str) -> Optional[str]:
    """Find the class name that contains the given test method."""
    try:
        content = file_path.read_text(encoding='utf-8')
        lines = content.split('\n')

        # Find the line with the test method
        test_line_idx = None
        for i, line in enumerate(lines):
            if re.match(rf'^\s*def\s+{re.escape(test_name)}\s*\(', line):
                test_line_idx = i
                break

        if test_line_idx is None:
            return None

        # Work backwards from the test method to find the containing class
        test_indent = len(lines[test_line_idx]) - len(lines[test_line_idx].lstrip())

        for i in range(test_line_idx - 1, -1, -1):
            line = lines[i]
            stripped = line.strip()

            # Look for class definitions
            class_match = re.match(r'^\s*class\s+(\w+)', line)
            if class_match:
                class_indent = len(line) - len(line.lstrip())
                # If the class has less indentation than the test method, it's the containing class
                if class_indent < test_indent:
                    return class_match.group(1)

        return None
    except Exception:
        return None


def run_test(test: TestReview) -> bool:
    """Run the specific test using pytest.
    Returns True if test passed, False otherwise."""
    file_path, line_number = get_test_file_path(test.file_link)

    if not file_path:
        print(f"Could not determine file path for test: {test.name}")
        return False

    if not file_path.exists():
        print(f"Test file does not exist: {file_path}")
        return False

    # Get the relative path from the project root for pytest
    py_root = Path(__file__).parent.resolve()
    try:
        rel_path = str(file_path.relative_to(py_root))
    except ValueError:
        # If file is outside the project, use absolute path
        rel_path = str(file_path)

    # Try to find the class that contains this test method
    class_name = find_test_class(file_path, test.name)

    # Build the test specification
    if class_name:
        test_spec = f"{rel_path}::{class_name}::{test.name}"
    else:
        test_spec = f"{rel_path}::{test.name}"

    print(f"Running test: {test_spec}")
    print("-" * 60)

    try:
        # Don't capture output for more verbose display
        result = subprocess.run(['python', '-m', 'pytest', test_spec, '-v', '-s'],
                              cwd=py_root, timeout=60)

        print("-" * 60)
        if result.returncode == 0:
            print("✓ Test PASSED")
            return True
        else:
            print("✗ Test FAILED")
            return False

    except subprocess.TimeoutExpired:
        print("✗ Test execution timed out")
        return False
    except FileNotFoundError:
        print("✗ pytest not found. Make sure pytest is installed.")
        return False
    except Exception as e:
        print(f"✗ Error running test: {e}")
        return False


def get_review_input() -> Tuple[Optional[str], Optional[str], str]:
    """Get review input from user.
    Returns: (status, action, notes_or_action)
    - status: "✓", "✗", or None
    - action: "QUIT", "PREVIOUS", "SKIP", "REPROMPT", "TEST", or None
    - notes_or_action: notes string if marking as insufficient, otherwise same as action
    """
    print("\nOptions:")
    print("  [p]ass - Mark test as sufficient (green tick)")
    print("  [t]est - Run this specific test")
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

    if choice_lower in ['t', 'test']:
        return None, "TEST", "TEST"

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
    
    # Count tests by status
    sufficient_count = sum(1 for test in tests if test.status == "✓")
    needs_review_count = len(tests) - sufficient_count

    print(f"Loaded {len(tests)} tests total.")
    print(f"- {sufficient_count} tests marked as sufficient (will be skipped)")
    print(f"- {needs_review_count} tests need review")
    print(f"Reading from and writing to: {review_file}")
    print("="*80)
    
    # Find first test that needs review (not sufficient)
    current_index = 0
    for i, test in enumerate(tests):
        if test.status != "✓":  # Skip tests marked as sufficient
            current_index = i
            if test.status is None or test.status == "—":
                print(f"Starting at first unreviewed test: Test {test.number}")
            else:
                print(f"Starting at test needing review: Test {test.number} (Status: {test.status or '—'})")
            break
    
    def find_next_non_sufficient_index(start_index: int) -> int:
        """Find the next test that is not marked as sufficient."""
        for i in range(start_index, len(tests)):
            if tests[i].status != "✓":
                return i
        return len(tests)  # No more tests to review

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
            # Find the previous test that needs review (skip sufficient ones)
            if current_index > 0:
                for i in range(current_index - 1, -1, -1):
                    if tests[i].status != "✓":
                        current_index = i
                        break
                else:
                    print("Already at the first test that needs review.")
            else:
                print("Already at the first test that needs review.")
            continue
        elif action == "SKIP":
            next_index = find_next_non_sufficient_index(current_index + 1)
            if next_index < len(tests):
                current_index = next_index
            else:
                print("No more tests to review!")
                current_index = len(tests)
            continue
        elif action == "TEST":
            # Run the test for informational purposes only
            run_test(test)
            # Do not auto-mark or auto-advance - stay for manual review
            continue

        # Update test
        if status:
            test.status = status
            # If marking as insufficient, set notes from user input
            if status == "✗" and notes_or_action:
                test.notes = notes_or_action
            
            # Auto-save after each change
            write_markdown_file(review_file, tests)
            
            # Auto-advance to next test that needs review (skip sufficient ones)
            next_index = find_next_non_sufficient_index(current_index + 1)
            if next_index < len(tests):
                current_index = next_index
            else:
                print("No more tests to review!")
                current_index = len(tests)
    
    print(f"\nReview session complete. Reviewed {current_index} of {len(tests)} tests.")
    print(f"Review file updated: {review_file}")


if __name__ == '__main__':
    main()

