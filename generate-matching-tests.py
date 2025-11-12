#!/usr/bin/env python3
"""
Generate a report of test cases across TypeScript, Python, and Go SDKs.
Creates a markdown table with clickable links to implementation files and line numbers.
"""

import re
import subprocess
from pathlib import Path
from difflib import SequenceMatcher
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional


@dataclass
class TestCase:
    """Represents a single test case."""
    file_path: str
    test_name: str
    line_number: int
    full_name: str


@dataclass
class MatchedTest:
    """Represents a test that exists in both TS and Python."""
    test_name: str
    ts_file_path: str
    ts_line_number: int
    py_file_path: str
    py_line_number: int
    py_function_name: str  # Actual Python function name (e.g., test_something)
    similarity_score: float


@dataclass
class UnifiedTestMatch:
    """Represents a test that may exist in TS, Python, and/or Go."""
    normalized_name: str
    display_name: str  # Original test name from TS (or first found)
    ts_match: Optional[TestCase] = None
    py_match: Optional[TestCase] = None
    go_match: Optional[TestCase] = None
    similarity_scores: Dict[str, float] = None  # Track similarity for fuzzy matches
    
    def __post_init__(self):
        if self.similarity_scores is None:
            self.similarity_scores = {}


def normalize_name(name: str) -> str:
    """Normalize test names for comparison."""
    # Convert from camelCase/PascalCase to snake_case
    name = re.sub('([a-z0-9])([A-Z])', r'\1_\2', name)
    # Remove common prefixes
    name = re.sub(r'^(test_|Test)', '', name, flags=re.IGNORECASE)
    # Remove special characters
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    # Lowercase
    name = name.lower()
    # Remove multiple underscores
    name = re.sub(r'_+', '_', name)
    # Remove leading/trailing underscores
    name = name.strip('_')
    return name


def similarity(a: str, b: str) -> float:
    """Calculate similarity ratio between two strings."""
    return SequenceMatcher(None, a, b).ratio()


def parse_ts_tests_with_lines(ts_root: Path) -> List[TestCase]:
    """Parse TypeScript test files and extract test cases with line numbers."""
    test_cases = []

    # Find all test files
    test_files = []
    for pattern in ['**/*.test.ts', '**/*.spec.ts']:
        for f in ts_root.glob(pattern):
            # Skip node_modules
            if 'node_modules' not in str(f):
                test_files.append(f)
    
    # Sort test files for consistent ordering
    test_files.sort(key=lambda f: str(f))

    for test_file in test_files:
        rel_path = str(test_file.relative_to(ts_root))

        try:
            content = test_file.read_text(encoding='utf-8')
            lines = content.split('\n')

            # Extract test names with line numbers using regex
            # Pattern for: it('test name', ...) or test('test name', ...)
            test_pattern = r"(?:it|test)\s*\(\s*['\"]([^'\"]+)['\"]"

            for line_idx, line in enumerate(lines, start=1):
                matches = re.finditer(test_pattern, line)
                for match in matches:
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


def parse_py_tests_with_lines(py_root: Path) -> Tuple[List[TestCase], Dict[str, str]]:
    """Parse Python test files directly to get line numbers."""
    test_cases = []
    test_files_with_paths = {}  # filename -> full relative path

    # Find all test files
    test_files = list(py_root.glob('tests/**/test_*.py'))
    
    # Sort test files for consistent ordering
    test_files.sort(key=lambda f: str(f))

    for test_file in test_files:
        rel_path = str(test_file.relative_to(py_root / 'tests'))
        filename = test_file.name
        test_files_with_paths[filename] = rel_path

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

    return test_cases, test_files_with_paths


def parse_go_tests_with_lines(go_root: Path) -> List[TestCase]:
    """Parse Go test files and extract test cases with line numbers."""
    test_cases = []

    # Find all test files
    test_files = list(go_root.glob('**/*_test.go'))
    
    # Sort test files for consistent ordering
    test_files.sort(key=lambda f: str(f))

    for test_file in test_files:
        rel_path = str(test_file.relative_to(go_root))

        try:
            content = test_file.read_text(encoding='utf-8')
            lines = content.split('\n')

            # Pattern for top-level test functions: func TestSomething(t *testing.T)
            top_level_pattern = r'^\s*func\s+(Test[A-Z][a-zA-Z0-9_]*)\s*\(t\s+\*testing\.T\)'
            
            # Pattern for sub-tests: t.Run("subtest name", func(t *testing.T) {...})
            subtest_pattern = r't\.Run\s*\(\s*["\']([^"\']+)["\']'

            for line_idx, line in enumerate(lines, start=1):
                # Check for top-level test function
                top_match = re.match(top_level_pattern, line)
                if top_match:
                    test_name = top_match.group(1)
                    test_cases.append(TestCase(
                        file_path=rel_path,
                        test_name=test_name,
                        line_number=line_idx,
                        full_name=test_name
                    ))
                
                # Check for sub-tests (t.Run calls)
                subtest_matches = re.finditer(subtest_pattern, line)
                for match in subtest_matches:
                    subtest_name = match.group(1)
                    test_cases.append(TestCase(
                        file_path=rel_path,
                        test_name=subtest_name,
                        line_number=line_idx,
                        full_name=subtest_name
                    ))
        except Exception as e:
            print(f"Error reading {test_file}: {e}")

    return test_cases


def find_all_matches(
    ts_tests: List[TestCase],
    py_tests: List[TestCase],
    go_tests: List[TestCase]
) -> List[UnifiedTestMatch]:
    """Find all test matches across TypeScript, Python, and Go."""
    
    # Create normalized lookup dictionaries for each language
    ts_normalized: Dict[str, List[TestCase]] = {}
    py_normalized: Dict[str, List[TestCase]] = {}
    go_normalized: Dict[str, List[TestCase]] = {}
    
    for ts_test in ts_tests:
        normalized = normalize_name(ts_test.test_name)
        if normalized not in ts_normalized:
            ts_normalized[normalized] = []
        ts_normalized[normalized].append(ts_test)
    
    for py_test in py_tests:
        normalized = normalize_name(py_test.test_name)
        if normalized not in py_normalized:
            py_normalized[normalized] = []
        py_normalized[normalized].append(py_test)
    
    for go_test in go_tests:
        normalized = normalize_name(go_test.test_name)
        if normalized not in go_normalized:
            go_normalized[normalized] = []
        go_normalized[normalized].append(go_test)
    
    # Collect all unique normalized names
    all_normalized = set(ts_normalized.keys()) | set(py_normalized.keys()) | set(go_normalized.keys())
    
    unified_matches = []
    
    # Track which tests have been used in fuzzy matches to prevent duplicates
    # Use (file_path, line_number) as unique identifier
    used_ts_tests = set()
    used_py_tests = set()
    used_go_tests = set()
    
    for norm_name in sorted(all_normalized):
        # Get matches from each language (take first match if multiple)
        ts_match = ts_normalized[norm_name][0] if norm_name in ts_normalized else None
        py_match = py_normalized[norm_name][0] if norm_name in py_normalized else None
        go_match = go_normalized[norm_name][0] if norm_name in go_normalized else None
        
        # Mark ALL tests in normalized groups as used (not just the first one)
        # This prevents tests that normalize to the same name from being reused
        if norm_name in ts_normalized:
            for ts_test in ts_normalized[norm_name]:
                used_ts_tests.add((ts_test.file_path, ts_test.line_number))
        if norm_name in py_normalized:
            for py_test in py_normalized[norm_name]:
                used_py_tests.add((py_test.file_path, py_test.line_number))
        if norm_name in go_normalized:
            for go_test in go_normalized[norm_name]:
                used_go_tests.add((go_test.file_path, go_test.line_number))
        
        # Determine display name (prefer TS, then Python, then Go)
        if ts_match:
            display_name = ts_match.test_name
        elif py_match:
            display_name = py_match.test_name
        elif go_match:
            display_name = go_match.test_name
        else:
            display_name = norm_name
        
        # Check for fuzzy matches if no exact match in a language
        # Only try fuzzy matching if we have at least one exact match
        similarity_scores = {}
        
        has_any_match = ts_match or py_match or go_match
        
        # If TS missing and we have a match in another language, try fuzzy match
        if not ts_match and has_any_match:
            best_ts = None
            best_score = 0.0
            for ts_norm, ts_list in ts_normalized.items():
                # Skip if this normalized name already has an exact match (already processed)
                if ts_norm == norm_name:
                    continue
                for ts_test in ts_list:
                    ts_id = (ts_test.file_path, ts_test.line_number)
                    # Only consider tests that haven't been used yet
                    if ts_id not in used_ts_tests:
                        score = similarity(norm_name, ts_norm)
                        if score > best_score and score > 0.8:
                            best_score = score
                            best_ts = ts_test
            if best_ts:
                ts_match = best_ts
                used_ts_tests.add((best_ts.file_path, best_ts.line_number))
                similarity_scores['ts'] = best_score
        
        # If Python missing and we have a match in another language, try fuzzy match
        if not py_match and has_any_match:
            best_py = None
            best_score = 0.0
            for py_norm, py_list in py_normalized.items():
                # Skip if this normalized name already has an exact match (already processed)
                if py_norm == norm_name:
                    continue
                for py_test in py_list:
                    py_id = (py_test.file_path, py_test.line_number)
                    # Only consider tests that haven't been used yet
                    if py_id not in used_py_tests:
                        score = similarity(norm_name, py_norm)
                        if score > best_score and score > 0.8:
                            best_score = score
                            best_py = py_test
            if best_py:
                py_match = best_py
                used_py_tests.add((best_py.file_path, best_py.line_number))
                similarity_scores['py'] = best_score
        
        # If Go missing and we have a match in another language, try fuzzy match
        if not go_match and has_any_match:
            best_go = None
            best_score = 0.0
            for go_norm, go_list in go_normalized.items():
                # Skip if this normalized name already has an exact match (already processed)
                if go_norm == norm_name:
                    continue
                for go_test in go_list:
                    go_id = (go_test.file_path, go_test.line_number)
                    # Only consider tests that haven't been used yet
                    if go_id not in used_go_tests:
                        score = similarity(norm_name, go_norm)
                        if score > best_score and score > 0.8:
                            best_score = score
                            best_go = go_test
            if best_go:
                go_match = best_go
                used_go_tests.add((best_go.file_path, best_go.line_number))
                similarity_scores['go'] = best_score
        
        unified_matches.append(UnifiedTestMatch(
            normalized_name=norm_name,
            display_name=display_name,
            ts_match=ts_match,
            py_match=py_match,
            go_match=go_match,
            similarity_scores=similarity_scores
        ))
    
    return unified_matches


def generate_markdown_table(unified_matches: List[UnifiedTestMatch], ts_root: Path, py_root: Path, go_root: Path, output_file: Path = None) -> str:
    """Generate a markdown table of matching tests with clickable links across all three languages."""
    
    # Get workspace root (parent of all repos)
    workspace_root = ts_root.parent
    
    # If output_file is provided, calculate relative paths from it
    # Otherwise use paths relative to workspace root
    if output_file:
        output_dir = output_file.parent
        ts_base = Path(workspace_root) / "ts-sdk"
        py_base = Path(workspace_root) / "py-sdk" / "tests"
        go_base = Path(workspace_root) / "go-sdk"
    else:
        ts_base = Path("ts-sdk")
        py_base = Path("py-sdk/tests")
        go_base = Path("go-sdk")

    # Sort by normalized name for consistent ordering
    unified_matches.sort(key=lambda x: x.normalized_name)

    # Count unique tests (by file_path and line_number) to avoid double-counting
    unique_ts_tests = set((m.ts_match.file_path, m.ts_match.line_number) for m in unified_matches if m.ts_match)
    unique_py_tests = set((m.py_match.file_path, m.py_match.line_number) for m in unified_matches if m.py_match)
    unique_go_tests = set((m.go_match.file_path, m.go_match.line_number) for m in unified_matches if m.go_match)
    
    total_with_ts = len(unique_ts_tests)
    total_with_py = len(unique_py_tests)
    total_with_go = len(unique_go_tests)
    total_all_three = sum(1 for m in unified_matches if m.ts_match and m.py_match and m.go_match)

    lines = [
        "# Matching Test Cases (TypeScript ↔ Python ↔ Go)",
        "",
        "This table shows test cases across all three SDK implementations.",
        "",
        f"**Total unique test names: {len(unified_matches)}**",
        f"- Unique tests with TypeScript: {total_with_ts}",
        f"- Unique tests with Python: {total_with_py}",
        f"- Unique tests with Go: {total_with_go}",
        f"- Tests in all three: {total_all_three}",
        "",
        "| Test Name | TypeScript | Python | Go |",
        "|-----------|-----------|--------|-----|",
    ]

    for match in unified_matches:
        test_name = match.display_name.replace('|', '\\|')
        
        # Add similarity indicators for fuzzy matches
        similarity_parts = []
        if 'ts' in match.similarity_scores:
            similarity_parts.append(f"TS:{match.similarity_scores['ts']:.0%}")
        if 'py' in match.similarity_scores:
            similarity_parts.append(f"PY:{match.similarity_scores['py']:.0%}")
        if 'go' in match.similarity_scores:
            similarity_parts.append(f"GO:{match.similarity_scores['go']:.0%}")
        if similarity_parts:
            test_name += f" *({', '.join(similarity_parts)})*"

        # Create TypeScript link
        if match.ts_match:
            if output_file:
                ts_full_path = ts_base / match.ts_match.file_path
                try:
                    ts_relative = str(ts_full_path.relative_to(output_dir))
                except ValueError:
                    ts_relative = f"file:///{ts_full_path.as_posix()}"
            else:
                ts_relative = f"ts-sdk/{match.ts_match.file_path}"
            ts_link = f"[{match.ts_match.file_path}:{match.ts_match.line_number}]({ts_relative}#L{match.ts_match.line_number})"
        else:
            ts_link = "—"

        # Create Python link
        if match.py_match:
            if output_file:
                py_full_path = py_base / match.py_match.file_path
                try:
                    py_relative = str(py_full_path.relative_to(output_dir))
                except ValueError:
                    py_relative = f"file:///{py_full_path.as_posix()}"
            else:
                py_relative = f"py-sdk/tests/{match.py_match.file_path}"
            py_link = f"[{match.py_match.file_path}:{match.py_match.line_number}]({py_relative}#L{match.py_match.line_number})"
        else:
            py_link = "—"

        # Create Go link
        if match.go_match:
            if output_file:
                go_full_path = go_base / match.go_match.file_path
                try:
                    go_relative = str(go_full_path.relative_to(output_dir))
                except ValueError:
                    go_relative = f"file:///{go_full_path.as_posix()}"
            else:
                go_relative = f"go-sdk/{match.go_match.file_path}"
            go_link = f"[{match.go_match.file_path}:{match.go_match.line_number}]({go_relative}#L{match.go_match.line_number})"
        else:
            go_link = "—"

        lines.append(f"| {test_name} | {ts_link} | {py_link} | {go_link} |")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("**Legend:**")
    lines.append("- Percentages in parentheses indicate fuzzy matches (< 100% similarity)")
    lines.append("- Click on file paths to open them at the exact line number")
    lines.append("- \"—\" indicates the test does not exist in that language")
    lines.append("")

    return '\n'.join(lines)


def generate_python_tests_list(py_tests: List[TestCase], py_root: Path, output_file: Path = None) -> str:
    """Generate a markdown list of all Python tests with clickable links."""
    
    # Get workspace root (parent of py_root)
    workspace_root = py_root.parent
    
    # If output_file is provided, calculate relative paths from it
    # Otherwise use paths relative to workspace root
    if output_file:
        output_dir = output_file.parent
        py_base = Path(workspace_root) / "py-sdk" / "tests"
    else:
        py_base = Path("py-sdk/tests")
    
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
            py_relative = f"py-sdk/tests/{test.file_path}"
        
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
    # Paths - workspace root is /home/sneakyfox/SDK
    workspace_root = Path('/home/sneakyfox/SDK')
    ts_root = workspace_root / 'ts-sdk'
    py_root = workspace_root / 'py-sdk'
    go_root = workspace_root / 'go-sdk'

    print("Parsing TypeScript tests with line numbers...")
    ts_tests = parse_ts_tests_with_lines(ts_root)
    print(f"Found {len(ts_tests)} TypeScript tests")

    print("\nParsing Python tests with line numbers...")
    py_tests, py_test_files_with_paths = parse_py_tests_with_lines(py_root)
    print(f"Found {len(py_tests)} Python tests in {len(py_test_files_with_paths)} files")

    print("\nParsing Go tests with line numbers...")
    go_tests = parse_go_tests_with_lines(go_root)
    print(f"Found {len(go_tests)} Go tests")

    print("\nFinding matching tests across all languages...")
    unified_matches = find_all_matches(ts_tests, py_tests, go_tests)
    print(f"Found {len(unified_matches)} unique test names")

    # Write matching tests file
    output_file = workspace_root / 'matching_tests.md'
    
    print("\nGenerating markdown table...")
    markdown = generate_markdown_table(unified_matches, ts_root, py_root, go_root, output_file)
    
    output_file.write_text(markdown)
    print(f"Markdown table written to: {output_file}")
    
    # Write Python tests list file
    python_tests_file = py_root / 'test-manual-review.md'
    
    print("\nGenerating Python tests list...")
    python_tests_markdown = generate_python_tests_list(py_tests, py_root, python_tests_file)
    
    python_tests_file.write_text(python_tests_markdown)
    print(f"Python tests list written to: {python_tests_file}")

    # Print summary
    # Count unique tests (by file_path and line_number) to avoid double-counting
    unique_ts_tests = set((m.ts_match.file_path, m.ts_match.line_number) for m in unified_matches if m.ts_match)
    unique_py_tests = set((m.py_match.file_path, m.py_match.line_number) for m in unified_matches if m.py_match)
    unique_go_tests = set((m.go_match.file_path, m.go_match.line_number) for m in unified_matches if m.go_match)
    
    total_with_ts = len(unique_ts_tests)
    total_with_py = len(unique_py_tests)
    total_with_go = len(unique_go_tests)
    total_all_three = sum(1 for m in unified_matches if m.ts_match and m.py_match and m.go_match)
    
    print(f"\n{'='*80}")
    print("SUMMARY")
    print(f"{'='*80}")
    print(f"Total TypeScript tests: {len(ts_tests)}")
    print(f"Total Python tests: {len(py_tests)}")
    print(f"Total Go tests: {len(go_tests)}")
    print(f"Unique test names: {len(unified_matches)}")
    print(f"Unique tests with TypeScript: {total_with_ts}")
    print(f"Unique tests with Python: {total_with_py}")
    print(f"Unique tests with Go: {total_with_go}")
    print(f"Tests in all three languages: {total_all_three}")
    print(f"{'='*80}")


if __name__ == '__main__':
    main()
