#!/usr/bin/env python3
import re

# Read the old file
with open('test-manual-review-old.md', 'r') as f:
    old_content = f.read()

# Read the new file
with open('test-manual-review.md', 'r') as f:
    new_content = f.read()

# Extract test names from old file
old_tests = set()
for line in old_content.split('\n'):
    if '| `test_' in line and '|' in line:
        # Match pattern: | ### | `test_name` | file_path | status | notes |
        match = re.search(r'\|.*\| `([^`]+)` \|.*\|.*\|.*\|', line)
        if match:
            old_tests.add(match.group(1))

# Extract test names from new file
new_tests = set()
for line in new_content.split('\n'):
    if '| `test_' in line and '|' in line:
        # Match pattern: | ### | `test_name` | file_path | status | notes |
        match = re.search(r'\|.*\| `([^`]+)` \|.*\|.*\|.*\|', line)
        if match:
            new_tests.add(match.group(1))

# Find new tests
new_test_list = sorted(new_tests - old_tests)
print(f'Found {len(new_test_list)} new tests:')
print()
for i, test in enumerate(new_test_list, 1):
    print(f'{i:2d}. {test}')

# Also show summary
print(f'\nSummary:')
print(f'Old file: {len(old_tests)} tests')
print(f'New file: {len(new_tests)} tests')
print(f'New tests: {len(new_test_list)} tests')