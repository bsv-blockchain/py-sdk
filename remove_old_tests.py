#!/usr/bin/env python3
import re

# Read the old file to get existing test names
with open('test-manual-review-old.md', 'r') as f:
    old_content = f.read()

# Read the current file (with all tests)
with open('test-manual-review.md', 'r') as f:
    current_content = f.read()

# Extract test names from old file
old_tests = set()
for line in old_content.split('\n'):
    if '| `test_' in line and '|' in line:
        match = re.search(r'\|.*\| `([^`]+)` \|.*\|.*\|.*\|', line)
        if match:
            old_tests.add(match.group(1))

print(f'Old file has {len(old_tests)} tests')

# Parse current file and keep only new tests
lines = current_content.split('\n')
new_lines = []
test_count = 0

for line in lines:
    if '| `test_' in line and '|' in line:
        match = re.search(r'\|.*\| `([^`]+)` \|.*\|.*\|.*\|', line)
        if match:
            test_name = match.group(1)
            if test_name not in old_tests:
                # This is a new test, renumber it
                test_count += 1
                # Replace the number in the line
                line = re.sub(r'\| (\d+) \|', f'| {test_count:3d} |', line)
                new_lines.append(line)
    else:
        # Keep non-test lines, but update the header
        if 'This file lists all' in line and 'Python tests' in line:
            line = f'This file lists all {test_count} Python tests with clickable links to their locations.'
        new_lines.append(line)

print(f'Kept {test_count} new tests')

# Write back the filtered content
with open('test-manual-review.md', 'w') as f:
    f.write('\n'.join(new_lines))

print('Successfully updated test-manual-review.md with only new tests')


