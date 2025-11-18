#!/usr/bin/env python3
import re
import os

def find_test_location(test_name):
    """Find the file and line number for a test."""
    for root, dirs, files in os.walk('tests'):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r') as f:
                        lines = f.readlines()
                        for i, line in enumerate(lines, 1):
                            if f'def {test_name}(' in line:
                                return f'{file_path}:{i}'
                except:
                    continue
    return 'tests/file.py:1'  # fallback

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
        match = re.search(r'\|.*\| `([^`]+)` \|.*\|.*\|.*\|', line)
        if match:
            old_tests.add(match.group(1))

# Extract test names from new file
new_tests = set()
for line in new_content.split('\n'):
    if '| `test_' in line and '|' in line:
        match = re.search(r'\|.*\| `([^`]+)` \|.*\|.*\|.*\|', line)
        if match:
            new_tests.add(match.group(1))

# Find new tests
new_test_list = sorted(new_tests - old_tests)

print(f'Found {len(new_test_list)} new tests to add')

# Find the last test number
last_test_match = None
for line in new_content.split('\n'):
    match = re.search(r'\| (\d+) \| `([^`]+)` \|.*\|.*\|.*\|', line)
    if match:
        last_test_match = match

last_number = int(last_test_match.group(1)) if last_test_match else 682

print(f'Last test number: {last_number}')

# Create new test entries
new_entries = []
for i, test_name in enumerate(new_test_list, 1):
    test_number = last_number + i
    file_location = find_test_location(test_name)
    entry = f'| {test_number:3d} | `{test_name}` | [{file_location}]({file_location}) | — | |'
    new_entries.append(entry)

print(f'Generated {len(new_entries)} new entries')

# Find where to insert (before the --- line)
lines = new_content.split('\n')
insert_index = -1
for i, line in enumerate(lines):
    if line.startswith('---'):
        insert_index = i - 1
        break

if insert_index > 0:
    # Insert new entries
    lines[insert_index:insert_index] = [''] + new_entries

    # Update the total count in the header
    new_total = last_number + len(new_test_list)
    lines[2] = f'This file lists all {new_total} Python tests with clickable links to their locations.'

    # Write back
    with open('test-manual-review.md', 'w') as f:
        f.write('\n'.join(lines))

    print(f'Successfully added {len(new_entries)} new tests to test-manual-review.md')
    print(f'Total tests now: {new_total}')
else:
    print('Could not find insertion point')


