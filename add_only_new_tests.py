#!/usr/bin/env python3
import re

# Read the old file
with open('test-manual-review-old.md', 'r') as f:
    old_content = f.read()

# Read the current file (which should be the new one)
with open('test-manual-review.md', 'r') as f:
    new_content = f.read()

# Extract test names from old file
old_tests = set()
for line in old_content.split('\n'):
    if '| `test_' in line and '|' in line:
        match = re.search(r'\|.*\| `([^`]+)` \|.*\|.*\|.*\|', line)
        if match:
            old_tests.add(match.group(1))

# Extract all test entries from new file (including file paths)
new_test_entries = []
for line in new_content.split('\n'):
    if '| `test_' in line and '|' in line:
        match = re.search(r'\| (\d+) \| `([^`]+)` \| \[([^\]]+)\]\([^)]+\) \| ([^|]+) \| ([^|]*) \|', line)
        if match:
            number, test_name, file_path, status, notes = match.groups()
            new_test_entries.append((test_name, file_path, status, notes))

print(f'Old file has {len(old_tests)} tests')
print(f'New file has {len(new_test_entries)} tests')

# Find truly new tests (in new file but not in old file)
truly_new_tests = []
for test_name, file_path, status, notes in new_test_entries:
    if test_name not in old_tests:
        truly_new_tests.append((test_name, file_path, status, notes))

print(f'Truly new tests: {len(truly_new_tests)}')

# Now add only these truly new tests to the old file content
lines = old_content.split('\n')

# Find the last test number in old file
last_test_match = None
for line in lines:
    match = re.search(r'\| (\d+) \| `([^`]+)` \|.*\|.*\|.*\|', line)
    if match:
        last_test_match = match

last_number = int(last_test_match.group(1)) if last_test_match else 0
print(f'Last test number in old file: {last_number}')

# Update the header count
new_total = last_number + len(truly_new_tests)
lines[2] = f'This file lists all {new_total} Python tests with clickable links to their locations.'

# Find insertion point (before ---)
insert_index = -1
for i, line in enumerate(lines):
    if line.startswith('---'):
        insert_index = i - 1
        break

# Create new entries
new_entries = []
for i, (test_name, file_path, status, notes) in enumerate(truly_new_tests):
    test_number = last_number + i + 1
    entry = f'| {test_number:3d} | `{test_name}` | [{file_path}]({file_path}) | {status} | {notes} |'
    new_entries.append(entry)

print(f'Adding {len(new_entries)} new entries')

# Insert the new entries
if insert_index > 0:
    lines[insert_index:insert_index] = [''] + new_entries

    # Write back to file
    with open('test-manual-review.md', 'w') as f:
        f.write('\n'.join(lines))

    print(f'Successfully added {len(new_entries)} truly new tests to test-manual-review.md')
    print(f'Total tests now: {new_total}')
else:
    print('Could not find insertion point')


