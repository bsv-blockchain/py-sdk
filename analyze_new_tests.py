#!/usr/bin/env python3
import re
from collections import defaultdict

# Read the new file to categorize tests
with open('test-manual-review.md', 'r') as f:
    content = f.read()

# Extract test details
test_categories = defaultdict(list)
for line in content.split('\n'):
    if '| `test_' in line and '|' in line:
        match = re.search(r'\|.*\| `([^`]+)` \|.*\|.*\|.*\|', line)
        if match:
            test_name = match.group(1)
            # Extract file path too
            file_match = re.search(r'\| \[([^\]]+)\]', line)
            if file_match:
                file_path = file_match.group(1)
                # Categorize by directory
                category = file_path.split('/')[1] if '/' in file_path else 'root'
                test_categories[category].append(test_name)

# Count by category
print('Tests by category:')
for category, tests in sorted(test_categories.items()):
    print(f'  {category}: {len(tests)} tests')

print()
print('Key new categories with examples:')
for category in ['script', 'beef', 'headers_client', 'spv', 'auth', 'transaction', 'broadcasters', 'chaintrackers']:
    if category in test_categories:
        tests = test_categories[category]
        print(f'  {category} ({len(tests)} tests):')
        for test in sorted(tests)[:3]:  # Show first 3 examples
            print(f'    - {test}')
        if len(tests) > 3:
            print(f'    ... and {len(tests) - 3} more')
        print()

