import re

# Read both files
with open('test-manual-review.md', 'r') as f:
    review_content = f.read()

with open('test-manual-review-COMPLETE.md', 'r') as f:
    complete_content = f.read()

# Extract test names using regex
review_tests = set(re.findall(r'\| \d+ \| `([^`]+)` \|', review_content))
complete_tests = set(re.findall(r'\| \d+ \| `([^`]+)` \|', complete_content))

print(f'Tests in review file: {len(review_tests)}')
print(f'Tests in complete file: {len(complete_tests)}')

# Tests that are in review but NOT in complete (new tests)
new_tests = review_tests - complete_tests
print(f'\nTests in review but not in complete: {len(new_tests)}')
for test in sorted(new_tests):
    print(f'  - {test}')

# Tests that are in complete but NOT in review
missing_tests = complete_tests - review_tests
print(f'\nTests in complete but not in review: {len(missing_tests)}')
for test in sorted(missing_tests):
    print(f'  - {test}')

# Extract full lines for new tests
print('\n' + '='*50)
print('FULL LINES FOR NEW TESTS:')
print('='*50)

review_lines = review_content.split('\n')
for line in review_lines:
    if '| — |' in line:  # Only unreviewed tests
        test_match = re.search(r'\| \d+ \| `([^`]+)` \|', line)
        if test_match:
            test_name = test_match.group(1)
            if test_name in new_tests:
                print(line)
