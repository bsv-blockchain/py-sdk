# Test Coverage Quick Reference Guide

Quick reference for implementing coverage improvements. See full plans for details.

## 🎯 Current Status
- **Coverage:** 66% → Target: 76%
- **Missing:** 7,481 statements
- **Priority:** High-impact files first

## 📊 Top Priority Files (Copy/Paste Ready)

### 1. bsv/utils.py (357 statements, 0% coverage)
```bash
# Create test file
touch tests/bsv/test_utils_varint.py
touch tests/bsv/test_utils_hex.py
touch tests/bsv/test_utils_pushdrop.py

# Run specific tests
pytest tests/bsv/test_utils_varint.py -v
pytest tests/bsv/test_utils_hex.py -v
pytest tests/bsv/test_utils_pushdrop.py -v

# Check coverage for this file only
pytest --cov=bsv.utils --cov-report=term-missing tests/bsv/test_utils_*.py
```

**Functions to test:**
- `unsigned_to_varint()`, `varint_to_unsigned()` - 15 tests
- `hex_to_bytes()`, `bytes_to_hex()` - 10 tests
- `encode_pushdrop_token()`, `decode_pushdrop_token()` - 12 tests

### 2. bsv/wallet/serializer/list_outputs.py (114 statements, 4% coverage)
```bash
# Create test file
touch tests/bsv/wallet/test_list_outputs_serializer.py

# Run tests
pytest tests/bsv/wallet/test_list_outputs_serializer.py -v

# Check coverage
pytest --cov=bsv.wallet.serializer.list_outputs --cov-report=term-missing \
       tests/bsv/wallet/test_list_outputs_serializer.py
```

**Functions to test:**
- `serialize_list_outputs_args()` - 12 tests
- `deserialize_list_outputs_result()` - 8 tests
- Round-trip tests - 4 tests

### 3. bsv/identity/client.py (172 statements, 13% coverage)
```bash
# Create test file
touch tests/bsv/identity/test_identity_client_comprehensive.py

# Run tests
pytest tests/bsv/identity/test_identity_client_comprehensive.py -v

# Check coverage
pytest --cov=bsv.identity.client --cov-report=term-missing \
       tests/bsv/identity/test_identity_client_comprehensive.py
```

**Methods to test:**
- `authenticate()` - 6 tests
- `get_identity()`, `resolve()` - 6 tests
- `create_identity()`, `update_identity()` - 8 tests
- Edge cases - 11 tests

### 4. bsv/utils/binary.py (67 statements, 31% coverage)
```bash
# Extend existing test file
# File: tests/bsv/test_utils_coverage.py (already exists)

# Run tests
pytest tests/bsv/test_utils_coverage.py::TestBinaryOperations -v

# Check coverage
pytest --cov=bsv.utils.binary --cov-report=term-missing \
       tests/bsv/test_utils_coverage.py
```

**Functions to test:**
- `int_to_bytes()`, `bytes_to_int()` - 10 tests
- `int_to_bytes_signed()`, `bytes_to_int_signed()` - 8 tests
- `reverse_bytes()`, bit operations - 9 tests

## 🔧 Test Template

### Basic Test Structure
```python
import pytest
from bsv.module import function_to_test

class TestFunctionName:
    """Test function_to_test."""
    
    def test_valid_input_case_1(self):
        """Test with valid input scenario 1."""
        result = function_to_test(valid_input)
        assert result == expected_output
    
    def test_valid_input_case_2(self):
        """Test with valid input scenario 2."""
        result = function_to_test(another_valid_input)
        assert result == expected_output
    
    def test_invalid_input_raises(self):
        """Test that invalid input raises appropriate error."""
        with pytest.raises(ValueError, match="error pattern"):
            function_to_test(invalid_input)
    
    def test_edge_case_empty(self):
        """Test with empty input."""
        with pytest.raises(ValueError, match="empty"):
            function_to_test("")
    
    def test_edge_case_none(self):
        """Test with None input."""
        with pytest.raises(TypeError):
            function_to_test(None)
    
    @pytest.mark.parametrize("input,expected", [
        (input1, output1),
        (input2, output2),
        (input3, output3),
    ])
    def test_multiple_cases(self, input, expected):
        """Test multiple input/output pairs."""
        assert function_to_test(input) == expected
```

### Mocking Template
```python
from unittest.mock import Mock, patch, MagicMock

class TestWithMocking:
    """Test functions that use external dependencies."""
    
    @patch('bsv.module.external_function')
    def test_with_mocked_dependency(self, mock_external):
        """Test with mocked external function."""
        # Setup mock
        mock_external.return_value = expected_value
        
        # Call function
        result = function_to_test()
        
        # Verify
        assert result == expected_result
        mock_external.assert_called_once()
    
    @patch('bsv.module.ExternalClass')
    def test_with_mocked_class(self, MockClass):
        """Test with mocked class."""
        # Setup mock instance
        mock_instance = MockClass.return_value
        mock_instance.method.return_value = expected_value
        
        # Call function
        result = function_to_test()
        
        # Verify
        assert result == expected_result
        mock_instance.method.assert_called_once()
```

### Round-Trip Test Template
```python
class TestRoundTrip:
    """Test encode/decode round trips."""
    
    @pytest.mark.parametrize("data", [
        test_data_1,
        test_data_2,
        test_data_3,
    ])
    def test_round_trip(self, data):
        """Test that encode -> decode returns original data."""
        encoded = encode_function(data)
        decoded = decode_function(encoded)
        assert decoded == data
```

## 📋 Checklist for Each Test File

- [ ] Import all necessary modules
- [ ] Create test class with descriptive name
- [ ] Add docstring explaining what's being tested
- [ ] Test happy path (valid inputs)
- [ ] Test edge cases (empty, zero, max values)
- [ ] Test error cases (invalid inputs)
- [ ] Test boundary conditions
- [ ] Add parametrized tests for multiple cases
- [ ] Add round-trip tests where applicable
- [ ] Use appropriate mocks for external dependencies
- [ ] Run tests and verify they pass
- [ ] Check coverage increase
- [ ] Update docstrings if needed

## 🏃 Common Commands

### Run All Tests
```bash
cd /home/sneakyfox/SDK/py-sdk
pytest
```

### Run Tests with Coverage
```bash
pytest --cov=bsv --cov-report=html --cov-report=term
```

### Run Specific Test File
```bash
pytest tests/bsv/test_utils_coverage.py -v
```

### Run Specific Test Class
```bash
pytest tests/bsv/test_utils_coverage.py::TestUtilsCoverage -v
```

### Run Specific Test Method
```bash
pytest tests/bsv/test_utils_coverage.py::TestUtilsCoverage::test_method -v
```

### Check Coverage for Specific Module
```bash
pytest --cov=bsv.utils --cov-report=term-missing
```

### Generate HTML Coverage Report
```bash
pytest --cov=bsv --cov-report=html
# Then open htmlcov/index.html
```

### Run with More Verbose Output
```bash
pytest -vv
```

### Run and Stop on First Failure
```bash
pytest -x
```

### Run Tests Matching Pattern
```bash
pytest -k "test_varint"
```

### Show Print Statements
```bash
pytest -s
```

### Run in Parallel (if pytest-xdist installed)
```bash
pytest -n auto
```

## 🎯 Testing Patterns Cheat Sheet

### 1. Testing Exceptions
```python
# Basic exception
with pytest.raises(ValueError):
    function_call()

# Exception with message pattern
with pytest.raises(ValueError, match="specific message"):
    function_call()

# Check exception details
with pytest.raises(ValueError) as exc_info:
    function_call()
assert "expected text" in str(exc_info.value)
```

### 2. Parametrized Tests
```python
@pytest.mark.parametrize("input,expected", [
    (1, "one"),
    (2, "two"),
])
def test_function(input, expected):
    assert function(input) == expected

# Multiple parameters
@pytest.mark.parametrize("a,b,result", [
    (1, 2, 3),
    (0, 0, 0),
])
def test_add(a, b, result):
    assert add(a, b) == result
```

### 3. Fixtures
```python
@pytest.fixture
def sample_data():
    return {"key": "value"}

def test_with_fixture(sample_data):
    assert sample_data["key"] == "value"
```

### 4. Mocking
```python
# Mock function
@patch('module.function')
def test_mock_function(mock_func):
    mock_func.return_value = "mocked"
    result = call_that_uses_function()
    assert result == expected

# Mock attribute
@patch('module.Class.attribute', new_value=10)
def test_mock_attribute():
    assert module.Class.attribute == 10

# Mock side effect (exception)
mock.side_effect = ValueError("error")

# Mock side effect (sequence)
mock.side_effect = [1, 2, 3]
```

### 5. Testing Async Functions
```python
import pytest

@pytest.mark.asyncio
async def test_async_function():
    result = await async_function()
    assert result == expected
```

## 🚦 Coverage Goals by File Type

| File Type | Min Coverage | Stretch Goal |
|-----------|--------------|--------------|
| Core Utils | 85% | 95% |
| Serializers | 80% | 90% |
| Clients | 70% | 80% |
| Complex Logic | 75% | 85% |
| Simple Models | 90% | 100% |

## ⚡ Pro Tips

1. **Start Simple:** Begin with happy path, then add edge cases
2. **One Thing:** Test one behavior per test
3. **Clear Names:** Test names should describe what's being tested
4. **Mock External:** Mock network calls, file I/O, databases
5. **Fast Tests:** Keep tests under 100ms when possible
6. **Deterministic:** No random values or time dependencies
7. **Independent:** Tests shouldn't depend on each other
8. **Readable:** Tests are documentation - make them clear

## 🐛 Common Pitfalls

- ❌ Over-mocking (mocking everything makes tests brittle)
- ❌ Testing implementation details (test behavior, not internals)
- ❌ Slow tests (use mocks for I/O operations)
- ❌ Flaky tests (avoid timing-dependent tests)
- ❌ Unclear test names (be explicit about what's tested)
- ❌ Multiple assertions testing different things
- ❌ Tests that don't test anything meaningful

## 📚 Next Steps

1. Pick a file from Priority list above
2. Create test file using template
3. Write tests following patterns
4. Run tests: `pytest <test_file> -v`
5. Check coverage: `pytest --cov=<module> --cov-report=term-missing`
6. Iterate until target coverage reached
7. Submit PR

## 📖 Full Documentation

- **Strategic Plan:** `COVERAGE_IMPROVEMENT_PLAN.md`
- **Tactical Plan:** `COVERAGE_TACTICAL_PLAN.md`
- **Summary:** `COVERAGE_SUMMARY.md`
- **Coverage Report:** `htmlcov/index.html`

---

*Quick Reference v1.0 - November 18, 2024*

