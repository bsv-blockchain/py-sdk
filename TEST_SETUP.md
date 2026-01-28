# Test Setup Commands for py-sdk

## Setup Virtual Environment

```bash
# Navigate to py-sdk directory
cd /home/sneakyfox/py-lib/py-sdk

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies (includes pytest and test dependencies)
pip install -r requirements.txt

# Install the package in development mode (editable install)
pip install -e .
```

## Run Tests

### Run all tests
```bash
# Make sure venv is activated
source venv/bin/activate

# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov=bsv --cov-report=html
```

### Run specific test files
```bash
# Run script-related tests
pytest tests/test_scripts.py -v

# Run all script tests
pytest tests/test_script*.py -v

# Run a specific test function
pytest tests/test_scripts.py::test_function_name -v
```

### Run tests matching a pattern
```bash
# Run tests matching "op_return" or "OP_RETURN"
pytest -k "op_return" -v

# Run tests matching "chunk"
pytest -k "chunk" -v
```

## Quick Setup Script

You can also create a simple setup script:

```bash
#!/bin/bash
cd /home/sneakyfox/py-lib/py-sdk
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
echo "Setup complete! Activate with: source venv/bin/activate"
```

## Verify Installation

```bash
# Check pytest is installed
pytest --version

# Check bsv package is installed
python -c "import bsv; print(bsv.__version__)"

# Run a quick test
pytest tests/test_scripts.py -v -k "test" --tb=short
```
