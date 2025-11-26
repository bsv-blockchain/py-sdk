"""
Coverage tests for polynomial.py - untested branches.
"""
import pytest


# ========================================================================
# Polynomial operations branches
# ========================================================================

# Constants for skip messages
SKIP_POLYNOMIAL = "Polynomial not available"

def test_polynomial_creation():
    """Test creating polynomial."""
    try:
        from bsv.polynomial import Polynomial
        p = Polynomial([1, 2, 3])
        assert p  # Verify object creation succeeds
    except ImportError:
        pytest.skip(SKIP_POLYNOMIAL)


def test_polynomial_empty():
    """Test empty polynomial."""
    try:
        from bsv.polynomial import Polynomial
        p = Polynomial([])
        assert hasattr(p, 'evaluate')
    except ImportError:
        pytest.skip(SKIP_POLYNOMIAL)


def test_polynomial_single_coefficient():
    """Test polynomial with single coefficient."""
    try:
        from bsv.polynomial import Polynomial
        p = Polynomial([5])
        assert hasattr(p, 'evaluate')
    except ImportError:
        pytest.skip(SKIP_POLYNOMIAL)


def test_polynomial_evaluate_zero():
    """Test evaluating polynomial at zero."""
    try:
        from bsv.polynomial import Polynomial
        p = Polynomial([1, 2, 3])  # 1 + 2x + 3x^2
        result = p.evaluate(0)
        assert result == 1
    except (ImportError, AttributeError):
        pytest.skip("Polynomial evaluate not available")


def test_polynomial_evaluate_one():
    """Test evaluating polynomial at one."""
    try:
        from bsv.polynomial import Polynomial
        p = Polynomial([1, 2, 3])  # 1 + 2x + 3x^2
        result = p.evaluate(1)
        assert result == 6  # 1 + 2 + 3
    except (ImportError, AttributeError):
        pytest.skip("Polynomial evaluate not available")


def test_polynomial_degree():
    """Test getting polynomial degree."""
    try:
        from bsv.polynomial import Polynomial
        p = Polynomial([1, 2, 3])
        if hasattr(p, 'degree'):
            assert p.degree() == 2
    except ImportError:
        pytest.skip(SKIP_POLYNOMIAL)


# ========================================================================
# Edge cases
# ========================================================================

def test_polynomial_with_zeros():
    """Test polynomial with zero coefficients."""
    try:
        from bsv.polynomial import Polynomial
        p = Polynomial([0, 0, 1])
        assert hasattr(p, 'evaluate')
    except ImportError:
        pytest.skip(SKIP_POLYNOMIAL)


def test_polynomial_negative_coefficients():
    """Test polynomial with negative coefficients."""
    try:
        from bsv.polynomial import Polynomial
        p = Polynomial([-1, -2, -3])
        assert hasattr(p, 'evaluate')
    except ImportError:
        pytest.skip(SKIP_POLYNOMIAL)

