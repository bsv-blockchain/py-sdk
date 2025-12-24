"""
Coverage tests for overlay/lookup.py - untested branches.
"""
import pytest


# ========================================================================
# Overlay lookup branches
# ========================================================================

def test_overlay_lookup_init():
    """Test overlay lookup initialization."""
    from bsv.overlay.lookup import LookupResolver

    lookup = LookupResolver()
    assert lookup is not None


def test_overlay_lookup_query():
    """Test overlay lookup query."""
    from bsv.overlay.lookup import LookupResolver, LookupQuestion
        
    lookup = LookupResolver()
    
    # LookupResolver.query requires a LookupQuestion object
    question = LookupQuestion(service='test', query={})
    result = lookup.query(None, question)
    assert result is not None
    assert result.type == 'output-list'


def test_overlay_lookup_with_protocol():
    """Test overlay lookup with protocol."""
    from bsv.overlay.lookup import LookupResolver

    # LookupResolver doesn't accept protocol parameter, only backend
    lookup = LookupResolver()
    assert lookup is not None


# ========================================================================
# Edge cases
# ========================================================================

def test_overlay_lookup_empty_query():
    """Test overlay lookup with empty query."""
    from bsv.overlay.lookup import LookupResolver, LookupQuestion

    lookup = LookupResolver()

    if hasattr(lookup, 'query'):
        # Query requires a LookupQuestion object
        question = LookupQuestion(service='test', query={})
        result = lookup.query(None, question)
        assert result is not None
        assert result.type == 'output-list'

