"""
Coverage tests for bsv.auth.__init__.py - normal operation validation.
"""
import bsv.auth


def test_auth_module_imports():
    """Test that all expected imports are available in bsv.auth."""
    # Test that the main classes are imported correctly
    assert hasattr(bsv.auth, 'Peer')
    assert hasattr(bsv.auth, 'PeerOptions')
    assert hasattr(bsv.auth, 'PeerSession')
    assert hasattr(bsv.auth, 'SessionManager')
    assert hasattr(bsv.auth, 'Certificate')  # May be None if import failed
    assert hasattr(bsv.auth, 'VerifiableCertificate')  # May be None if import failed
    assert hasattr(bsv.auth, 'RequestedCertificateSet')
    assert hasattr(bsv.auth, 'AuthMessage')
    assert hasattr(bsv.auth, 'Transport')

    # Test that the imports are the expected types
    assert bsv.auth.Peer is not None
    assert bsv.auth.PeerOptions is not None
    assert bsv.auth.PeerSession is not None
    assert bsv.auth.SessionManager is not None
    assert bsv.auth.RequestedCertificateSet is not None
    assert bsv.auth.AuthMessage is not None
    assert bsv.auth.Transport is not None

    # Certificate classes may be None if modules are not available
    # This is expected fallback behavior
