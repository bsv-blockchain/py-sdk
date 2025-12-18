import pytest

from bsv.script.interpreter import operations


@pytest.fixture(autouse=True)
def patch_signature_validation(monkeypatch):
    """Provide deterministic verification results for interpreter tests."""

    def deterministic_verify(*args, **kwargs):
        sig_bytes = args[2] if len(args) > 2 else kwargs.get("sig_bytes", b"")
        if not sig_bytes or all(b == 0 for b in sig_bytes):
            return False
        return True

    monkeypatch.setattr(operations, "_verify_signature_with_nullfail", deterministic_verify)

