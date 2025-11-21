import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# Path to project root (contains py-sdk package)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
PYSRC_DIR = PROJECT_ROOT / "py-sdk"
PYTHON_EXECUTABLE = PROJECT_ROOT / "venv" / "bin" / "python3"

@pytest.mark.skipif(not PYTHON_EXECUTABLE.exists(), reason="Project venv not found")
def test_build_and_import_package():
    """Builds the py-sdk package into an isolated directory and ensures it can be imported."""
    # Build / install into a temporary target directory (no deps)
    with tempfile.TemporaryDirectory() as site_dir:
        cmd = [
            str(PYTHON_EXECUTABLE),
            "-m",
            "pip",
            "install",
            "-q",
            "--no-deps",
            "--target",
            site_dir,
            str(PYSRC_DIR),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0, f"pip install failed: {result.stderr}"

        # Prepend site_dir to sys.path to import the freshly installed package
        sys.path.insert(0, site_dir)
        try:
            import bsv  # noqa: F401  # pylint: disable=import-error
            from bsv.utils import to_hex  # type: ignore

            # Simple runtime assertion
            assert to_hex(b"abc") == "616263"
        finally:
            # Clean sys.path regardless of assertion outcomes
            if site_dir in sys.path:
                sys.path.remove(site_dir)

