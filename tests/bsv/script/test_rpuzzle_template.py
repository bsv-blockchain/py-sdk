"""
Tests for RPuzzle script template implementation.

Translated from TS SDK RPuzzle template tests.
"""

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from bsv.hash import hash160, hash256, sha1, sha256
from bsv.keys import PrivateKey
from bsv.script.type import RPuzzle


class TestRPuzzleTemplate:
    """Test RPuzzle script template matching TS SDK tests."""

    def test_should_create_raw_rpuzzle_locking_script(self):
        """Test that lock creates raw RPuzzle locking script."""
        r_value = b"\x01" * 32  # 32-byte R value

        rpuzzle = RPuzzle("raw")
        locking_script = rpuzzle.lock(r_value)

        assert locking_script is not None
        assert len(locking_script.to_bytes()) > 0

    def test_should_create_sha256_rpuzzle_locking_script(self):
        """Test that lock creates SHA256 RPuzzle locking script."""
        r_value = b"\x01" * 32
        r_hash = sha256(r_value)

        rpuzzle = RPuzzle("SHA256")
        locking_script = rpuzzle.lock(r_hash)

        assert locking_script is not None
        assert len(locking_script.to_bytes()) > 0

    def test_should_create_sha1_rpuzzle_locking_script(self):
        """Test that lock creates SHA1 RPuzzle locking script."""
        r_value = b"\x01" * 32
        r_hash = sha1(r_value)

        rpuzzle = RPuzzle("SHA1")
        locking_script = rpuzzle.lock(r_hash)

        assert locking_script is not None
        assert len(locking_script.to_bytes()) > 0

    def test_should_create_hash160_rpuzzle_locking_script(self):
        """Test that lock creates HASH160 RPuzzle locking script."""
        r_value = b"\x01" * 32
        r_hash = hash160(r_value)

        rpuzzle = RPuzzle("HASH160")
        locking_script = rpuzzle.lock(r_hash)

        assert locking_script is not None
        assert len(locking_script.to_bytes()) > 0

    def test_should_create_unlocking_script_template(self):
        """Test that unlock creates unlocking script template."""
        from bsv.curve import curve

        k_value = 12345  # K value for R-puzzle
        private_key = PrivateKey()
        r_value = b"\x01" * 32

        rpuzzle = RPuzzle("raw")
        _ = rpuzzle.lock(r_value)
        unlocker = rpuzzle.unlock(k_value, private_key)

        assert unlocker is not None
        assert hasattr(unlocker, "sign")
        assert hasattr(unlocker, "estimated_unlocking_byte_length")

    def test_should_estimate_unlocking_script_length(self):
        """Test that unlocker estimates unlocking script length."""
        from bsv.curve import curve

        k_value = 12345
        private_key = PrivateKey()

        rpuzzle = RPuzzle("raw")
        unlocker = rpuzzle.unlock(k_value, private_key)

        length = unlocker.estimated_unlocking_byte_length()
        assert length > 0
        # RPuzzle unlocking script should be ~108 bytes
        assert length >= 100

    def test_omitted_unlock_key_is_fresh_and_import_creates_none(self):
        """Two unlock() calls without a key do not share one, and import builds none."""
        repo_root = Path(__file__).resolve().parents[3]
        probe = textwrap.dedent("""\
            import sys
            import types
            from pathlib import Path

            root = Path(sys.argv[1]).resolve()
            package = types.ModuleType("bsv")
            package.__path__ = [str(root / "bsv")]
            package.__package__ = "bsv"
            sys.modules["bsv"] = package

            import bsv.keys as keys

            created = []
            original_init = keys.PrivateKey.__init__

            def counting_init(self, *args, **kwargs):
                created.append(1)
                return original_init(self, *args, **kwargs)

            keys.PrivateKey.__init__ = counting_init

            import bsv.script.type as type_mod

            default = type_mod.RPuzzle.unlock.__defaults__[0]
            if default is not None:
                raise SystemExit(
                    f"import stored a {type(default).__name__} on RPuzzle.unlock"
                )
            if created:
                raise SystemExit(
                    f"importing bsv.script.type constructed PrivateKey {len(created)} time(s)"
                )
            print("import-ok")
            """)
        completed = subprocess.run(
            [sys.executable, "-c", probe, str(repo_root)],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == 0, f"{completed.stdout}\n{completed.stderr}"
        assert "import-ok" in completed.stdout

        assert RPuzzle.unlock.__defaults__[0] is None

        first = _signing_private_key(RPuzzle().unlock(1))
        second = _signing_private_key(RPuzzle().unlock(1))
        assert isinstance(first, PrivateKey)
        assert isinstance(second, PrivateKey)
        assert first is not second
        assert first.serialize() != second.serialize()

        explicit = PrivateKey()
        assert _signing_private_key(RPuzzle().unlock(1, explicit)) is explicit


def _signing_private_key(template):
    """Return the PrivateKey closed over by an unlocking template's sign function."""
    sign = template.__dict__["sign"]
    closed = {name: cell.cell_contents for name, cell in zip(sign.__code__.co_freevars, sign.__closure__, strict=True)}
    return closed["private_key"]
