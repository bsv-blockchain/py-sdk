import os
import sys

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext

# BSV_NO_NATIVE=1  → skip C extension entirely (pure Python)
# BSV_REQUIRE_NATIVE=1 → fail build if C extension cannot compile (for wheel CI)
USE_C_EXTENSION = os.environ.get("BSV_NO_NATIVE", "0") != "1"
REQUIRE_NATIVE = os.environ.get("BSV_REQUIRE_NATIVE", "0") == "1"

SECP256K1_DIR = os.path.join("_bsv_native", "secp256k1")
SECP256K1_SRC = os.path.join(SECP256K1_DIR, "src")
SECP256K1_INC = os.path.join(SECP256K1_DIR, "include")


class BuildExtFallback(build_ext):
    """build_ext that falls back to pure Python on compilation failure,
    unless BSV_REQUIRE_NATIVE=1 is set (wheel CI must not silently degrade)."""

    def run(self):
        try:
            super().run()
        except Exception:
            if REQUIRE_NATIVE:
                raise
            print("WARNING: C extension build failed — installing pure Python fallback")

    def build_extension(self, ext):
        try:
            super().build_extension(ext)
        except Exception:
            if REQUIRE_NATIVE:
                raise
            print(f"WARNING: Failed to build {ext.name} — skipping")


ext_modules = []

if USE_C_EXTENSION:
    compile_args = [
        "-DSECP256K1_BUILD",
        "-DECMULT_WINDOW_SIZE=15",
        "-DECMULT_GEN_PREC_BITS=4",
        "-DENABLE_MODULE_RECOVERY=1",
        "-DENABLE_MODULE_ECDH=1",
        "-DENABLE_MODULE_SCHNORRSIG=1",
        "-DENABLE_MODULE_EXTRAKEYS=1",
    ]

    if sys.platform == "win32":
        compile_args.extend(["/O2", "/std:c11"])
    else:
        compile_args.extend(
            [
                "-O2",
                "-std=c99",
                "-Wno-unused-function",
                "-Wno-sign-compare",
                "-Wno-implicit-fallthrough",
            ]
        )

    ext_modules.append(
        Extension(
            "_bsv_native",
            sources=[os.path.join("_bsv_native", "bsv_native.c")],
            include_dirs=[
                "_bsv_native",
                SECP256K1_DIR,
                SECP256K1_SRC,
                SECP256K1_INC,
            ],
            extra_compile_args=compile_args,
            language="c",
        )
    )

setup(
    ext_modules=ext_modules,
    cmdclass={"build_ext": BuildExtFallback},
)
