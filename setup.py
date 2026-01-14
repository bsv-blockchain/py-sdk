from setuptools import find_packages, setup

with open("bsv/__init__.py") as f:
    for line in f:
        if line.startswith("__version__"):
            version = line.strip().split("=")[1].strip().strip('"').strip("'")
            break

setup(
    version=version,
    packages=find_packages(exclude=("tests",)),
)
