#!/usr/bin/env python3
"""
Setup script for Mitsubishi PLC Security Audit Tool.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Read version
version = "1.0.0"

setup(
    name="mitsubishicheck",
    version=version,
    author="Security Research Team",
    author_email="security@example.com",
    description="Security audit tool for Mitsubishi PLCs using MELSEC protocol",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/mitsubishicheck",
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    keywords=[
        "plc",
        "mitsubishi",
        "melsec",
        "security",
        "audit",
        "ics",
        "scada",
        "industrial",
    ],
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.8",
    install_requires=[
        # No external dependencies - uses only stdlib
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
            "ruff>=0.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "mitsubishicheck=mitsubishicheck.cli:main",
        ],
    },
    data_files=[
        ("share/man/man1", ["man/mitsubishicheck.1"]),
    ],
    include_package_data=True,
    zip_safe=False,
)
