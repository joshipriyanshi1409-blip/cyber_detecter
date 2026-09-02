#!/usr/bin/env python3
"""
Setup script for cyber_detecter.

cyber_detecter is a passive/read-only AI-based network threat detection
prototype (DDoS/flooding, port scanning, DGA/DNS-tunnelling-style domain
analysis, with encrypted-traffic-metadata and data-exfiltration analysis
as ongoing work). It performs no active probing, no packet injection, no
blocking, and no TLS/QUIC decryption -- see docs/THREAT-MODELS.md.

This file makes the project pip-installable (`pip install -e .`) so that
`import src...` works the same way whether the code is run from a
checkout (scripts already do `sys.path.insert(0, project_root)`) or from
an installed package. It intentionally does NOT vendor exact dependency
pins -- see requirements.txt for the abstract version ranges and
requirements-lock.txt for a best-effort pinned snapshot (read the header
of that file: it was NOT generated with `pip freeze` in a fully
provisioned environment, and should be regenerated on one before being
trusted for reproducible deploys).
"""

from pathlib import Path

from setuptools import find_packages, setup

ROOT = Path(__file__).parent


def read_requirements(filename: str):
    """Parse a requirements.txt-style file into a list of dependency
    specifiers, skipping comments, blank lines, and options."""
    path = ROOT / filename
    if not path.exists():
        return []
    requirements = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        requirements.append(line)
    return requirements


def read_long_description():
    readme = ROOT / "README.md"
    if readme.exists():
        return readme.read_text()
    return (
        "cyber_detecter: a passive AI-based network threat detection "
        "prototype. See docs/ARCHITECTURE.md and docs/THREAT-MODELS.md."
    )


setup(
    name="cyber_detecter",
    version="0.1.0",
    description=(
        "Passive/read-only AI-based network threat detection prototype "
        "(DDoS, port scanning, DGA/DNS analysis)."
    ),
    long_description=read_long_description(),
    long_description_content_type="text/markdown",
    author="cyber_detecter contributors",
    license="MIT",
    python_requires=">=3.10",
    packages=find_packages(include=["src", "src.*", "scripts", "scripts.*"]),
    install_requires=read_requirements("requirements.txt"),
    extras_require={
        # Everything needed to run the full test suite, including the
        # scapy/nfstream/pytest-dependent tests that this sandbox could
        # not import -- see docs/AUDIT_PROGRESS.md and
        # docs/NEXT_AGENT_PROMPT.md for the "no network access" caveat
        # that applies throughout this repo's audit history.
        "dev": ["pytest>=7.4.0", "pytest-cov>=4.1.0"],
    },
    entry_points={
        "console_scripts": [
            "cyber-detecter-pipeline=scripts.run_pipeline:main",
            "cyber-detecter-dashboard=scripts.run_dashboard:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
