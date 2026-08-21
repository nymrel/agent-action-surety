#!/usr/bin/env python3
"""Setup script for agent-action-surety."""
from setuptools import setup, find_packages

setup(
    name="agent-action-surety",
    version="1.0.0",
    description="Zero-dependency execution firewall, path sandbox, command interceptor, and cryptographic audit ledger for AI coding agents.",
    long_description=open("README.md", encoding="utf-8").read() if os_exists := __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="Nymrel",
    author_email="contact@nymrel.com",
    url="https://github.com/nymrel/agent-action-surety",
    package_dir={"": "python"},
    packages=find_packages(where="python"),
    python_requires=">=3.9",
    install_requires=[],
    entry_points={
        "console_scripts": [
            "agent-surety=agent_action_surety.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)
