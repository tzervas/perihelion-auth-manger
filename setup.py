#!/usr/bin/env python3
"""
Setup script for Git Credential Manager
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="git-credential-manager",
    version="1.0.0",
    author="Tyler Zervas",
    author_email="tz-dev@vectorweight.com",
    description="Secure-by-design multi-platform Git authentication tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tzervas/git-credential-manager",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Version Control :: Git",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
    ],
    python_requires=">=3.8",
    install_requires=[
        # No external dependencies - uses standard library only
    ],
    entry_points={
        "console_scripts": [
            "git-cred-manager=git_credential_manager:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
