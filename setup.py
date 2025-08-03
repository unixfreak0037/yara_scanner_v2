#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="yara_scanner_v2",
    version="2.0.1",
    author="John Davison",
    author_email="unixfreak0037@gmail.com",
    description="A Python wrapper library for libyara and a local server for fully utilizing the CPUs of the system to scan with yara.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/unixfreak0037/yara_scanner_v2",
    py_modules=["yara_scanner", "ysc", "yss"],
    install_requires=requirements,
    python_requires=">=3.11",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.12",
    ],
    entry_points={
        "console_scripts": [
            "scan=yara_scanner:main",
            "ysc=ysc:main",
            "yss=yss:main",
        ],
    },
    license="Apache-2.0",
    keywords=["yara", "ace", "ace3"],
)