#!/usr/bin/env python3
"""
Q-TLS Python Binding - Setup Script
====================================

Setup script for installing Q-TLS Python bindings.

Copyright 2025 QSIGN Project
Licensed under the Apache License, Version 2.0
"""

from setuptools import setup, find_packages
import os
import sys

# Read the long description from README
long_description = ""
if os.path.exists('README.md'):
    with open('README.md', 'r', encoding='utf-8') as f:
        long_description = f.read()

# Read version from qtls.py
version = "1.0.0"

setup(
    name='qtls',
    version=version,
    description='Python binding for Q-TLS (Quantum-Resistant Transport Security Layer)',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='QSIGN Project',
    author_email='info@qsign.org',
    url='https://github.com/QSIGN/Q-TLS',
    license='Apache License 2.0',

    # Package configuration
    py_modules=['qtls'],
    python_requires='>=3.7',

    # Dependencies
    install_requires=[
        'cffi>=1.15.0',
        'cryptography>=3.4.0',
    ],

    # Optional dependencies
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-cov>=3.0.0',
            'black>=22.0.0',
            'flake8>=4.0.0',
            'mypy>=0.950',
        ],
        'docs': [
            'sphinx>=4.0.0',
            'sphinx-rtd-theme>=1.0.0',
        ],
    },

    # Classifiers
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Networking',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS :: MacOS X',
    ],

    # Keywords
    keywords=[
        'quantum',
        'post-quantum',
        'cryptography',
        'tls',
        'security',
        'kyber',
        'dilithium',
        'pqc',
        'nist',
    ],

    # Project URLs
    project_urls={
        'Bug Reports': 'https://github.com/QSIGN/Q-TLS/issues',
        'Source': 'https://github.com/QSIGN/Q-TLS',
        'Documentation': 'https://qtls.readthedocs.io/',
    },
)
