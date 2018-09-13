#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

requirements = ['cis_crypto', 'jsonschema']

setup(
    name="moz_iam_profile",
    version="0.0.1",
    author="Guillaume Destuynder",
    author_email= "kang@mozilla.com",
    description="Mozilla IAM user profile ('v2') class utility.",
    long_description=long_description,
    url="https://github.com/mozilla-iam/cis",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Mozilla Public License",
        "Operating System :: OS Independent",
    ],
    install_requires=requirements,
    license="Mozilla Public License 2.0",
    include_package_data=True,
    packages=find_packages(include=['moz_iam_profile']),
    setup_requires=requirements,
)
