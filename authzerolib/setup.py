#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2018 Mozilla Corporation
# Author: gdestuynder@mozilla.com

import os
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "authzerolib",
        py_modules = ['authzerolib'],
        version = "1.0.0",
        author = "Guillaume Destuynder",
        author_email = "gdestuynder@mozilla.com",
        description = ("A super simple and basic client lib for Auth0"),
        license = "MPL",
        keywords = "auth0 iam library",
        url = "https://github.com/mozilla-iam/auth0-scripts",
        install_requires = [],
        classifiers = [
            "Development Status :: 5 - Production/Stable",
            "Topic :: Software Development :: Libraries :: Python Modules",
            "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        ],
)
