#!/usr/bin/env python
# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""setuptools install script"""
from os.path import dirname, join as pathjoin
from setuptools import setup

if __name__ == "__main__":
    with open(pathjoin(dirname(__file__), "README.md"), "r") as infp:
        README = infp.read()
    setup(
        author="Tyson Smith",
        classifiers=[
            'Intended Audience :: Developers',
            'Topic :: Software Development :: Testing',
            'License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)',
            'Programming Language :: Python :: 3',
            'Programming Language :: Python :: 3.5',
            'Programming Language :: Python :: 3.6',
            'Programming Language :: Python :: 3.7',
            'Programming Language :: Python :: 3.8'
        ],
        description="A python module that aids in the automation of Firefox at the process level",
        entry_points={
            "console_scripts": ["ffpuppet = ffpuppet.main:main"]
        },
        extra_requires=[
            "pytest",
            "pytest-cov",
            "pytest-mock"
            "pytest-pylint"
        ],
        install_requires=[
            "psutil >= 4.4.0",
            "xvfbwrapper >= 0.2.9; sys_platform == 'linux' or sys_platform == 'linux2'"
        ],
        keywords="automation firefox fuzz fuzzing security test testing",
        license="MPL 2.0",
        long_description=README,
        long_description_content_type="text/markdown",
        maintainer="Mozilla Fuzzing Team",
        maintainer_email="fuzzing@mozilla.com",
        name="ffpuppet",
        packages=["ffpuppet"],
        package_data={"": ["cmds.gdb"]},
        url="https://github.com/MozillaSecurity/ffpuppet",
        version="0.7.4")
