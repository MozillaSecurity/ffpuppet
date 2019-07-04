#!/usr/bin/env python
# coding=utf-8
"""setuptools install script"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from setuptools import setup

if __name__ == "__main__":
    setup(
        author="Tyson Smith",
        description="A python module that aids in the automation of Firefox at the process level",
        entry_points={
            "console_scripts": ["ffpuppet = ffpuppet.main:main"]
        },
        install_requires=[
            "psutil >= 4.4.0",
            "xvfbwrapper >= 0.2.9; sys_platform == 'linux' or sys_platform == 'linux2'"
        ],
        keywords="fuzz fuzzing security test testing",
        license="MPL 2.0",
        maintainer="Mozilla Fuzzing Team",
        maintainer_email="fuzzing@mozilla.com",
        name="ffpuppet",
        packages=["ffpuppet"],
        package_data={"": ["cmds.gdb"]},
        url="https://github.com/MozillaSecurity/ffpuppet",
        version="0.6.5")
