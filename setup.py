#!/usr/bin/env python
from setuptools import setup

if __name__ == '__main__':
    with open('requirements.txt') as f:
        requires = f.read().strip().splitlines()
    setup(name="ffpuppet",
          version="0.1",
          install_requires=requires,
          packages=['ffpuppet'],
          package_dir={'ffpuppet': ''})

