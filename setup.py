#!/usr/bin/env python
import sys
from setuptools import setup

if __name__ == '__main__':
    plat = {'linux2': 'linux',
            'win32': 'windows',
            'darwin': 'mac'}[sys.platform]
    with open('requirements-%s.txt' % plat) as f:
        requires = f.read().strip().splitlines()
    setup(name = "ffpuppet",
          version = "0.1",
          install_requires=requires,
          packages = ['ffpuppet'],
          package_dir = {'ffpuppet': ''})

