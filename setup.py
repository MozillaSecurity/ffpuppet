#!/usr/bin/env python
from setuptools import setup

if __name__ == '__main__':
    with open('requirements.txt') as f:
        requires = f.read().strip().splitlines()
    setup(name="ffpuppet",
          version="0.5.7",
          install_requires=requires,
          url='https://github.com/MozillaSecurity/ffpuppet',
          license='MPL 2.0',
          author='Tyson Smith',
          package_data={'': ['cmds.gdb']},
          description='A python module that aids in the automation of Firefox at the process level',
          entry_points={"console_scripts": ["ffpuppet = ffpuppet.main:main"]},
          packages=['ffpuppet', 'ffpuppet.workers'])
