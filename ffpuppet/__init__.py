# coding=utf-8
"""FFPuppet module"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from .core import FFPuppet
from .exceptions import BrowserTimeoutError, BrowserTerminatedError, LaunchError

__all__ = ("FFPuppet", "BrowserTimeoutError", "BrowserTerminatedError", "LaunchError")
__author__ = "Tyson Smith"
