"""FFPuppet module"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from .core import Debugger, FFPuppet, Reason
from .exceptions import (
    BrowserExecutionError,
    BrowserTerminatedError,
    BrowserTimeoutError,
    LaunchError,
)
from .sanitizer_util import SanitizerOptions

__all__ = (
    "Debugger",
    "FFPuppet",
    "Reason",
    "BrowserExecutionError",
    "BrowserTimeoutError",
    "BrowserTerminatedError",
    "LaunchError",
    "SanitizerOptions",
)
__author__ = "Tyson Smith"
