# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""FFPuppet module"""

from .core import Debugger, FFPuppet, Reason
from .display import DisplayMode
from .exceptions import (
    BrowserExecutionError,
    BrowserTerminatedError,
    BrowserTimeoutError,
    LaunchError,
)
from .sanitizer_util import SanitizerOptions

__all__ = (
    "BrowserExecutionError",
    "BrowserTerminatedError",
    "BrowserTimeoutError",
    "Debugger",
    "DisplayMode",
    "FFPuppet",
    "LaunchError",
    "Reason",
    "SanitizerOptions",
)
__author__ = "Tyson Smith"
