# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet exceptions"""


class LaunchError(Exception):
    """
    Raised when the browser process does not appear to be in a functional state
    during launch.
    """


class BrowserExecutionError(LaunchError):
    """
    Raised when the browser binary cannot be executed.
    """


class BrowserTerminatedError(LaunchError):
    """
    Raised when the browser process goes away during launch.
    """


class BrowserTimeoutError(LaunchError):
    """
    Raised when the browser process appears to hang during launch.
    """


class InvalidPrefs(LaunchError):
    """
    Raised when an invalid prefs.js file is used.
    """


class TerminateError(Exception):
    """
    Raised when attempts to terminate the browser fail.
    """
