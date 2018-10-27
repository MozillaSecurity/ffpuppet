# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


class LaunchError(Exception):
    """
    Raised when the browser process does not appear to be in a functional state during launch
    """
    pass


class BrowserTerminatedError(LaunchError):
    """
    Raised when the browser process goes away during launch
    """
    pass


class BrowserTimeoutError(LaunchError):
    """
    Raised when the browser process appears to hang during launch
    """
    pass


class TerminateError(Exception):
    """
    Raised when attempts to terminate the browser fail
    """
    pass
