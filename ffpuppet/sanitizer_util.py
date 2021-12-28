# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet sanitizer utilities"""
from logging import getLogger
from os.path import exists
from re import compile as re_compile

LOG = getLogger(__name__)

__author__ = "Tyson Smith"
__all__ = ("SanitizerOptions",)


class SanitizerOptions:  # pylint: disable=missing-docstring
    re_delim = re_compile(r":(?![\\|/])")

    __slots__ = ("_options",)

    def __init__(self, options=None):
        self._options = dict()
        if options is not None:
            assert isinstance(options, str)
            self.load_options(options)

    def __contains__(self, item):
        return item in self._options

    def add(self, flag, value, overwrite=False):
        """Add sanitizer flag.

        Args:
            flag (str): Flags to set.
            value (str): Value to use.
            overwrite (bool): Overwrite existing value.

        Returns:
            None
        """
        assert flag and isinstance(flag, str)
        assert isinstance(value, str)
        if ":" in value or " " in value:
            assert self.is_quoted(value), "%s (%s) must be quoted" % (value, flag)
        if flag not in self._options or overwrite:
            self._options[flag] = value

    def check_path(self, flag):
        """Check path exists on disk.
        Only indicate failure if flag exists and path does not.

        Args:
            flag (str): Flags to set.

        Returns:
            bool: False if the flag exists and the path does not otherwise False
        """
        if flag in self._options:
            value = self._options[flag]
            if self.is_quoted(value):
                value = value[1:-1]
            return exists(value)
        return True

    def get(self, flag):
        """Get sanitizer flag.

        Args:
            flag (str): Flags to retrieve.

        Returns:
            str: Value of given flag or None
        """
        return self._options.get(flag, None)

    @staticmethod
    def is_quoted(token):
        """Check if token is quoted.

        Args:
            token (str): Value to check.

        Returns:
            bool: True if token is quoted otherwise False.
        """
        if len(token) > 1:
            if token.startswith("'") and token.endswith("'"):
                return True
            if token.startswith('"') and token.endswith('"'):
                return True
        return False

    def load_options(self, options):
        """Load flags from *SAN_OPTIONS in env.

        Args:
            options (str): Colon separated list of `flag=value` pairs.

        Returns:
            None
        """
        self._options.clear()
        if options:
            for option in self.re_delim.split(options):
                try:
                    self.add(*option.split("=", maxsplit=1))
                except TypeError:
                    LOG.warning("Malformed option %r", option)

    @property
    def options(self):
        """Join all flag and value pairs for use with *SAN_OPTIONS.

        Args:
            None

        Returns:
            str: Colon separated list of options.
        """
        return ":".join("=".join(kv) for kv in self._options.items())

    def pop(self, flag):
        """Pop sanitizer flag.

        Args:
            flag (str): Flags to retrieve.

        Returns:
            str: Value of given flag or None
        """
        return self._options.pop(flag, None)
