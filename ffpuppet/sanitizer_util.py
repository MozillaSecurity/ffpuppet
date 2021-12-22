# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet sanitizer utilities"""

from __future__ import annotations

from logging import getLogger
from os.path import exists
from re import compile as re_compile

LOG = getLogger(__name__)

__author__ = "Tyson Smith"
__all__ = ("SanitizerOptions",)


class SanitizerOptions:  # pylint: disable=missing-docstring
    re_delim = re_compile(r":(?![\\|/])")

    __slots__ = ("_options",)

    def __init__(self) -> None:
        self._options: dict[str, str] = dict()

    def __contains__(self, item: str) -> bool:
        return item in self._options

    def add(self, flag: str, value: str, overwrite: bool = False) -> None:
        """Add sanitizer flag.

        Args:
            flag: Flags to set.
            value: Value to use.
            overwrite: Overwrite existing value.

        Returns:
            None
        """
        assert flag and isinstance(flag, str)
        assert isinstance(value, str)
        if ":" in value or " " in value:
            assert self.is_quoted(value), "%s (%s) must be quoted" % (value, flag)
        if flag not in self._options or overwrite:
            self._options[flag] = value

    def check_path(self, flag: str) -> bool:
        """Check path exists on disk.
        Only indicate failure if flag exists and path does not.

        Args:
            flag: Flags to set.

        Returns:
            False if the flag exists and the path does not otherwise False
        """
        if flag in self._options:
            value = self._options[flag]
            if self.is_quoted(value):
                value = value[1:-1]
            return exists(value)
        return True

    def get(self, flag: str) -> str | None:
        """Get sanitizer flag.

        Args:
            flag: Flags to retrieve.

        Returns:
            Value of given flag or None
        """
        return self._options.get(flag, None)

    @staticmethod
    def is_quoted(token: str) -> bool:
        """Check if token is quoted.

        Args:
            token: Value to check.

        Returns:
            True if token is quoted otherwise False.
        """
        if len(token) > 1:
            if token.startswith("'") and token.endswith("'"):
                return True
            if token.startswith('"') and token.endswith('"'):
                return True
        return False

    def load_options(self, options: str) -> None:
        """Load flags from *SAN_OPTIONS in env.

        Args:
            options: Colon separated list of `flag=value` pairs.

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
    def options(self) -> str:
        """Join all flag and value pairs for use with *SAN_OPTIONS.

        Args:
            None

        Returns:
            Colon separated list of options.
        """
        return ":".join("=".join(kv) for kv in self._options.items())

    def pop(self, flag: str) -> str | None:
        """Pop sanitizer flag.

        Args:
            flag: Flags to retrieve.

        Returns:
            Value of given flag or None
        """
        return self._options.pop(flag, None)
