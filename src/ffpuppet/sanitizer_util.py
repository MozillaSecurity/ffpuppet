# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet sanitizer utilities"""

from logging import getLogger
from os.path import exists
from re import compile as re_compile
from typing import Dict, Iterator, Optional, Tuple

LOG = getLogger(__name__)

__author__ = "Tyson Smith"
__all__ = ("SanitizerOptions",)


class SanitizerOptions:  # pylint: disable=missing-docstring
    re_delim = re_compile(r":(?![\\|/])")

    __slots__ = ("_options",)

    def __init__(self, options: Optional[str] = None) -> None:
        self._options: Dict[str, str] = {}
        if options is not None:
            self.load_options(options)

    def __contains__(self, item: str) -> bool:
        return item in self._options

    def __iter__(self) -> Iterator[Tuple[str, str]]:
        yield from self._options.items()

    def __len__(self) -> int:
        return len(self._options)

    def __str__(self) -> str:
        return ":".join("=".join(kv) for kv in self)

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
            assert self.is_quoted(value), f"{value} ({flag}) must be quoted"
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

    def get(self, flag: str) -> Optional[str]:
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
        if len(token) > 1 and token[0] == token[-1] and token[0] in ('"', "'"):
            return True
        return False

    def load_options(self, options: Optional[str]) -> None:
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
                    self.add(*option.split("=", maxsplit=1))  # type: ignore
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
        # TODO: Remove after next release
        return str(self)

    def pop(self, flag: str) -> Optional[str]:
        """Pop sanitizer flag.

        Args:
            flag: Flags to retrieve.

        Returns:
            Value of given flag or None
        """
        return self._options.pop(flag, None)
