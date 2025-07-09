# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet sanitizer utilities"""

from __future__ import annotations

from logging import getLogger
from os import environ
from os.path import exists
from pathlib import Path
from re import compile as re_compile
from shutil import copyfileobj
from subprocess import CalledProcessError, TimeoutExpired, run
from sys import executable
from tempfile import TemporaryFile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Generator, Sequence

# included from:
# https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/asan/scripts/
ASAN_SYMBOLIZE = str(Path(__file__).parent / "asan_symbolize.py")
LOG = getLogger(__name__)

__author__ = "Tyson Smith"


class SanitizerOptions:
    """Used to parse, load and manage sanitizer options."""

    re_delim = re_compile(r":(?![\\|/])")

    __slots__ = ("_options",)

    def __init__(self, options: str | None = None) -> None:
        """
        Args:
            options: Sanitizer options string to load.
        """
        self._options: dict[str, str] = {}
        if options is not None:
            self.load_options(options)

    def __bool__(self) -> bool:
        return any(self._options)

    def __contains__(self, item: str) -> bool:
        return item in self._options

    def __iter__(self) -> Generator[Sequence[str]]:
        yield from self._options.items()

    def __len__(self) -> int:
        return len(self._options)

    def __str__(self) -> str:
        return ":".join(f"{k}={v}" for k, v in self)

    def add(self, flag: str, value: str, overwrite: bool = False) -> None:
        """Add sanitizer option flag.

        Args:
            flag: Sanitizer option flag to set.
            value: Value to use. Values containing ':' or ' ' must be quoted.
            overwrite: Overwrite existing value.

        Returns:
            None
        """
        if not flag:
            raise ValueError("Flag name cannot be empty")
        if (":" in value or " " in value) and not self.is_quoted(value):
            raise ValueError(f"'{value}' ({flag}) must be quoted")
        if flag not in self._options or overwrite:
            self._options[flag] = value

    def check_path(self, flag: str) -> bool:
        """Check path exists on disk.
        Only indicate failure if flag exists and path does not.

        Args:
            flag: Flags to set.

        Returns:
            False if the flag exists and the path does not otherwise True.
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
        return self._options.get(flag)

    @staticmethod
    def is_quoted(token: str) -> bool:
        """Check if token is quoted.

        Args:
            token: Value to check.

        Returns:
            True if token is quoted otherwise False.
        """
        return len(token) > 1 and token[0] == token[-1] and token[0] in ('"', "'")

    def load_options(self, options: str | None) -> None:
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
                except TypeError:  # noqa: PERF203
                    LOG.warning("Malformed sanitizer option %r", option)

    def pop(self, flag: str) -> str | None:
        """Pop sanitizer flag.

        Args:
            flag: Flags to retrieve.

        Returns:
            Value of given flag or None
        """
        return self._options.pop(flag, None)


def symbolize_log(
    log: Path,
    llvm_symbolizer: str | None = None,
    timeout: int = 120,
) -> bool:
    """Symbolize a sanitizer log.

    Args:
        log: Log file to symbolize.
        llvm_symbolizer: Binary to use. System installed binary is used by default.
        timeout: Time limit for symbolizer process.

    Returns:
        True if symbolizer process ran successfully otherwise False.
    """
    assert timeout > 0
    env = dict(environ)
    # don't override
    if "LLVM_SYMBOLIZER_PATH" not in environ and llvm_symbolizer is not None:
        env["LLVM_SYMBOLIZER_PATH"] = llvm_symbolizer
    with TemporaryFile("wb+") as tmp_fp:
        with log.open("rb") as log_fp:
            try:
                run(
                    (executable, ASAN_SYMBOLIZE, "-d"),
                    env=env,
                    stdin=log_fp,
                    stdout=tmp_fp,
                    check=True,
                    timeout=timeout,
                )
            except CalledProcessError:
                return False
            except TimeoutExpired:
                # this should NEVER happen
                LOG.warning("Symbolizer process did not complete in %ds", timeout)
                return False
        tmp_fp.seek(0)
        with log.open("wb") as log_fp:
            copyfileobj(tmp_fp, log_fp)
    return True
