# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet checks module"""

from __future__ import annotations

from abc import ABC, abstractmethod
from os import SEEK_SET, stat
from platform import system
from typing import IO, TYPE_CHECKING, Callable

from psutil import AccessDenied, NoSuchProcess, Process

if TYPE_CHECKING:
    from collections.abc import Iterable
    from re import Pattern

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class _LogContentsCheckState:
    __slots__ = ("buffer", "fname", "offset")

    def __init__(self, fname: str) -> None:
        self.fname: str = fname
        self.buffer: bytes = b""
        self.offset: int = 0


class Check(ABC):
    """
    Check base class
    """

    name: str

    __slots__ = ("message", "name")

    def __init__(self) -> None:
        self.message: str | None = None

    @abstractmethod
    def check(self) -> bool:
        """
        Implement a check that returns True when the abort conditions are met.
        """

    def dump_log(self, dst_fp: IO[bytes]) -> None:
        """Write log contents to file.

        Args:
            dst_fp: Open file object to write logs to.

        Returns:
            None
        """
        if self.message is not None:
            dst_fp.write(self.message.encode(errors="ignore"))


class CheckLogContents(Check):
    """
    CheckLogContents will search through the browser logs for a token.
    """

    buf_limit = 1024  # 1KB
    chunk_size = 0x20000  # 128KB
    name = "log_contents"

    __slots__ = ("logs", "tokens")

    def __init__(
        self, log_files: Iterable[str], search_tokens: Iterable[Pattern[str]]
    ) -> None:
        assert log_files, "log_files is empty"
        assert search_tokens, "search_tokens is empty"
        super().__init__()
        self.logs: list[_LogContentsCheckState] = []
        for log_file in log_files:
            self.logs.append(_LogContentsCheckState(log_file))
        self.tokens = search_tokens

    def check(self) -> bool:
        """Collect log contents for tokens.

        Args:
            None

        Returns:
            True if a token is located otherwise False.
        """
        for log in self.logs:
            try:
                # check if file has new data
                if stat(log.fname).st_size <= log.offset:
                    continue
                with open(log.fname, "rb") as scan_fp:
                    # only collect new data
                    scan_fp.seek(log.offset, SEEK_SET)
                    # read and prepend chunk of previously read data
                    data = b"".join((log.buffer, scan_fp.read(self.chunk_size)))
                    log.offset = scan_fp.tell()
            except OSError:
                # log does not exist
                continue
            for token in self.tokens:
                match = token.search(data.decode(errors="replace"))
                if match:
                    self.message = f"TOKEN_LOCATED: {match.group()}\n"
                    return True
            log.buffer = data[-1 * self.buf_limit :]
        return False


class CheckLogSize(Check):
    """
    CheckLogSize will check the total file size of the browser logs.
    """

    name = "log_size"

    __slots__ = ("limit", "stderr_file", "stdout_file")

    def __init__(self, limit: int, stderr_file: str, stdout_file: str) -> None:
        super().__init__()
        self.limit = limit
        self.stderr_file = stderr_file
        self.stdout_file = stdout_file

    def check(self) -> bool:
        """Collect log disk usage info and compare with limit.

        Args:
            None

        Returns:
            True if the total usage is greater than or equal to
            self.limit otherwise False.
        """
        err_size = stat(self.stderr_file).st_size
        out_size = stat(self.stdout_file).st_size
        total_size = err_size + out_size
        if total_size > self.limit:
            self.message = (
                f"LOG_SIZE_LIMIT_EXCEEDED: {total_size:,}\n"
                f"Limit: {self.limit:,} ({self.limit / 1_048_576}MB)\n"
                f"stderr log: {err_size:,} ({err_size / 1_048_576}MB)\n"
                f"stdout log: {out_size:,} ({out_size / 1_048_576}MB)\n"
            )
        return self.message is not None


class CheckMemoryUsage(Check):
    """
    CheckMemoryUsage is used to check the amount of memory used by the browser
    process and its descendants against a defined limit.
    """

    name = "memory_usage"

    __slots__ = ("_get_procs", "_is_linux", "limit", "pid")

    def __init__(
        self, pid: int, limit: int, get_procs_cb: Callable[[], list[Process]]
    ) -> None:
        super().__init__()
        self._get_procs = get_procs_cb
        self._is_linux = system() == "Linux"
        self.limit = limit
        self.pid = pid

    def check(self) -> bool:
        """Use psutil to collect memory usage info and compare with limit.

        Args:
            None

        Returns:
            True if the total usage is greater than or equal to
            self.limit otherwise False.
        """
        largest_shared = 0
        proc_info: list[tuple[int, int]] = []
        total_usage = 0
        for proc in self._get_procs():
            try:
                mem_info = proc.memory_info()
            except (AccessDenied, NoSuchProcess):  # pragma: no cover
                continue
            cur_usage: int = mem_info.rss
            if self._is_linux:
                # on Linux use "rss - shared" as the current usage
                cur_usage -= mem_info.shared
                # track largest shared amount to be appended to the grand total
                # this is not perfect but it is close enough for this
                largest_shared = max(largest_shared, mem_info.shared)
            total_usage += cur_usage
            proc_info.append((proc.pid, cur_usage))
        total_usage += largest_shared
        if total_usage >= self.limit:
            msg = [
                f"MEMORY_LIMIT_EXCEEDED: {total_usage:,}\n",
                f"Limit: {self.limit:,} ({self.limit / 1_048_576}MB)\n",
                f"Parent PID: {self.pid}\n",
            ]
            for pid, usage in proc_info:
                msg.append(f"-> PID {pid: 6}: {usage: 14,}\n")
            self.message = "".join(msg)
        return self.message is not None
