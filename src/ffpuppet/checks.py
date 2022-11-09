# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet checks module"""

from abc import ABC, abstractmethod
from os import SEEK_SET, stat
from typing import IO, Iterable, List, Optional, Pattern

from psutil import AccessDenied, NoSuchProcess

from .helpers import get_processes

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

    name: Optional[str] = None

    __slots__ = ("message",)

    def __init__(self) -> None:
        self.message: Optional[str] = None

    @abstractmethod
    def check(self) -> Optional[bool]:
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
        self.logs: List[_LogContentsCheckState] = []
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

    __slots__ = ("limit", "pid")

    def __init__(self, pid: int, limit: int) -> None:
        super().__init__()
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
        proc_info = []
        total_usage = 0
        for proc in get_processes(self.pid):
            try:
                cur_rss = proc.memory_info().rss
                total_usage += cur_rss
                proc_info.append((proc.pid, cur_rss))
            except (AccessDenied, NoSuchProcess):  # pragma: no cover
                pass
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
