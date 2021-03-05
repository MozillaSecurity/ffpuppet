# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet checks module"""

from abc import ABC, abstractmethod
from os import SEEK_SET, stat

from psutil import AccessDenied, NoSuchProcess

from .helpers import get_processes

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class Check(ABC):
    """
    Check base class
    """

    name = None

    __slots__ = ("message",)

    def __init__(self):
        self.message = None

    @abstractmethod
    def check(self):
        """
        Implement a check that returns True when the abort conditions are met.
        """

    def dump_log(self, dst_fp):
        """Write log contents to file.

        Args:
            dst_fp (file): Open file object to write logs to.

        Returns:
            None
        """
        if self.message is not None:
            dst_fp.write(self.message.encode("utf-8", "ignore"))


class CheckLogContents(Check):
    """
    CheckLogContents will search through the browser logs for a token.
    """

    buf_limit = 1024  # 1KB
    chunk_size = 0x20000  # 128KB
    name = "log_contents"

    __slots__ = ("logs", "tokens")

    def __init__(self, log_files, search_tokens):
        assert log_files, "log_files is empty"
        assert search_tokens, "search_tokens is empty"
        super().__init__()
        self.logs = list()
        for log_file in log_files:
            self.logs.append({"fname": log_file, "buffer": "", "offset": 0})
        self.tokens = search_tokens

    def check(self):
        """Collect log contents for tokens.

        Args:
            None

        Returns:
            bool: True if a token is located otherwise False.
        """
        for log in self.logs:
            try:
                # check if file has new data
                if stat(log["fname"]).st_size <= log["offset"]:
                    continue
                with open(log["fname"], "r") as scan_fp:
                    # only collect new data
                    scan_fp.seek(log["offset"], SEEK_SET)
                    # read and prepend chunk of previously read data
                    data = "".join([log["buffer"], scan_fp.read(self.chunk_size)])
                    log["offset"] = scan_fp.tell()
            except (IOError, OSError):
                # log does not exist
                continue
            for token in self.tokens:
                match = token.search(data)
                if match:
                    self.message = "TOKEN_LOCATED: %s\n" % (match.group(),)
                    return True
            log["buffer"] = data[-1 * self.buf_limit :]
        return False


class CheckLogSize(Check):
    """
    CheckLogSize will check the total file size of the browser logs.
    """

    name = "log_size"

    __slots__ = ("limit", "stderr_file", "stdout_file")

    def __init__(self, limit, stderr_file, stdout_file):
        super().__init__()
        self.limit = limit
        self.stderr_file = stderr_file
        self.stdout_file = stdout_file

    def check(self):
        """Collect log disk usage info and compare with limit.

        Args:
            None

        Returns:
            bool: True if the total usage is greater than or equal to
                  self.limit otherwise False.
        """
        err_size = stat(self.stderr_file).st_size
        out_size = stat(self.stdout_file).st_size
        total_size = err_size + out_size
        if total_size > self.limit:
            self.message = (
                "LOG_SIZE_LIMIT_EXCEEDED: %s\n"
                "Limit: %s (%dMB)\n"
                "stderr log: %s (%dMB)\n"
                "stdout log: %s (%dMB)\n"
                % (
                    format(total_size, ","),
                    format(self.limit, ","),
                    self.limit / 1048576,
                    format(err_size, ","),
                    err_size / 1048576,
                    format(out_size, ","),
                    out_size / 1048576,
                )
            )
        return self.message is not None


class CheckMemoryUsage(Check):
    """
    CheckMemoryUsage is used to check the amount of memory used by the browser
    process and its descendants against a defined limit.
    """

    name = "memory_usage"

    __slots__ = ("limit", "pid")

    def __init__(self, pid, limit):
        super().__init__()
        self.limit = limit
        self.pid = pid

    def check(self):
        """Use psutil to collect memory usage info and compare with limit.

        Args:
            None

        Returns:
            bool: True if the total usage is greater than or equal to
                  self.limit otherwise False.
        """
        proc_info = list()
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
                "MEMORY_LIMIT_EXCEEDED: %s\n" % (format(total_usage, ","),),
                "Limit: %s (%dMB)\n" % (format(self.limit, ","), self.limit / 1048576),
                "Parent PID: %d\n" % (self.pid,),
            ]
            for pid, usage in proc_info:
                msg.append("-> PID %6d: %s\n" % (pid, format(usage, "14,")))
            self.message = "".join(msg)
        return self.message is not None
