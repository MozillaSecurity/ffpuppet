# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""browser and debugger log management"""

from __future__ import annotations

from contextlib import suppress
from logging import getLogger
from mmap import ACCESS_READ, mmap
from os import getpid, stat
from os.path import isfile
from pathlib import Path
from shutil import copy2, copyfileobj, copytree, rmtree
from subprocess import STDOUT, CalledProcessError, check_output
from tempfile import NamedTemporaryFile, mkdtemp
from typing import IO, TYPE_CHECKING

from .helpers import warn_open

if TYPE_CHECKING:
    from collections.abc import Generator

LOG = getLogger(__name__)

__author__ = "Tyson Smith"
__credits__ = ["Tyson Smith"]


class PuppetLogger:  # pylint: disable=missing-docstring
    BUF_SIZE = 0x10000  # buffer size used to copy logs
    PATH_RR = "rr-traces"
    PREFIX_SAN = f"ffp_asan_{getpid()}.log"
    PREFIX_VALGRIND = f"valgrind.{getpid()}"

    __slots__ = ("_base", "_logs", "_rr_packed", "closed", "path", "watching")

    def __init__(self, base_path: str | None = None) -> None:
        self._base = base_path
        self._logs: dict[str, IO[bytes]] = {}
        self._rr_packed = False
        self.closed = True
        self.path: Path | None = None
        self.watching: dict[str, int] = {}
        self.reset()

    def __enter__(self) -> PuppetLogger:
        return self

    def __exit__(self, *exc: object) -> None:
        self.clean_up()

    def add_log(self, log_id: str, logfp: IO[bytes] | None = None) -> IO[bytes]:
        """Add a log file to the log manager.

        Args:
            log_id: ID of the log to add.
            logfp: File object to use. If None a new log file will be created.

        Returns:
            Newly added log file.
        """
        assert log_id not in self._logs
        assert not self.closed
        if logfp is None:
            logfp = PuppetLogger.open_unique(
                base_dir=str(self.path) if self.path else None
            )
        self._logs[log_id] = logfp
        return logfp

    def add_path(self, name: str) -> Path:
        """Add a directory that can be used as temporary storage for
        miscellaneous items such as additional debugger output.

        Args:
            name: Name of directory to create.

        Returns:
            Path of newly created directory.
        """
        assert not self.closed
        assert self.path is not None
        path = self.path / name
        LOG.debug("adding path '%s' as '%s'", name, path)
        path.mkdir()
        return path

    def available_logs(self) -> frozenset[str]:
        """IDs for the available logs.

        Args:
            None

        Returns:
            All available log IDs.
        """
        return frozenset(self._logs.keys())

    def clean_up(self, ignore_errors: bool = False) -> None:
        """Remove log files from disk.

        Args:
            ignore_errors: Ignore errors triggered by removing files and directories.

        Returns:
            None
        """
        if not self.closed:
            self.close()
        if self.path is not None:
            try:
                if self.path.exists():
                    rmtree(self.path, ignore_errors=ignore_errors)
            except OSError:
                warn_open(self.path)
                raise
        self._logs.clear()
        self.path = None

    def clone_log(
        self,
        log_id: str,
        offset: int = 0,
        target_file: str | None = None,
    ) -> Path | None:
        """Create a copy of the specified log.

        Args:
            log_id: ID of the log to clone.
            offset: Where to begin reading the log from.
            target_file: The log contents will be saved to target_file.

        Returns:
            Name of the file containing the cloned log or None on failure.
        """
        log_fp = self.get_fp(log_id)
        if log_fp is None:
            return None
        if not log_fp.closed:
            log_fp.flush()
        with open(log_fp.name, "rb") as in_fp:
            if offset:
                in_fp.seek(offset)
            if target_file is None:
                with PuppetLogger.open_unique(base_dir=self._base) as cpyfp:
                    target_file = cpyfp.name
            with open(target_file, "wb") as cpyfp:
                copyfileobj(in_fp, cpyfp, self.BUF_SIZE)
        return Path(target_file)

    def close(self) -> None:
        """Close all open file objects.

        Args:
            None

        Returns:
            None
        """
        for lfp in self._logs.values():
            if not lfp.closed:
                lfp.close()
        self.closed = True

    @property
    def files(self) -> Generator[str]:
        """File names of log files.

        Args:
            None

        Yields:
            File names of log files.
        """
        for lfp in self._logs.values():
            if lfp.name is not None:
                yield lfp.name

    def get_fp(self, log_id: str) -> IO[bytes] | None:
        """Lookup log file object by ID.

        Args:
            log_id: ID of the log (stderr, stdout... etc).

        Returns:
            The file matching given ID otherwise None.
        """
        try:
            log_fp = self._logs[log_id]
        except KeyError:
            LOG.warning("log_id '%s' does not exist", log_id)
            return None
        if log_fp.name is None or not isfile(log_fp.name):
            raise FileNotFoundError(f"Log file not found: {log_fp.name}")
        return log_fp

    def log_length(self, log_id: str) -> int | None:
        """Get the length of the specified log.

        Args:
            log_id: ID of the log to measure.

        Returns:
            Length of the specified log in bytes or None if the log does not exist.
        """
        log_fp = self.get_fp(log_id)
        if log_fp is None:
            return None
        if not log_fp.closed:
            log_fp.flush()
        return stat(log_fp.name).st_size

    @staticmethod
    def open_unique(base_dir: str | None = None, mode: str = "wb") -> IO[bytes]:
        """Create and open a unique file.

        Args:
            base_dir: This is where the file will be created. If None is
                      passed the system default will be used.
            mode: File mode. See documentation for open().

        Returns:
            An open file object.
        """
        return NamedTemporaryFile(
            mode, delete=False, dir=base_dir, prefix="ffp_log_", suffix=".txt"
        )

    def reset(self) -> None:
        """Reset logger for reuse.

        Args:
            None

        Returns:
            None
        """
        self.clean_up()
        self.closed = False
        self._rr_packed = False
        self.path = Path(mkdtemp(prefix="ffplogs_", dir=self._base))

    def save_logs(
        self,
        dest: Path,
        logs_only: bool = False,
        bin_path: Path | None = None,
        rr_pack: bool = False,
    ) -> None:
        """The browser logs will be saved to dest. This can only be called
        after close() has been called.

        Args:
            dest: Destination path for log data. Existing files will be overwritten.
            logs_only: Do not include other data, including debugger output files.
            bin_path: Firefox binary.
            rr_pack: Pack rr trace if required.

        Returns:
            None
        """
        assert self.closed, "save_logs() cannot be called before calling close()"
        assert self.path is not None

        # copy log to location specified by dest
        dest.mkdir(parents=True, exist_ok=True)

        for log_id, log_fp in self._logs.items():
            copy2(log_fp.name, dest / f"log_{log_id}.txt")

        if not logs_only:
            rr_trace = self.path / self.PATH_RR / "latest-trace"
            if rr_trace.is_dir():
                # check logs for rr related issues
                # OSError: in case the file does not exist
                # ValueError: cannot mmap an empty file on Windows
                with (
                    suppress(OSError, ValueError),
                    (dest / "log_stderr.txt").open("rb") as lfp,
                    mmap(lfp.fileno(), 0, access=ACCESS_READ) as lmm,
                ):
                    if lmm.find(b"=== Start rr backtrace:") != -1:
                        LOG.warning("rr traceback detected in stderr log")
                if rr_pack and not self._rr_packed:
                    LOG.debug("packing rr trace")
                    try:
                        check_output(["rr", "pack", str(rr_trace)], stderr=STDOUT)
                        self._rr_packed = True
                    except (OSError, CalledProcessError):
                        LOG.warning("Error calling 'rr pack %s'", rr_trace)
                # copy `taskcluster-build-task` for use with Pernosco if available
                if bin_path is not None:
                    task_info = bin_path / "taskcluster-build-task"
                    if task_info.is_file():
                        moz_rr = rr_trace / "files.mozilla"
                        moz_rr.mkdir(parents=True, exist_ok=True)
                        copy2(task_info, moz_rr)
                        LOG.debug("Copied 'taskcluster-build-task' to trace")

            for entry in self.path.iterdir():
                if entry.is_dir():
                    copytree(entry, dest / entry.name, symlinks=True)
