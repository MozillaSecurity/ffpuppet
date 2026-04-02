# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet process tree module"""

from __future__ import annotations

import sys
from contextlib import suppress
from logging import getLogger
from os import getenv
from pathlib import Path
from time import perf_counter, sleep
from typing import TYPE_CHECKING, cast

from psutil import (
    STATUS_ZOMBIE,
    AccessDenied,
    NoSuchProcess,
    Process,
    TimeoutExpired,
    process_iter,
    wait_procs,
)

from .exceptions import TerminateError

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Iterable

if sys.platform != "win32":
    from signal import SIGUSR1, Signals  # pylint: disable=no-name-in-module

    COVERAGE_SIGNAL: Signals | None = SIGUSR1
else:
    COVERAGE_SIGNAL = None


LOG = getLogger(__name__)


def _filter_zombies(procs: Iterable[Process]) -> Generator[Process]:
    """Filter out zombie processes from a collection of processes.

    Args:
        procs: Processes to check.

    Yields:
        Processes that are not zombies.
    """
    for proc in procs:
        with suppress(AccessDenied, NoSuchProcess):
            if proc.status() == STATUS_ZOMBIE:
                LOG.debug("filtering zombie: %d - %s", proc.pid, proc.name())
                continue
            yield proc


def _last_modified(scan_dir: Path) -> float | None:
    """Scan directory recursively and find the latest modified date of all .gcda files.

    Args:
        scan_dir: Directory to scan.

    Returns:
        Last modified date or None if no files are found.
    """
    with suppress(ValueError):
        return max(x.stat().st_mtime for x in scan_dir.glob("**/*.gcda"))
    return None


def _safe_wait_procs(
    procs: Iterable[Process],
    timeout: float | None = 0,
    callback: Callable[[Process], object] | None = None,
) -> tuple[list[Process], list[Process]]:
    """Wrapper for psutil.wait_procs() to avoid AccessDenied.
    This can be an issue on Windows.

    Args:
        See psutil.wait_procs().

    Returns:
        See psutil.wait_procs().
    """
    assert timeout is None or timeout >= 0

    deadline = None if timeout is None else perf_counter() + timeout
    while True:
        remaining = None if deadline is None else max(deadline - perf_counter(), 0)
        with suppress(AccessDenied):
            return cast(
                "tuple[list[Process], list[Process]]",
                wait_procs(procs, timeout=remaining, callback=callback),
            )
        if deadline is not None and deadline <= perf_counter():
            break
        sleep(0.25)

    # manually check processes
    alive: list[Process] = []
    gone: list[Process] = []
    for proc in procs:
        try:
            if not proc.is_running():
                gone.append(proc)
            else:
                alive.append(proc)
        except AccessDenied:  # noqa: PERF203
            alive.append(proc)
        except NoSuchProcess:
            gone.append(proc)
    return (gone, alive)


def _writing_coverage(procs: Iterable[Process]) -> bool:
    """Check if any processes have open .gcda files.

    Args:
        procs: Processes to check.

    Returns:
        True if processes with open .gcda files are found.
    """
    for proc in procs:
        with suppress(AccessDenied, NoSuchProcess):
            if any(x for x in proc.open_files() if x.path.endswith(".gcda")):
                return True
    return False


class ProcessTree:
    """Manage the Firefox process tree. The process tree layout depends on the platform.
    Windows:
        python -> firefox (launcher) -> firefox (parent) -> firefox (content procs)

    Linux and others:
        python -> firefox (parent) -> firefox (content procs)
    """

    __slots__ = ("launcher", "parent")

    def __init__(self, pid: int) -> None:
        self.launcher: Process | None = None
        self.parent = Process(pid)

    @staticmethod
    def _browser_parent_pid(proc: Process) -> int | None:
        with suppress(AccessDenied, NoSuchProcess, IndexError, ValueError):
            cmd = proc.cmdline()
            if "-contentproc" in cmd:
                idx = cmd.index("-parentPid")
                return int(cmd[idx + 1])
        return None

    def detect_launcher(self) -> None:
        """Check if launcher process exists. This could include a debugger or
        the launcher process. This should be called after bootstrap once the browser
        has launched.

        Args:
            None

        Returns:
            None.
        """
        if self.launcher is None:
            try:
                # search for browser parent process info
                for child in self.parent.children(recursive=True):
                    parent_pid = self._browser_parent_pid(child)
                    if parent_pid is not None:
                        parent = Process(parent_pid)
                        # check if debugger or launcher processes is in use
                        if parent.pid != self.parent.pid:
                            self.launcher = self.parent
                            self.parent = parent
                            break
            except (AccessDenied, NoSuchProcess):  # pragma: no cover
                LOG.debug("failed to detect launcher")

    def processes(self) -> list[Process]:
        """Processes in the process tree.

        Args:
            None

        Returns:
            Processes in the process tree.
        """
        procs: list[Process] = []
        subprocs: list[Process] | None = None
        if self.launcher is not None and self._poll(self.launcher) is None:
            procs.append(self.launcher)
        if self._poll(self.parent) is None:
            procs.append(self.parent)
            subprocs = self._recursive_process_scan()
        if subprocs is None:
            subprocs = list(self._full_system_scan())
        procs.extend(subprocs)
        return procs

    def _recursive_process_scan(self) -> list[Process] | None:
        """Scan the parent process recursively for running browser processes.
        This may included the actual parent process if detect_launcher() was not called.

        Args:
            None

        Returns:
            Browser processes.
        """
        with suppress(AccessDenied, NoSuchProcess):
            # mypy complains when returning result directly
            procs: list[Process] = self.parent.children(recursive=True)
            return procs
        return None

    def _full_system_scan(self) -> Generator[Process]:
        """Scan all running processes for browser content processes.
        This should be used when the parent process is no longer running to detect
        lingering content processes.

        Args:
            None

        Yields:
            Browser content processes.
        """
        for proc in process_iter(["pid", "cmdline"]):
            parent_pid = self._browser_parent_pid(proc)
            if parent_pid is not None and parent_pid == self.parent.pid:
                with suppress(AccessDenied, NoSuchProcess):
                    yield Process(proc.pid)

    def cpu_usage(self) -> Generator[tuple[int, float]]:
        """Collect percentage of CPU usage per process.

        Note: the returned value can be > 100.0 in case of a process running multiple
        threads on different CPU cores.
        See: https://psutil.readthedocs.io/en/latest/#psutil.Process.cpu_percent

        This value is not divided by CPU count because we are typically more concerned
        with the low end for detecting idle processes.

        Args:
            None

        Yields:
            PID and the CPU usage as a percentage.
        """
        procs = self.processes()
        for proc in procs:
            with suppress(AccessDenied, NoSuchProcess):
                proc.cpu_percent()
        # psutil recommends at least '0.1'.
        sleep(0.1)
        for proc in procs:
            with suppress(AccessDenied, NoSuchProcess):
                yield proc.pid, proc.cpu_percent()

    def dump_coverage(self, timeout: int = 15, idle_wait: int = 2) -> bool:
        """Signal processes to write coverage data to disk. Running coverage builds in
        parallel that are writing to the same location on disk is not recommended.
        NOTE: Coverage data is also written when launching and closing the browser.

        Args:
            timeout: Number of seconds to wait for data to be written to disk.
            idle_wait: Number of seconds to wait to determine if update is complete.

        Returns:
            True if coverage is written to disk or processes exit otherwise False.
        """
        assert COVERAGE_SIGNAL is not None
        assert getenv("GCOV_PREFIX_STRIP"), "GCOV_PREFIX_STRIP not set"
        assert getenv("GCOV_PREFIX"), "GCOV_PREFIX not set"
        # coverage output can take a few seconds to start and complete
        assert timeout > 5
        cov_path = Path(getenv("GCOV_PREFIX", ""))
        last_mdate = _last_modified(cov_path) or 0
        signaled = 0
        # send COVERAGE_SIGNAL (SIGUSR1) to browser processes
        for proc in self.processes():
            with suppress(AccessDenied, NoSuchProcess):
                proc.send_signal(COVERAGE_SIGNAL)
                signaled += 1
        # no processes signaled
        if signaled == 0:
            LOG.debug("coverage signal not sent, no browser processes found")
            return True
        # wait for processes to write .gcda files (typically takes ~2 seconds)
        start_time = perf_counter()
        last_change = None
        while True:
            if not self.is_running():
                LOG.debug("not running waiting for coverage dump")
                return True
            # collect latest last modified dates
            mdate = _last_modified(cov_path) or 0
            # check if gcda files have been updated
            now = perf_counter()
            elapsed = now - start_time
            if mdate > last_mdate:
                last_change = now
                last_mdate = mdate
            # check if gcda write is complete (wait)
            if (
                last_change is not None
                and now - last_change > idle_wait
                and not _writing_coverage(self.processes())
            ):
                LOG.debug("coverage (gcda) dump took %0.2fs", elapsed)
                return True
            # check if max duration has been exceeded
            if elapsed >= timeout:
                if last_change is None:
                    LOG.warning("Coverage files not modified after %0.2fs", elapsed)
                else:
                    LOG.warning("Coverage file open after %0.2fs", elapsed)
                break
            sleep(0.25)
        return False

    def is_running(self) -> bool:
        """Check if parent process is running.

        Args:
            None

        Returns:
            True if the parent process is running otherwise False
        """
        return self._poll(self.parent) is None

    @staticmethod
    def _poll(proc: Process) -> int | None:
        """Poll a given process.

        Args:
            proc: Process to poll.

        Returns:
            None if the process is running otherwise the exit code is returned.
        """
        try:
            return proc.wait(timeout=0) or 0
        except NoSuchProcess:
            LOG.debug("called poll() on process that does not exist")
            return 0
        except (AccessDenied, TimeoutExpired):
            return None

    def terminate(self) -> None:
        """Call terminate() on browser processes. If terminate() fails try kill().

        Args:
            None

        Returns:
            None
        """
        procs = self.processes()
        if not procs:
            LOG.debug("no processes to terminate")
            return
        # try terminating the parent process first, this should be all that is needed
        if self._poll(self.parent) is None:
            with suppress(AccessDenied, NoSuchProcess, TimeoutExpired):
                LOG.debug("attempting to terminate parent (%d)", self.parent.pid)
                self.parent.terminate()
                self.parent.wait(timeout=10)
        # remaining processes should exit if parent process is gone
        _safe_wait_procs(procs, timeout=1)
        procs = list(_filter_zombies(self.processes()))
        use_kill = False
        while procs:
            LOG.debug(
                "calling %s on %d running process(es)",
                "kill()" if use_kill else "terminate()",
                len(procs),
            )
            # iterate over processes and call terminate()/kill()
            for proc in procs:
                with suppress(AccessDenied, NoSuchProcess):
                    if use_kill:
                        proc.kill()
                    else:
                        proc.terminate()
            # wait for processes to terminate
            _safe_wait_procs(procs, timeout=30)
            procs = list(_filter_zombies(self.processes()))
            if use_kill:
                break
            use_kill = True

        if procs:
            LOG.warning("Processes still running: %d", len(procs))
            for proc in procs:
                with suppress(AccessDenied, NoSuchProcess):
                    LOG.warning("-> %d: %s (%s)", proc.pid, proc.name(), proc.status())
            raise TerminateError("Failed to terminate processes")

    def wait(self, timeout: int = 300) -> int:
        """Wait for parent process to exit.

        Args:
            timeout: Maximum time to wait before raising TimeoutExpired.

        Returns:
            Process exit code.
        """
        with suppress(AccessDenied, NoSuchProcess):
            return self.parent.wait(timeout=timeout) or 0
        return 0  # pragma: no cover

    def wait_procs(self, timeout: float | None = 0) -> int:
        """Wait for process tree to exit.

        Args:
            timeout: Maximum time to wait.

        Returns:
            Number of processes still alive.
        """
        return len(_safe_wait_procs(self.processes(), timeout=timeout)[1])
