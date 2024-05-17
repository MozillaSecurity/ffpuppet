# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet process tree module"""

from logging import getLogger
from platform import system
from subprocess import Popen
from time import sleep
from typing import Generator, List, Optional, Tuple

from psutil import AccessDenied, NoSuchProcess, Process, TimeoutExpired, wait_procs

from .exceptions import TerminateError

LOG = getLogger(__name__)


class ProcessTree:
    """Manage the Firefox process tree. The process tree layout depends on the platform.
    Windows:
        python -> firefox (launcher) -> firefox (parent) -> firefox (content procs)

    Linux and others:
        python -> firefox (parent) -> firefox (content procs)
    """

    __slots__ = ("_launcher", "_launcher_check", "_proc", "parent")

    def __init__(self, proc: "Popen[bytes]") -> None:
        self._launcher: Optional[Process] = None
        # only perform the launcher check on Windows
        self._launcher_check = system() == "Windows"
        self._proc = proc
        self.parent: Process = Process(proc.pid)

    def cpu_usage(self) -> Generator[Tuple[int, float], None, None]:
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
            try:
                proc.cpu_percent()
            except (AccessDenied, NoSuchProcess):  # pragma: no cover
                continue
        # psutil recommends at least '0.1'.
        sleep(0.1)
        for proc in procs:
            try:
                yield proc.pid, proc.cpu_percent()
            except (AccessDenied, NoSuchProcess):  # pragma: no cover
                continue

    def is_running(self) -> bool:
        """Check if parent process is running.

        Args:
            None

        Returns:
            True if the parent process is running otherwise False
        """
        return self._poll(self.parent) is None

    @property
    def launcher(self) -> Optional[Process]:
        """Inspect process tree and identity the browser launcher and parent processes.

        Args:
            None

        Returns:
            None
        """
        if self._launcher_check and self._launcher is None:
            try:
                cmd = self.parent.cmdline()
            except (AccessDenied, NoSuchProcess):  # pragma: no cover
                LOG.debug("call to self.parent.cmdline() failed")
                cmd = []
            # check if launcher process is in use
            if "-no-deelevate" in cmd:
                launcher_children = self.parent.children(recursive=False)
                # launcher should only have one child process
                if len(launcher_children) == 1:
                    LOG.debug("launcher process detected")
                    self._launcher = self.parent
                    self.parent = launcher_children[0]
                else:
                    # this is expected behaviour when setting:
                    # - `browser.launcherProcess.enabled=false`
                    # it can also happen for unknown reasons...
                    LOG.debug(
                        "using launcher as parent, %d child proc(s) detected",
                        len(launcher_children),
                    )
                self._launcher_check = False
        return self._launcher

    @staticmethod
    def _poll(proc: Process) -> Optional[int]:
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
        except TimeoutExpired:
            return None

    def processes(self, recursive: bool = False) -> List[Process]:
        """Processes in the process tree.

        Args:
            recursive: if False only the parent and child processes are returned.

        Returns:
            Processes in the process tree.
        """
        procs: List[Process] = []
        if self.launcher is not None and self._poll(self.launcher) is None:
            procs.append(self.launcher)
        if self._poll(self.parent) is None:
            procs.append(self.parent)
        try:
            procs.extend(self.parent.children(recursive=recursive))
        except (AccessDenied, NoSuchProcess):  # pragma: no cover
            pass
        return procs

    def terminate(self) -> None:
        """Call terminate() on browser processes. If terminate() fails try kill().

        Args:
            None

        Returns:
            None
        """
        procs = self.processes(recursive=True)
        if not procs:
            LOG.debug("no processes to terminate")
            return

        # try terminating the parent process first, this should be all that is needed
        if self._poll(self.parent) is None:
            try:
                LOG.debug("attempting to terminate parent (%d)", self.parent.pid)
                self.parent.terminate()
                self.parent.wait(timeout=10)
            except (AccessDenied, NoSuchProcess, TimeoutExpired):  # pragma: no cover
                pass
            procs = wait_procs(procs, timeout=0)[1]

        use_kill = False
        while procs:
            LOG.debug(
                "calling %s on %d running process(es)",
                "kill()" if use_kill else "terminate()",
                len(procs),
            )
            # iterate over processes and call terminate()/kill()
            for proc in procs:
                try:
                    proc.kill() if use_kill else proc.terminate()
                except (AccessDenied, NoSuchProcess):  # pragma: no cover
                    pass
            # wait for processes to terminate
            procs = wait_procs(procs, timeout=30)[1]
            if use_kill:
                break
            use_kill = True

        if procs:
            LOG.warning("Processes still running: %d", len(procs))
            for proc in procs:
                try:
                    LOG.warning("-> %d (%s)", proc.pid, proc.name())
                except (AccessDenied, NoSuchProcess):  # pragma: no cover
                    pass
            raise TerminateError("Failed to terminate processes")

    def wait(self, timeout: int = 300) -> int:
        """Wait for parent process to exit.

        Args:
            timeout: Maximum time to wait before raising TimeoutExpired.

        Returns:
            Process exit code.
        """
        try:
            exit_code = self.parent.wait(timeout=timeout) or 0
        except NoSuchProcess:  # pragma: no cover
            # this is triggered sometimes when the process goes away
            exit_code = 0
        return exit_code

    def wait_procs(self, timeout: Optional[float] = 0) -> int:
        """Wait for process tree to exit.

        Args:
            timeout: Maximum time to wait.

        Returns:
            Number of processes still alive.
        """
        return len(wait_procs(self.processes(), timeout=timeout)[1])
