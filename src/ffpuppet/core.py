# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet module"""

from __future__ import annotations

from contextlib import suppress
from enum import IntEnum, unique
from logging import getLogger
from os import X_OK, access, getenv
from os.path import isfile, realpath
from pathlib import Path
from platform import system
from re import IGNORECASE, Pattern
from re import compile as re_compile
from re import match as re_match
from shutil import copy, copyfileobj
from subprocess import Popen
from sys import executable
from typing import TYPE_CHECKING
from urllib.request import pathname2url

with suppress(ImportError):
    # pylint: disable=ungrouped-imports
    from subprocess import CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]

    CREATE_SUSPENDED = 0x00000004

from .bootstrapper import Bootstrapper
from .checks import CheckLogContents, CheckLogSize, CheckMemoryUsage
from .debugger import ValgrindDebugger, load_debugger
from .display import DISPLAYS, DisplayMode
from .exceptions import BrowserExecutionError, InvalidPrefs, LaunchError
from .helpers import prepare_environment, wait_on_files
from .minidump_parser import MDSW_URL, MinidumpParser
from .process_tree import ProcessTree
from .profile import Profile
from .puppet_logger import PuppetLogger

if TYPE_CHECKING:
    from collections.abc import Generator

if system() == "Windows":
    # config_job_object is only available on Windows
    from .job_object import config_job_object, resume_suspended_process


# Note: ignore 245 for now to avoid getting flooded with OOMs that don't
# have a crash report... this should be revisited when time allows
# https://bugzil.la/1370520
# Ignore -9 to avoid false positives due to system OOM killer
BENIGN_EXIT_CODES = frozenset((0, 1, 2, 9, 15, 245))
LOG = getLogger(__name__)

__author__ = "Tyson Smith"
__all__ = ("FFPuppet", "Reason")


@unique
class Reason(IntEnum):
    """Indicates why the browser process was terminated"""

    # target crashed, aborted, triggered an assertion failure, etc...
    ALERT = 0
    # target was closed by call to FFPuppet close() or has not been launched
    CLOSED = 1
    # target exited
    EXITED = 2
    # target was closed by worker thread
    WORKER = 3


class FFPuppet:
    """FFPuppet manages launching and monitoring the browser process(es).
    This includes setting up the environment, collecting logs and some debugger support.
    """

    # minimum amount of time to wait for the browser to launch
    LAUNCH_TIMEOUT_MIN = 10

    __slots__ = (
        "_abort_tokens",
        "_bin_path",
        "_checks",
        "_dbg",
        "_display",
        "_launches",
        "_logs",
        "_proc_tree",
        "_profile_template",
        "_working_path",
        "marionette",
        "profile",
        "reason",
    )

    def __init__(
        self,
        debugger: str | None = None,
        display_mode: DisplayMode = DisplayMode.DEFAULT,
        use_profile: Path | None = None,
        working_path: str | None = None,
    ) -> None:
        """
        Args:
            debugger: Debugger to use.
            display_mode: Display mode to use.
            use_profile: Path to existing profile to use.
            working_path: Path to use as base directory for temporary files.
        """
        # tokens used to notify log scanner to kill the browser process
        self._abort_tokens: set[Pattern[str]] = set()
        self._bin_path: Path | None = None
        self._checks: list[CheckLogContents | CheckLogSize | CheckMemoryUsage] = []
        self._dbg = load_debugger(debugger) if debugger is not None else None
        self._display = DISPLAYS[display_mode]()
        # number of successful browser launches
        self._launches = 0
        self._proc_tree: ProcessTree | None = None
        self._profile_template = use_profile
        self._working_path = working_path
        self.marionette: int | None = None
        self.profile: Profile | None = None
        self.reason: Reason | None = Reason.CLOSED

        self._logs = PuppetLogger(base_path=working_path)

    def __enter__(self) -> FFPuppet:
        return self

    def __exit__(self, *exc: object) -> None:
        self.clean_up()

    def _benign_sanitizer_report(self, report: Path) -> bool:
        """Scan file for benign sanitizer reports.

        Args:
            report: File to scan.

        Returns:
            True if only benign reports are found otherwise False.
        """
        size = self._logs.watching.get(str(report))
        # skip previously scanned file if it has not been updated
        if size is not None and size == report.stat().st_size:
            return True

        try:
            # WARNING: cannot open files that are already open on Windows
            with report.open("rb") as log_fp:
                # NOTE: only add benign single line warnings here
                # this should not include any fatal errors
                for line in log_fp:
                    line = line.rstrip()
                    # entries to ignores
                    if not line:
                        # empty or blank line
                        continue
                    if line.endswith(b"==WARNING: Symbolizer buffer too small"):
                        # frequently emitted by TSan
                        continue
                    if (
                        b"Sanitizer failed to allocate" in line
                        and b"==WARNING: " in line
                    ):
                        # emitted by *SAN_OPTIONS=max_allocation_size_mb
                        continue
                    if b"Sanitizer: soft rss limit exhausted" in line:
                        # emitted by *SAN_OPTIONS=soft_rss_limit_mb
                        continue
                    # line looks interesting so stop scanning
                    break
                else:
                    # nothing interesting was found
                    LOG.debug("benign log has changed '%s'", report)
                    self._logs.watching[str(report)] = log_fp.tell()
                    return True

        except OSError:
            LOG.debug("failed to scan log %r", str(report))

        return False

    def _crashreports(
        self, skip_md: bool = False, skip_benign: bool = True
    ) -> Generator[Path]:
        """Collect crash logs/reports.

        Args:
            skip_md: Do not scan for minidumps.
            skip_benign: Skip reports that only contain benign non-fatal warnings.

        Yields:
            Log on the filesystem.
        """
        assert self._logs.path is not None
        # scan for sanitizer logs
        for entry in self._logs.path.glob(f"{self._logs.PREFIX_SAN}*"):
            if skip_benign and self._benign_sanitizer_report(entry):
                continue
            yield entry.resolve()
        # scan for Valgrind logs
        if isinstance(self._dbg, ValgrindDebugger):
            for entry in self._logs.path.glob(f"{self._logs.PREFIX_VALGRIND}*"):
                if entry.stat().st_size:
                    yield entry.resolve()
        # scan for minidump files
        if not skip_md:
            assert self.profile is not None
            assert self.profile.path is not None
            for entry in (self.profile.path / "minidumps").glob("*.dmp"):
                yield entry.resolve()

    def add_abort_token(self, token: str) -> None:
        """Add a token that when present in the browser log will have the
        browser process terminated.

        Args:
            token: Value to search for in the browser logs.

        Returns:
            None
        """
        assert token
        self._abort_tokens.add(re_compile(token))

    def available_logs(self) -> list[str]:
        """List of IDs for the currently available logs.

        Args:
            None

        Returns:
            All log IDs.
        """
        return list(self._logs.available_logs())

    def build_launch_cmd(
        self, bin_path: str, additional_args: list[str] | None = None
    ) -> list[str]:
        """Build a command that can be used to launch the browser.

        Args:
            bin_path: Absolute path to the browser binary.
            additional_args: Additional arguments to pass to the browser.

        Returns:
            Arguments that make up the launch command.
        """
        # if a python script is passed use 'sys.executable' as the binary
        # this is used by the test framework
        cmd: list[str] = []
        if bin_path.lower().endswith(".py"):
            cmd.append(executable)
        cmd += [bin_path, "-new-instance"]
        cmd.extend(self._display.args)
        if self.profile is not None:
            cmd += ["-profile", str(self.profile)]

        if additional_args:
            cmd.extend(additional_args)

        if self._dbg is not None:
            cmd = self._dbg.args() + cmd

        return cmd

    def clean_up(self) -> None:
        """Remove all remaining files created during execution. This will also
        clear some state information and should only be called once the FFPuppet
        object is no longer needed. Using the FFPuppet object after calling
        clean_up() is not supported.

        Args:
            None

        Returns:
            None
        """
        if self._launches < 0:
            LOG.debug("clean_up() call ignored")
            return
        LOG.debug("clean_up() called")
        try:
            self.close(force_close=True)
        finally:
            self._display.close()
        self._logs.clean_up(ignore_errors=True)
        # at this point everything should be cleaned up
        assert self.reason is not None
        assert self._logs.closed
        assert self._proc_tree is None
        assert self.profile is None
        # negative 'self._launches' indicates clean_up() has been called
        self._launches = -1

    def clone_log(
        self,
        log_id: str,
        offset: int = 0,
        target_file: str | None = None,
    ) -> Path | None:
        """Create a copy of the selected browser log.

        Args:
            log_id: ID (key) of the log to clone (stderr, stdout... etc).
            offset: Location to begin reading the file from.
            target_file: The log contents will be saved to target_file.

        Returns:
            Cloned log file or None on failure.
        """
        return self._logs.clone_log(log_id, offset=offset, target_file=target_file)

    def close(self, force_close: bool = False) -> None:
        """Terminate the browser process(es) and set `self.reason`. The reason
        code indicates how/why the browser process was terminated.

        Args:
            force_close: Do not collect logs, etc, just make sure everything is closed.

        Returns:
            None
        """
        LOG.debug("close(force_close=%r) called", force_close)
        assert self._launches > -1, "clean_up() has been called"
        if self.reason is not None:
            # make sure browser logs are closed
            self._logs.close()
            return

        assert self._proc_tree is not None
        LOG.debug("processes found: %d", self._proc_tree.wait_procs())
        # check state of browser processes and set the close reason
        if any(self._crashreports(skip_benign=True)):
            r_code = Reason.ALERT
            # Wait a moment for processes to exit automatically.
            # This will allow crash reports to be fully written to disk.
            # This assumes a crash report is written and all processes exit
            # when an issue is detected.
            # Be sure MOZ_CRASHREPORTER_SHUTDOWN=1 to avoid delays.
            proc_count = self._proc_tree.wait_procs(
                timeout=15 if self._dbg is None else 30
            )
            if proc_count > 0:
                LOG.warning(
                    "Slow shutdown detected, %d process(es) still running",
                    proc_count,
                )
            crash_reports = set(self._crashreports(skip_benign=True))
            LOG.debug("%d crash report(s) found", len(crash_reports))
            if crash_reports:
                # additional delay to allow crash reports to be completed/closed
                report_wait = 30 if self._dbg is None else 60
                if not wait_on_files(crash_reports, timeout=report_wait):
                    LOG.warning("Crash reports still open after %ds", report_wait)
            else:
                # this can actually happen
                LOG.warning("Crash reports disappeared! How did this happen?")
        elif self._proc_tree.is_running():
            r_code = Reason.CLOSED
        elif abs(self._proc_tree.wait()) not in BENIGN_EXIT_CODES:
            exit_code = self._proc_tree.wait()
            r_code = Reason.ALERT
            LOG.warning(
                "No crash reports found, exit code: %d (%X)", exit_code, exit_code
            )
        else:
            r_code = Reason.EXITED

        # close browser
        self._proc_tree.terminate()

        # collect crash reports and logs
        if not force_close and not self._logs.closed:
            LOG.debug("reviewing %d check(s)", len(self._checks))
            for check in self._checks:
                if check.message is not None:
                    r_code = Reason.WORKER
                    check.dump_log(
                        dst_fp=self._logs.add_log(f"ffp_worker_{check.name}")
                    )
            # collect logs (excluding minidumps)
            for log_path in self._crashreports(skip_md=True, skip_benign=False):
                self._logs.add_log(log_path.name, log_path.open("rb"))
            assert self.profile is not None
            assert self.profile.path is not None
            assert self._bin_path is not None
            dmp_files = MinidumpParser.dmp_files(self.profile.path / "minidumps")
            if dmp_files and not MinidumpParser.mdsw_available():
                LOG.error(
                    "Unable to process minidump, minidump-stackwalk is required. %s",
                    MDSW_URL,
                )
            elif dmp_files:
                if getenv("SAVE_DMP") == "1":
                    # save minidump directory contents (.dmp and .extra files)
                    dmps = self._logs.add_path("minidumps")
                    for md_file in (self.profile.path / "minidumps").glob("*"):
                        copy(md_file, dmps)
                # check for local build symbols
                if (self._bin_path.parent / "crashreporter-symbols").is_dir():
                    sym_path = self._bin_path.parent / "crashreporter-symbols"
                # use packaged symbols
                elif (self._bin_path / "symbols").is_dir():
                    sym_path = self._bin_path / "symbols"
                # no symbols path detected
                else:
                    sym_path = None

                with MinidumpParser(symbols=sym_path) as parser:
                    for count, dmp_file in enumerate(dmp_files):
                        md_txt = parser.create_log(dmp_file, f"minidump_{count:02}.txt")
                        with md_txt.open("rb") as md_fp:
                            copyfileobj(md_fp, self._logs.add_log(md_txt.stem))

            stderr_fp = self._logs.get_fp("stderr")
            if stderr_fp:
                stderr_fp.write(
                    f"[ffpuppet] Exit code: {self._proc_tree.wait()}\n".encode()
                )
                stderr_fp.write(f"[ffpuppet] Reason code: {r_code.name}\n".encode())

        # reset remaining to closed state
        try:
            self.marionette = None
            self._proc_tree = None
            self._logs.close()
            self._checks = []
            if self.profile is not None:
                self.profile.remove()
                self.profile = None
        finally:
            LOG.debug("reason code: %s", r_code.name)
            self.reason = r_code

    def cpu_usage(self) -> Generator[tuple[int, float]]:
        """Collect percentage of CPU usage per process.

        Args:
            None

        Yields:
            PID and the CPU usage as a percentage.
        """
        if self._proc_tree is not None:
            yield from self._proc_tree.cpu_usage()

    def dump_coverage(self, timeout: int = 15) -> None:
        """Signal browser to write coverage data to disk.

        Args:
            timeout: Number of seconds to wait for data to be written to disk.

        Returns:
            None
        """
        if system() != "Linux":  # pragma: no cover
            raise NotImplementedError("dump_coverage() is not available")
        if self._proc_tree and not self._proc_tree.dump_coverage(timeout=timeout):
            LOG.warning("Timeout writing coverage data")
            self.close()

    def get_pid(self) -> int | None:
        """Get the browser parent process ID.

        Args:
            None

        Returns:
            Browser PID.
        """
        pid: int | None = None
        if self._proc_tree is not None:
            pid = self._proc_tree.parent.pid
        return pid

    def is_healthy(self) -> bool:
        """Verify the browser is in a good state by performing a series of checks.

        Args:
            None

        Returns:
            True if the browser is running and determined to be
            in a valid functioning state otherwise False.
        """
        if self.reason is not None:
            LOG.debug("reason is set to %r", self.reason.name)
            return False
        if self._proc_tree is None or not self._proc_tree.is_running():
            LOG.debug("ProcessTree.is_running() returned False")
            return False
        if any(self._crashreports()):
            LOG.debug("crash report found")
            return False
        for check in self._checks:
            if check.check():
                LOG.debug("%r check abort conditions met", check.name)
                return False
        return True

    def is_running(self) -> bool:
        """Check if the browser is running.

        Args:
            None

        Returns:
            True if the browser is running otherwise False.
        """
        return self._proc_tree is not None and self._proc_tree.is_running()

    def launch(
        self,
        bin_path: Path,
        env_mod: dict[str, str | None] | None = None,
        launch_timeout: int = 300,
        location: str | None = None,
        log_limit: int = 0,
        marionette: int | None = None,
        memory_limit: int = 0,
        prefs_js: Path | None = None,
        extension: list[Path] | None = None,
        cert_files: list[Path] | None = None,
    ) -> None:
        """Launch a new browser process.

        Args:
            bin_path: Firefox binary.
            env_mod: Environment modifier. Add, remove and update entries
                     in the prepared environment. Add and update by
                     setting value (str) and remove by setting entry value to None.
            launch_timeout: Timeout in seconds for launching the browser.
            location: URL to navigate to after successfully launch of the browser.
            log_limit: Log file size limit in bytes. Browser will be
                       terminated if the log file exceeds the amount specified.
            memory_limit: Memory limit in bytes. Browser will be terminated
                          if its memory usage exceeds the amount specified.
            prefs_js: prefs.js file to install in the Firefox profile.
            extension: List of extensions to be installed.

        Returns:
            None
        """
        assert self._launches > -1, "clean_up() has been called"
        assert log_limit >= 0
        assert memory_limit >= 0
        if self._proc_tree is not None:
            raise LaunchError("Process is already running")

        # resolve path to avoid path issues when casting to a string
        bin_path = bin_path.resolve()
        if not bin_path.is_file() or not access(bin_path, X_OK):
            raise OSError(f"{bin_path} is not an executable")
        # need the path to help find symbols
        self._bin_path = bin_path.parent

        LOG.debug("requested location: %r", location)
        if location is not None:
            if isfile(location):
                location = f"file:///{pathname2url(realpath(location)).lstrip('/')}"
            elif re_match(r"http(s)?://", location, IGNORECASE) is None:
                raise OSError(f"Cannot find {location!r}")

        # clean up existing log files
        self._logs.reset()
        assert self._logs.path is not None

        # process environment
        env_mod = env_mod or {}
        if self._dbg is not None:
            env_mod.update(self._dbg.env())
        env_mod.update(self._display.env)

        # create a profile
        self.profile = Profile(
            browser_bin=bin_path,
            cert_files=cert_files,
            extensions=extension,
            prefs_file=prefs_js,
            template=self._profile_template,
            working_path=self._working_path,
        )
        LOG.debug("using profile '%s'", self.profile)

        # performing the bootstrap helps guarantee that the browser
        # will be loaded and ready to accept input when launch() returns
        bootstrapper = Bootstrapper.create()
        try:
            # added `network.proxy.failover_direct` and `network.proxy.allow_bypass`
            # to workaround default prefs.js packaged with Grizzly test cases.
            # This can be removed in the future but for now it unblocks
            # reducing older Grizzly test cases.
            prefs = {
                "capability.policy.localfilelinks.checkloaduri.enabled": "'allAccess'",
                "capability.policy.localfilelinks.sites": f"'{bootstrapper.location}'",
                "capability.policy.policynames": "'localfilelinks'",
                "network.proxy.allow_bypass": "false",
                "network.proxy.failover_direct": "false",
                "privacy.partition.network_state": "false",
            }

            launch_args = [bootstrapper.location]
            is_windows = system() == "Windows"
            if is_windows:
                # disable launcher process
                launch_args.append("-no-deelevate")
                launch_args.append("-wait-for-browser")

            if marionette is not None:
                # find/validate port to use
                free_sock = Bootstrapper.create_socket(port=marionette)
                if free_sock is None:
                    if marionette == 0:
                        LOG.error("Cannot find available port for marionette")
                    else:
                        LOG.error("Marionette cannot use port: %d", marionette)
                    raise LaunchError("Debugging server port unavailable")
                self.marionette = free_sock.getsockname()[1]
                free_sock.close()
                launch_args.append("-marionette")
                prefs["marionette.port"] = str(self.marionette)

            self.profile.add_prefs(prefs)

            cmd = self.build_launch_cmd(str(bin_path), additional_args=launch_args)

            # open logs
            self._logs.add_log("stdout")
            stderr = self._logs.add_log("stderr")
            stderr.write(f"[ffpuppet] Launch command: {' '.join(cmd)}\n\n".encode())
            stderr.flush()
            # launch the browser
            launch_timeout = max(launch_timeout, self.LAUNCH_TIMEOUT_MIN)
            LOG.debug("launch (%ds): %r", launch_timeout, " ".join(cmd))
            self.reason = None
            creationflags = 0
            if is_windows:
                creationflags |= CREATE_NEW_PROCESS_GROUP
                if memory_limit:
                    creationflags |= CREATE_SUSPENDED
            # pylint: disable=consider-using-with
            proc = Popen(
                cmd,
                bufsize=0,  # unbuffered (for log scanners)
                creationflags=creationflags,
                env=prepare_environment(
                    self._bin_path,
                    self._logs.path / self._logs.PREFIX_SAN,
                    env_mod=env_mod,
                ),
                shell=False,
                stderr=stderr,
                stdout=self._logs.get_fp("stdout"),
            )
            self._proc_tree = ProcessTree(proc)
            if (
                memory_limit and is_windows
            ):  # pylint: disable=possibly-used-before-assignment
                LOG.debug("configuring job object")
                # pylint: disable=no-member,protected-access
                config_job_object(
                    proc._handle,  # type: ignore[attr-defined]
                    memory_limit,
                )
                resume_suspended_process(proc.pid)
            bootstrapper.wait(self.is_healthy, timeout=launch_timeout, url=location)
            # check if launcher process is in use
            if self._proc_tree.launcher is not None:
                LOG.debug("browser launcher pid %d", self._proc_tree.launcher.pid)
            LOG.debug("browser parent pid %d", self._proc_tree.parent.pid)

        except FileNotFoundError as exc:
            if Path(exc.filename).exists():
                # this is known to happen when attempting to launch 32-bit binaries
                # on a 64-bit environment without proper libraries installed
                raise BrowserExecutionError("Cannot execute binary") from None
            raise
        finally:
            if self._proc_tree is None:
                # only clean up here if a launch was not attempted or Popen failed
                LOG.debug("process not launched")
                self.marionette = None
                self.profile.remove()
                self.profile = None
                self.reason = Reason.CLOSED
            bootstrapper.close()

        if prefs_js and self.profile and self.profile.invalid_prefs:
            raise InvalidPrefs(f"'{prefs_js.resolve()}' is invalid")

        logs_fp_stderr = self._logs.get_fp("stderr")
        assert logs_fp_stderr is not None
        logs_fp_stdout = self._logs.get_fp("stdout")
        assert logs_fp_stdout is not None
        if log_limit:
            self._checks.append(
                CheckLogSize(log_limit, logs_fp_stderr.name, logs_fp_stdout.name)
            )
        if memory_limit and not is_windows:
            # memory limit is enforced with config_job_object on Windows
            self._checks.append(
                CheckMemoryUsage(proc.pid, memory_limit, self._proc_tree.processes)
            )
        if self._abort_tokens:
            self._checks.append(
                CheckLogContents(
                    [
                        logs_fp_stderr.name,
                        logs_fp_stdout.name,
                    ],
                    self._abort_tokens,
                )
            )

        self._launches += 1

    @property
    def launches(self) -> int:
        """Number of successful launches.

        Args:
            None

        Returns:
            Successful launch count.
        """
        assert self._launches > -1, "clean_up() has been called"
        return self._launches

    def log_length(self, log_id: str) -> int | None:
        """Get the length of the selected browser log.

        Args:
            log_id: ID (key) of the log (stderr, stdout... etc).

        Returns:
            Length of the log in bytes.
        """
        return self._logs.log_length(log_id)

    def save_logs(self, dest: Path, logs_only: bool = False) -> None:
        """The browser logs will be saved to dest. This can only be called
        after close().

        Args:
            dest: Destination path for log data. Existing files will be overwritten.
            logs_only: Do not include other data such as debugger output files.

        Returns:
            None
        """
        LOG.debug("save_logs('%s', logs_only=%r)", dest, logs_only)
        assert self._launches > -1, "clean_up() has been called"
        assert self._logs.closed, "Logs are still in use. Call close() first!"
        self._logs.save_logs(
            dest,
            logs_only=logs_only,
            bin_path=self._bin_path,
            rr_pack=getenv("RR_PACK") == "1",
        )

    def wait(self, timeout: float | None = None) -> bool:
        """Wait for browser process(es) to terminate. This call will block until
        all process(es) exit unless a timeout is specified. If a timeout of zero
        or greater is specified the call will block until the timeout expires.

        Args:
            timeout: The maximum amount of time in seconds to wait or
                     None (wait indefinitely).

        Returns:
            True if processes exit before timeout expires otherwise False.
        """
        assert timeout is None or timeout >= 0
        if self._proc_tree and self._proc_tree.wait_procs(timeout=timeout) > 0:
            LOG.debug("wait(timeout=%0.2f) timed out", timeout)
            return False
        return True
