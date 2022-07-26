# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet module"""

from enum import Enum, unique
from logging import getLogger
from os import X_OK, access, getenv, getpid
from os.path import abspath, dirname, isfile
from os.path import join as pathjoin
from os.path import realpath
from pathlib import Path
from platform import system
from re import IGNORECASE
from re import compile as re_compile
from re import match as re_match
from shutil import rmtree
from subprocess import Popen, check_output
from sys import executable
from typing import Any, Dict, Iterator, List, Optional, Pattern, Set, Tuple, Union
from urllib.request import pathname2url

try:
    # pylint: disable=ungrouped-imports
    from subprocess import CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
except ImportError:
    pass

from psutil import AccessDenied, NoSuchProcess, Process, process_iter, wait_procs

try:
    from xvfbwrapper import Xvfb
except ImportError:
    pass

from .bootstrapper import Bootstrapper
from .checks import CheckLogContents, CheckLogSize, CheckMemoryUsage
from .exceptions import InvalidPrefs, LaunchError, TerminateError
from .helpers import (
    append_prefs,
    create_profile,
    files_in_use,
    get_processes,
    onerror,
    prepare_environment,
    wait_on_files,
)
from .minidump_parser import process_minidumps
from .puppet_logger import PuppetLogger

LOG = getLogger(__name__)

__author__ = "Tyson Smith"
__all__ = ("Debugger", "FFPuppet", "Reason")


@unique
class Debugger(Enum):
    """Available "debuggers" to run the browser with"""

    NONE: int = 0
    GDB: int = 1
    PERNOSCO: int = 2
    RR: int = 3
    VALGRIND: int = 4


@unique
class Reason(Enum):
    """Indicates why the browser process was terminated"""

    # target crashed, aborted, triggered an assertion failure, etc...
    ALERT: int = 0
    # target was closed by call to FFPuppet close() or has not been launched
    CLOSED: int = 1
    # target exited
    EXITED: int = 2
    # target was closed by worker thread
    WORKER: int = 3


class FFPuppet:
    """FFPuppet manages launching and monitoring the browser process(es).
    This includes setting up the environment, collecting logs and some debugger support.

    Attributes:
        debugger: Debugger to use.
        headless: Headless mode to use.
        use_profile: Path to existing user profile.
        use_xvfb: Use Xvfb (DEPRECATED).
        working_path: Path to use as base directory for temporary files.
    """

    LAUNCH_TIMEOUT_MIN = 10  # minimum amount of time to wait for the browser to launch
    VALGRIND_MIN_VERSION = 3.14  # minimum allowed version of Valgrind

    __slots__ = (
        "_abort_tokens",
        "_bin_path",
        "_checks",
        "_dbg",
        "_headless",
        "_launches",
        "_logs",
        "_proc",
        "_profile_template",
        "_xvfb",
        "_working_path",
        "profile",
        "reason",
    )

    def __init__(
        self,
        debugger: Debugger = Debugger.NONE,
        headless: Optional[str] = None,
        use_profile: Optional[str] = None,
        use_xvfb: bool = False,
        working_path: Optional[str] = None,
    ):
        # tokens used to notify log scanner to kill the browser process
        self._abort_tokens: Set[Pattern[str]] = set()
        self._bin_path: Optional[str] = None
        self._checks: List[
            Union[CheckLogContents, CheckLogSize, CheckMemoryUsage]
        ] = list()
        self._dbg = debugger
        self._dbg_sanity_check(self._dbg)
        self._headless = headless
        self._launches = 0  # number of successful browser launches
        self._logs = PuppetLogger(base_path=working_path)
        self._proc: Optional["Popen[bytes]"] = None
        self._profile_template = use_profile  # profile that is used as a template
        self._xvfb = None
        self._working_path = working_path
        self.profile: Optional[str] = None  # path to profile
        self.reason: Optional[Reason] = Reason.CLOSED

        if use_xvfb:
            self._headless = "xvfb"

        if self._headless == "xvfb":
            try:
                self._xvfb = Xvfb(width=1280, height=1024)
            except NameError:
                self._logs.clean_up(ignore_errors=True)
                raise OSError(
                    "Please install xvfbwrapper (Only supported on Linux)"
                ) from None
            self._xvfb.start()
        else:
            assert self._headless in (None, "default")

    def __enter__(self) -> "FFPuppet":
        return self

    def __exit__(self, *exc: Any) -> None:
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
    ) -> Iterator[Path]:
        """Collect crash logs/reports.

        Args:
            skip_md: Do not scan for minidumps.
            skip_benign: Skip reports that only contain benign non-fatal
                                warnings.

        Yields:
            Log on the filesystem.
        """
        assert self._logs.working_path is not None
        log_path = Path(self._logs.working_path)
        # scan for sanitizer logs
        for entry in log_path.glob(f"{self._logs.PREFIX_SAN}*"):
            if skip_benign and self._benign_sanitizer_report(entry):
                continue
            yield entry.resolve()
        # scan for Valgrind logs
        if self._dbg == Debugger.VALGRIND:
            for entry in log_path.glob(f"{self._logs.PREFIX_VALGRIND}*"):
                if entry.stat().st_size:
                    yield entry.resolve()
        # scan for minidump files
        if not skip_md:
            assert self.profile is not None
            for entry in (Path(self.profile) / "minidumps").glob("*.dmp"):
                yield entry.resolve()

    @classmethod
    def _dbg_sanity_check(cls, dbg: Debugger) -> None:
        """Check requested debugger is supported and available.

        Args:
            dbg: Debugger to sanity check.

        Returns:
            None
        """
        LOG.debug("checking %s support", dbg)
        if dbg == Debugger.GDB:
            if not system().startswith("Linux"):
                raise OSError("GDB is only supported on Linux")
            try:
                check_output(["gdb", "--version"])
            except OSError:
                raise OSError("Please install GDB") from None
        elif dbg in (Debugger.PERNOSCO, Debugger.RR):
            if not system().startswith("Linux"):
                raise OSError("rr is only supported on Linux")
            try:
                check_output(["rr", "--version"])
            except OSError:
                raise OSError("Please install rr") from None
        elif dbg == Debugger.VALGRIND:
            if not system().startswith("Linux"):
                raise OSError("Valgrind is only supported on Linux")
            try:
                match = re_match(
                    b"valgrind-(?P<ver>\\d+\\.\\d+)",
                    check_output(["valgrind", "--version"]),
                )
            except OSError:
                raise OSError("Please install Valgrind") from None
            if not match or float(match.group("ver")) < cls.VALGRIND_MIN_VERSION:
                raise OSError(f"Valgrind >= {cls.VALGRIND_MIN_VERSION:.2f} is required")

    @staticmethod
    def _terminate(
        procs: List[Process], retry_delay: int = 30, use_kill: bool = False
    ) -> None:
        """Call terminate() on provided processes. If terminate() fails try kill().

        Args:
            procs: Processes to terminate/kill.
            retry_delay: Time in seconds to wait before next attempt.
            use_kill: Initial mode.

        Returns:
            None
        """
        while True:
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
            procs = wait_procs(procs, timeout=retry_delay)[1]
            if not procs or use_kill:
                break
            use_kill = True

        if procs:
            for proc in procs:
                try:
                    LOG.warning(
                        "Failed to terminate process %d (%s)", proc.pid, proc.name()
                    )
                except (AccessDenied, NoSuchProcess):  # pragma: no cover
                    pass
            raise TerminateError("Failed to terminate processes")

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

    def available_logs(self) -> List[str]:
        """List of IDs for the currently available logs.

        Args:
            None

        Returns:
            A list contains log IDs (str).
        """
        return list(self._logs.available_logs())

    def build_launch_cmd(
        self, bin_path: str, additional_args: Optional[List[str]] = None
    ) -> List[str]:
        """Build a command that can be used to launch the browser.

        Args:
            bin_path: Path to the browser binary.
            additional_args: Additional arguments to pass to the browser.

        Returns:
            List of arguments that make up the launch command.
        """
        # if a python script is passed use 'sys.executable' as the binary
        # this is used by the test framework
        cmd = list()
        if bin_path.lower().endswith(".py"):
            cmd.append(executable)
        cmd += [bin_path, "-no-remote"]
        if self._headless == "default":
            cmd.append("-headless")
        if self.profile is not None:
            cmd += ["-profile", self.profile]

        if additional_args:
            cmd.extend(additional_args)

        if self._dbg == Debugger.VALGRIND:
            assert self._logs.working_path is not None
            valgrind_log_prefix = pathjoin(
                self._logs.working_path, self._logs.PREFIX_VALGRIND
            )
            valgrind_cmd = [
                "valgrind",
                "-q",
                "--error-exitcode=99",
                "--exit-on-first-error=yes",
                "--expensive-definedness-checks=yes",
                "--fair-sched=try",
                "--gen-suppressions=all",
                "--leak-check=no",
                f"--log-file={valgrind_log_prefix}.%p",
                "--read-inline-info=no",
                "--show-mismatched-frees=no",
                "--show-possibly-lost=no",
                "--smc-check=all-non-file",
                "--trace-children=yes",
                "--trace-children-skip=python*,*/lsb_release",
                "--track-origins=yes",
                "--vex-iropt-register-updates=allregs-at-mem-access",
            ]

            sup_file = getenv("VALGRIND_SUP_PATH")
            if sup_file:
                if not isfile(sup_file):
                    raise OSError(f"Missing Valgrind suppressions {sup_file!r}")
                LOG.debug("using Valgrind suppressions: %r", sup_file)
                valgrind_cmd.append(f"--suppressions={sup_file}")

            cmd = valgrind_cmd + cmd

        elif self._dbg == Debugger.GDB:
            cmd = [
                "gdb",
                "-nx",
                "-x",
                abspath(pathjoin(dirname(__file__), "cmds.gdb")),
                "-ex",
                "run",
                "-ex",
                "print $_siginfo",
                "-ex",
                "info locals",
                "-ex",
                "info registers",
                "-ex",
                "backtrace full",
                "-ex",
                "disassemble",
                "-ex",
                "symbol-file",
                # "-ex", "symbol-file %s",
                "-ex",
                "sharedlibrary",
                "-ex",
                "info proc mappings",
                "-ex",
                "info threads",
                "-ex",
                "shared",
                "-ex",
                "info sharedlibrary",
                # "-ex", "init-if-undefined $_exitcode = -1", # windows
                # "-ex", "quit $_exitcode", # windows
                "-ex",
                "quit_with_code",
                "-return-child-result",
                "-batch",
                "--args",
            ] + cmd

        elif self._dbg in (Debugger.PERNOSCO, Debugger.RR):
            rr_cmd = [
                "rr",
                "record",
            ]
            if self._dbg == Debugger.PERNOSCO:
                rr_cmd += [
                    "--chaos",
                    "--disable-cpuid-features-ext",
                    "0xdc230000,0x2c42,0xc",
                ]
            cmd = rr_cmd + cmd

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
        self.close(force_close=True)
        self._logs.clean_up(ignore_errors=True)
        # close Xvfb
        if self._xvfb is not None:
            self._xvfb.stop()
            self._xvfb = None
        # at this point everything should be cleaned up
        assert self.reason is not None
        assert self._logs.closed
        assert self._proc is None
        assert self.profile is None
        # negative 'self._launches' indicates clean_up() has been called
        self._launches = -1

    def clone_log(
        self,
        log_id: str,
        offset: Optional[int] = None,
        target_file: Optional[str] = None,
    ) -> Optional[str]:
        """Create a copy of the selected browser log.

        Args:
            log_id: ID (key) of the log to clone (stderr, stdout... etc).
            offset: Location to begin reading the file from.
            target_file: The log contents will be saved to target_file.

        Returns:
            Name of the file containing the cloned log or None on failure.
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

        assert self._proc is not None
        pid = self.get_pid()
        procs = get_processes(pid) if pid is not None else list()
        LOG.debug("browser pid: %r, %d proc(s)", pid, len(procs))

        # If the parent process closes while other processes are still open
        # get_processes() will return an empty list, perform a secondary scan if needed
        if not procs and self._logs.get_fp("stderr"):
            stderr_fp = self._logs.get_fp("stderr")
            assert stderr_fp is not None
            # create a list of processes that are using the stderr file
            # this *should* only include the browser and the current Python process
            procs = []
            for _, other_pid, _ in files_in_use(
                [Path(stderr_fp.name)], process_iter(["pid", "name", "open_files"])
            ):
                # don't include the current Python process in the results
                if other_pid != getpid():
                    try:
                        procs.append(Process(other_pid))
                    except (AccessDenied, NoSuchProcess):  # pragma: no cover
                        pass
            LOG.debug("secondary scan found %d process(es)", len(procs))

        # set reason code
        exit_code = None
        if any(self._crashreports(skip_benign=True)):
            r_code = Reason.ALERT
            # Wait a moment for processes to exit automatically.
            # This will allow crash reports to be fully written to disk.
            # This assumes a crash report is written and all processes exit
            # when an issue is detected.
            # Be sure MOZ_CRASHREPORTER_SHUTDOWN=1 to avoid delays.
            procs = wait_procs(
                procs,
                timeout=30 if self._dbg == Debugger.NONE else 60,
            )[1]
            if procs:
                LOG.warning(
                    "Slow shutdown detected, %d process(es) still running",
                    len(procs),
                )
            crash_reports = set(self._crashreports(skip_benign=True))
            LOG.debug("%d crash report(s) found", len(crash_reports))
            # wait until crash report files are closed
            report_wait = 60 if self._dbg == Debugger.NONE else 300
            if not wait_on_files(crash_reports, timeout=report_wait):
                LOG.warning("Crash reports still open after %ds", report_wait)
            # get active processes after waiting for crash reports to close
            procs = wait_procs(procs, timeout=0)[1]
        elif self.is_running():
            r_code = Reason.CLOSED
            assert procs
        elif self._proc.poll() not in (0, -1, 1, -2, -9, 245):
            # Note: ignore 245 for now to avoid getting flooded with OOMs that don't
            # have a crash report... this should be revisited when time allows
            # https://bugzil.la/1370520
            # Ignore -9 to avoid false positives due to system OOM killer
            exit_code = self._proc.poll()
            r_code = Reason.ALERT
            LOG.warning(
                "Browser exit code: %r (%X), no crash reports found",
                exit_code,
                exit_code,
            )
        else:
            r_code = Reason.EXITED

        # close processes
        if procs:
            # when running under a debugger close the debugger first
            if self._dbg != Debugger.NONE and self.is_running():
                LOG.debug("attempting to close debugger")
                try:
                    procs[0].terminate()
                    # only wait if terminate() call does not fail
                    procs = wait_procs(procs, timeout=10)[1]
                except (AccessDenied, NoSuchProcess):  # pragma: no cover
                    pass
            self._terminate(procs)

        # collect crash reports and logs
        if not force_close:
            if self._logs.closed:  # pragma: no cover
                # This should not happen while everything is working as expected.
                # This is here to prevent additional unexpected issues.
                # Since this should never happen in normal operation this assert
                # will help verify that.
                # If '_proc' is not None this is the first call to close()
                # in this situation the PuppetLogger should still be available.
                assert self._proc is None, "PuppetLogger is closed!"
            else:
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
                assert self._bin_path is not None
                # check for minidumps and process them if possible
                md_path = Path(self.profile) / "minidumps"
                if any(md_path.glob("*.dmp")):
                    # check for local build symbols
                    sym_path = Path(self._bin_path) / ".." / "crashreporter-symbols"
                    if not sym_path.is_dir():
                        # use packaged symbols
                        sym_path = Path(self._bin_path) / "symbols"
                    process_minidumps(
                        md_path,
                        sym_path,
                        self._logs.add_log,
                        working_path=self._working_path,
                    )
                stderr_fp = self._logs.get_fp("stderr")
                if stderr_fp:
                    if exit_code is not None:
                        stderr_fp.write(f"[ffpuppet] Exit code: {exit_code}\n".encode())
                    stderr_fp.write(f"[ffpuppet] Reason code: {r_code.name}\n".encode())

        # reset remaining to closed state
        try:
            self._proc = None
            self._logs.close()
            self._checks = list()
            # remove temporary profile directory if necessary
            try:
                assert self.profile is not None
                rmtree(self.profile, onerror=onerror)
            except OSError:  # pragma: no cover
                LOG.error("Failed to remove profile %r", self.profile)
                if not force_close:
                    raise
            finally:
                self.profile = None
        finally:
            LOG.debug("reason code: %s", r_code.name)
            self.reason = r_code

    def cpu_usage(self) -> Iterator[Tuple[int, float]]:
        """Collect percentage of CPU usage per process.

        Args:
            None

        Yields:
            PID and the CPU usage as a percentage.
        """
        pid = self.get_pid()
        if pid is not None:
            for proc in get_processes(pid):
                try:
                    yield proc.pid, proc.cpu_percent(interval=0.1)
                except (AccessDenied, NoSuchProcess):  # pragma: no cover
                    continue

    def get_pid(self) -> Optional[int]:
        """Get the browser process ID.

        Args:
            None

        Returns:
            Browser PID.
        """
        try:
            return self._proc.pid  # type: ignore[union-attr]
        except AttributeError:
            return None

    def is_healthy(self) -> bool:
        """Verify the browser is in a good state by performing a series
        of checks.

        Args:
            None

        Returns:
            True if the browser is running and determined to be
            in a valid functioning state otherwise False.
        """
        if self.reason is not None:
            LOG.debug("reason is set to %r", self.reason.name)
            return False
        if not self.is_running():
            LOG.debug("is_running() returned False")
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
        """Check if the browser process is running.

        Args:
            None

        Returns:
            True if the process is running otherwise False.
        """
        try:
            return self._proc.poll() is None  # type: ignore[union-attr]
        except AttributeError:
            return False

    def launch(
        self,
        bin_path: str,
        env_mod: Optional[Dict[str, Optional[str]]] = None,
        launch_timeout: int = 300,
        location: Optional[str] = None,
        log_limit: int = 0,
        memory_limit: int = 0,
        prefs_js: Optional[str] = None,
        extension: Optional[str] = None,
    ) -> None:
        """Launch a new browser process.

        Args:
            bin_path: Path to the Firefox binary.
            env_mod: Environment modifier. Add, remove and update entries
                     in the prepared environment. Add and update by
                     setting value (str) and remove by setting entry value to None.
            launch_timeout: Timeout in seconds for launching the browser.
            location: URL to navigate to after successfully launch of the browser.
            log_limit: Log file size limit in bytes. Browser will be
                       terminated if the log file exceeds the amount specified.
            memory_limit: Memory limit in bytes. Browser will be terminated
                          if its memory usage exceeds the amount specified.
            prefs_js: Path to a prefs.js file to install in the Firefox profile.
            extension: Path to an extension (or list of extension) to be installed.

        Returns:
            None
        """
        assert self._launches > -1, "clean_up() has been called"
        assert log_limit >= 0
        assert memory_limit >= 0
        if self._proc is not None:
            raise LaunchError("Process is already running")

        bin_path = abspath(bin_path)
        if not isfile(bin_path) or not access(bin_path, X_OK):
            raise OSError(f"{bin_path} is not an executable")
        # need the path to help find symbols
        self._bin_path = dirname(bin_path)

        LOG.debug("requested location: %r", location)
        if location is not None:
            if isfile(location):
                location = "///".join(
                    ["file:", pathname2url(realpath(location)).lstrip("/")]
                )
            elif re_match(r"http(s)?://", location, IGNORECASE) is None:
                raise OSError(f"Cannot find {location!r}")

        # create and modify a profile
        self.profile = create_profile(
            extension=extension,
            prefs_js=prefs_js,
            template=self._profile_template,
            working_path=self._working_path,
        )
        LOG.debug("using profile %r", self.profile)

        launch_timeout = max(launch_timeout, self.LAUNCH_TIMEOUT_MIN)
        LOG.debug("launch timeout: %d", launch_timeout)
        # clean up existing log files
        self._logs.reset()
        self.reason = None
        # performing the bootstrap helps guarantee that the browser
        # will be loaded and ready to accept input when launch() returns
        bootstrapper = Bootstrapper()
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
            append_prefs(self.profile, prefs)

            launch_args = [bootstrapper.location]
            is_windows = system().startswith("Windows")
            if is_windows:
                # disable launcher process
                launch_args.append("-no-deelevate")
                launch_args.append("-wait-for-browser")
            cmd = self.build_launch_cmd(bin_path, additional_args=launch_args)

            if self._dbg in (Debugger.PERNOSCO, Debugger.RR):
                if env_mod is None:
                    env_mod = dict()
                env_mod["_RR_TRACE_DIR"] = self._logs.add_path(self._logs.PATH_RR)
            elif self._dbg == Debugger.VALGRIND:
                if env_mod is None:
                    env_mod = dict()
                # https://developer.gimp.org/api/2.0/glib/glib-running.html#G_DEBUG
                env_mod["G_DEBUG"] = "gc-friendly"
                env_mod["MOZ_CRASHREPORTER_DISABLE"] = "1"

            # open logs
            self._logs.add_log("stdout")
            stderr = self._logs.add_log("stderr")
            stderr.write(f"[ffpuppet] Launch command: {' '.join(cmd)}\n\n".encode())
            stderr.flush()
            assert self._logs.working_path is not None
            sanitizer_logs = pathjoin(self._logs.working_path, self._logs.PREFIX_SAN)
            # launch the browser
            LOG.debug("launch command: %r", " ".join(cmd))
            # pylint: disable=consider-using-with
            self._proc = Popen(
                cmd,
                bufsize=0,  # unbuffered (for log scanners)
                creationflags=CREATE_NEW_PROCESS_GROUP if is_windows else 0,
                env=prepare_environment(
                    self._bin_path, sanitizer_logs, env_mod=env_mod
                ),
                shell=False,
                stderr=stderr,
                stdout=self._logs.get_fp("stdout"),
            )
            LOG.debug("launched process %r", self.get_pid())
            bootstrapper.wait(self.is_healthy, timeout=launch_timeout, url=location)
        finally:
            bootstrapper.close()
            if prefs_js is not None and isfile(
                pathjoin(self.profile, "Invalidprefs.js")
            ):
                raise InvalidPrefs(f"{prefs_js!r} is invalid")

        logs_fp_stderr = self._logs.get_fp("stderr")
        assert logs_fp_stderr is not None
        logs_fp_stdout = self._logs.get_fp("stdout")
        assert logs_fp_stdout is not None
        if log_limit:
            self._checks.append(
                CheckLogSize(
                    log_limit,
                    logs_fp_stderr.name,
                    logs_fp_stdout.name,
                )
            )
        if memory_limit:
            curr_pid = self.get_pid()
            assert curr_pid is not None
            self._checks.append(CheckMemoryUsage(curr_pid, memory_limit))
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

    def log_length(self, log_id: str) -> Optional[int]:
        """Get the length of the selected browser log.

        Args:
            log_id: ID (key) of the log (stderr, stdout... etc).

        Returns:
            Length of the log in bytes.
        """
        return self._logs.log_length(log_id)

    def save_logs(self, dest: str, logs_only: bool = False, meta: bool = False) -> None:
        """The browser logs will be saved to dest. This can only be called
        after close().

        Args:
            dest: Destination path for log data. Existing files will
                        be overwritten.
            logs_only: Do not include other data such as debugger
                              output files.
            meta: Output JSON file containing log file meta data.

        Returns:
            None
        """
        LOG.debug("save_logs(%r, logs_only=%r, meta=%r)", dest, logs_only, meta)
        assert self._launches > -1, "clean_up() has been called"
        assert self._logs.closed, "Logs are still in use. Call close() first!"
        self._logs.save_logs(
            dest,
            logs_only=logs_only,
            meta=meta,
            bin_path=self._bin_path,
            rr_pack=self._dbg in (Debugger.PERNOSCO, Debugger.RR),
        )

    def wait(self, timeout: Optional[float] = None) -> bool:
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
        pid = self.get_pid()
        if pid is None or not wait_procs(get_processes(pid), timeout=timeout)[1]:
            return True
        LOG.debug("wait(timeout=%0.2f) timed out", timeout)
        return False
