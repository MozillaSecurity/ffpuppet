# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet module"""

from enum import Enum, unique
from logging import getLogger
from os import X_OK, access, getenv, scandir
from os.path import abspath, basename, dirname, isfile
from os.path import join as pathjoin
from os.path import realpath
from platform import system
from re import IGNORECASE
from re import compile as re_compile
from re import match as re_match
from shutil import rmtree
from subprocess import Popen, check_output

try:
    from subprocess import CREATE_NEW_PROCESS_GROUP
except ImportError:
    pass
from sys import executable
from urllib.request import pathname2url

from psutil import AccessDenied, NoSuchProcess, wait_procs

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

    NONE = 0
    GDB = 1
    PERNOSCO = 2
    RR = 3
    VALGRIND = 4


@unique
class Reason(Enum):
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

    Attributes:
        debugger (Debugger): Debugger to use.
        use_profile (str): Path to existing user profile.
        use_xvfb (bool): Use Xvfb.
        working_path (str): Path to use as base directory for temporary files.
    """

    LAUNCH_TIMEOUT_MIN = 10  # minimum amount of time to wait for the browser to launch
    VALGRIND_MIN_VERSION = 3.14  # minimum allowed version of Valgrind

    __slots__ = (
        "_abort_tokens",
        "_bin_path",
        "_checks",
        "_dbg",
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
        debugger=Debugger.NONE,
        use_profile=None,
        use_xvfb=False,
        working_path=None,
    ):
        # tokens used to notify log scanner to kill the browser process
        self._abort_tokens = set()
        self._bin_path = None
        self._checks = list()
        self._dbg = debugger
        self._dbg_sanity_check(self._dbg)
        self._launches = 0  # number of successful browser launches
        self._logs = PuppetLogger(base_path=working_path)
        self._proc = None
        self._profile_template = use_profile  # profile that is used as a template
        self._xvfb = None
        self._working_path = working_path
        self.profile = None  # path to profile
        self.reason = Reason.CLOSED

        if use_xvfb:
            if not system().startswith("Linux"):
                self._logs.clean_up(ignore_errors=True)
                raise EnvironmentError("Xvfb is only supported on Linux")
            try:
                self._xvfb = Xvfb(width=1280, height=1024)
            except NameError:
                self._logs.clean_up(ignore_errors=True)
                raise EnvironmentError("Please install xvfbwrapper") from None
            self._xvfb.start()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.clean_up()

    def _crashreports(self, skip_md=False, skip_benign=True):
        """Collect crash logs/reports.

        Args:
            skip_md (bool): Do not scan for minidumps.
            skip_benign (bool): Skip reports that only contain benign non-fatal
                                warnings.

        Yields:
            str: Path to log on the filesystem.
        """
        assert self._logs is not None
        try:
            contents = scandir(self._logs.working_path)
        except OSError:  # pragma: no cover
            contents = tuple()
        for entry in contents:
            # scan for sanitizer logs
            if entry.name.startswith(self._logs.PREFIX_SAN):
                if skip_benign:
                    size = self._logs.watching.get(entry.path)
                    # skip previously scanned files that have not been updated
                    if size is not None and size == entry.stat().st_size:
                        continue
                    try:
                        # WARNING: cannot open files that are already open on Windows
                        with open(entry.path, "rb") as log_fp:
                            # NOTE: add only benign single line warnings here
                            # This should not include any fatal errors
                            for line in log_fp:
                                line = line.rstrip()
                                if not line:
                                    continue
                                # entries to ignores
                                if line.endswith(
                                    b"==WARNING: Symbolizer buffer too small"
                                ):
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
                                # the file contains something interesting
                                break
                            else:
                                self._logs.watching[entry.path] = log_fp.tell()
                                LOG.debug("benign log has changed %r", entry.path)
                                continue
                    except OSError:
                        LOG.debug("failed to scan log %r", entry.path)
                yield entry.path
            # scan for Valgrind logs
            elif self._dbg == Debugger.VALGRIND and entry.name.startswith(
                self._logs.PREFIX_VALGRIND
            ):
                if entry.stat().st_size:
                    yield entry.path
        # check for minidumps
        if not skip_md:
            assert self.profile is not None
            try:
                for entry in scandir(pathjoin(self.profile, "minidumps")):
                    if ".dmp" in entry.name:
                        yield entry.path
            except OSError:  # pragma: no cover
                pass

    @classmethod
    def _dbg_sanity_check(cls, dbg):
        """Check requested debugger is supported and available.

        Args:
            dbg (Debugger): Debugger to sanity check.

        Returns:
            None
        """
        LOG.debug("checking %s support", dbg)
        if dbg == Debugger.GDB:
            if not system().startswith("Linux"):
                raise EnvironmentError("GDB is only supported on Linux")
            try:
                check_output(["gdb", "--version"])
            except OSError:
                raise EnvironmentError("Please install GDB") from None
        elif dbg in (Debugger.PERNOSCO, Debugger.RR):
            if not system().startswith("Linux"):
                raise EnvironmentError("rr is only supported on Linux")
            try:
                check_output(["rr", "--version"])
            except OSError:
                raise EnvironmentError("Please install rr") from None
        elif dbg == Debugger.VALGRIND:
            if not system().startswith("Linux"):
                raise EnvironmentError("Valgrind is only supported on Linux")
            try:
                match = re_match(
                    b"valgrind-(?P<ver>\\d+\\.\\d+)",
                    check_output(["valgrind", "--version"]),
                )
            except OSError:
                raise EnvironmentError("Please install Valgrind") from None
            if not match or float(match.group("ver")) < cls.VALGRIND_MIN_VERSION:
                raise EnvironmentError(
                    "Valgrind >= %0.2f is required" % cls.VALGRIND_MIN_VERSION
                )

    @staticmethod
    def _terminate(pid, retry_delay=30, start_mode=0):
        """Terminate the process. Each mode (retry pass) is more aggressive.
        At the end of each attempt if there are active processes mode is
        incremented and another pass is performed.

        Mode:
        - 0: uses process.terminate() on the parent process only.
        - 1: uses process.terminate() on all processes.
        - 2: uses process.kill() on all processes.

        Args:
            retry_delay (int): Time in seconds to wait before next attempt.
            start_mode (int): Initial mode.

        Returns:
            None
        """
        LOG.debug(
            "_terminate(%d, retry_delay=%0.2f, start_mode=%d)",
            pid,
            retry_delay,
            start_mode,
        )
        procs = get_processes(pid)
        for mode in range(start_mode, 3):
            LOG.debug("%d running process(es)", len(procs))
            # iterate over and terminate/kill processes
            for proc in procs:
                try:
                    proc.kill() if mode > 1 else proc.terminate()
                except (AccessDenied, NoSuchProcess):  # pragma: no cover
                    pass
                if mode == 0:
                    # only target the parent process on the first pass
                    break
            procs = wait_procs(procs, timeout=retry_delay)[1]
            if not procs:
                LOG.debug("_terminate() was successful")
                break
            LOG.debug("timed out (%0.2f), mode %d", retry_delay, mode)
        else:
            for proc in procs:
                try:
                    LOG.warning(
                        "Failed to terminate process %d (%s)", proc.pid, proc.name()
                    )
                except (AccessDenied, NoSuchProcess):  # pragma: no cover
                    pass
            raise TerminateError("Failed to terminate browser")

    def add_abort_token(self, token):
        """Add a token that when present in the browser log will have the
        browser process terminated.

        Args:
            token (str): Value to search for in the browser logs.

        Returns:
            None
        """
        assert token and isinstance(token, str)
        self._abort_tokens.add(re_compile(token))

    def available_logs(self):
        """List of IDs for the currently available logs.

        Args:
            None

        Returns:
            list: A list contains log IDs (str).
        """
        return list(self._logs.available_logs())

    def build_launch_cmd(self, bin_path, additional_args=None):
        """Build a command that can be used to launch the browser.

        Args:
            bin_path (str): Path to the browser binary.
            additional_args (list(str)): Additional arguments to pass to the browser.

        Returns:
            list: List of arguments that make up the launch command.
        """
        assert isinstance(bin_path, str)

        # if a python script is passed use 'sys.executable' as the binary
        # this is used by the test framework
        cmd = list()
        if bin_path.lower().endswith(".py"):
            cmd.append(executable)
        cmd += [bin_path, "-no-remote"]
        if self.profile is not None:
            cmd += ["-profile", self.profile]

        if additional_args:
            assert isinstance(additional_args, list)
            assert all(isinstance(x, str) for x in additional_args)
            cmd.extend(additional_args)

        if self._dbg == Debugger.VALGRIND:
            valgrind_cmd = [
                "valgrind",
                "-q",
                "--error-exitcode=99",
                "--exit-on-first-error=yes",
                "--expensive-definedness-checks=yes",
                "--fair-sched=try",
                "--gen-suppressions=all",
                "--leak-check=no",
                "--log-file=%s.%%p"
                % pathjoin(self._logs.working_path, self._logs.PREFIX_VALGRIND),
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
                    raise IOError("Missing Valgrind suppressions %r" % sup_file)
                LOG.debug("using Valgrind suppressions: %r", sup_file)
                valgrind_cmd.append("--suppressions=%s" % sup_file)

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

    def clean_up(self):
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

    def clone_log(self, log_id, offset=None, target_file=None):
        """Create a copy of the selected browser log.

        Args:
            log_id (str): ID (key) of the log to clone (stderr, stdout... etc).
            target_file (str): The log contents will be saved to target_file.
            offset (int): Location to begin reading the file from.

        Returns:
            str: Name of the file containing the cloned log or None on failure.
        """
        return self._logs.clone_log(log_id, offset=offset, target_file=target_file)

    def close(self, force_close=False):
        """Terminate the browser process(es) and set `self.reason`. The reason
        code indicates how/why the browser process was terminated.

        Args:
            force_close (bool): Do not collect logs, etc, just make sure
                                everything is closed.

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
        # set reason code
        crash_reports = set(self._crashreports(skip_benign=True))
        if crash_reports:
            r_code = Reason.ALERT
            while True:
                LOG.debug("%d crash report(s) found", len(crash_reports))
                # wait until crash report files are closed
                report_wait = 300 if self._dbg == Debugger.RR else 90
                if not wait_on_files(procs, crash_reports, timeout=report_wait):
                    LOG.warning("Crash reports still open after %ds", report_wait)
                    break
                new_reports = set(self._crashreports(skip_benign=True))
                # verify no new reports have appeared
                if not new_reports - crash_reports:
                    break
                LOG.debug("more reports have appeared")
                crash_reports = new_reports
        elif self.is_running():
            r_code = Reason.CLOSED
        elif self._proc.poll() not in (0, -1, 1, -2):
            r_code = Reason.ALERT
            LOG.debug("poll() returned %r", self._proc.poll())
        else:
            r_code = Reason.EXITED
        # close processes
        if self.is_running():
            LOG.debug("browser needs to be terminated")
            # when running under a debugger be less aggressive
            self._terminate(pid, start_mode=1 if self._dbg == Debugger.NONE else 0)
        # wait for any remaining processes to close
        if wait_procs(procs, timeout=1 if force_close else 30)[1]:
            LOG.warning("Some browser processes are still running!")
        # collect crash logs
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
                            dst_fp=self._logs.add_log("ffp_worker_%s" % check.name)
                        )
                # collect logs (excluding minidumps)
                for fname in self._crashreports(skip_md=True, skip_benign=False):
                    # pylint: disable=consider-using-with
                    self._logs.add_log(basename(fname), open(fname, "rb"))
                # check for minidumps in the profile and dump them if possible
                process_minidumps(
                    pathjoin(self.profile, "minidumps"),
                    pathjoin(self._bin_path, "symbols"),
                    self._logs.add_log,
                    working_path=self._working_path,
                )
                if self._logs.get_fp("stderr"):
                    self._logs.get_fp("stderr").write(
                        ("[ffpuppet] Reason code: %s\n" % r_code.name).encode("utf-8")
                    )
        # reset remaining to closed state
        try:
            self._proc = None
            self._logs.close()
            self._checks = list()
            # remove temporary profile directory if necessary
            try:
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

    def cpu_usage(self):
        """Collect percentage of CPU usage per process.

        Args:
            None

        Yields:
            tuple: PID and the CPU usage as a percentage.
        """
        pid = self.get_pid()
        if pid is not None:
            for proc in get_processes(pid):
                try:
                    yield proc.pid, proc.cpu_percent(interval=0.1)
                except (AccessDenied, NoSuchProcess):  # pragma: no cover
                    continue

    def get_pid(self):
        """Get the browser process ID.

        Args:
            None

        Returns:
            int: Browser PID.
        """
        try:
            return self._proc.pid
        except AttributeError:
            return None

    def is_healthy(self):
        """Verify the browser is in a good state by performing a series
        of checks.

        Args:
            None

        Returns:
            bool: True if the browser is running and determined to be
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

    def is_running(self):
        """Check if the browser process is running.

        Args:
            None

        Returns:
            bool: True if the process is running otherwise False.
        """
        try:
            return self._proc.poll() is None
        except AttributeError:
            return False

    def launch(
        self,
        bin_path,
        env_mod=None,
        launch_timeout=300,
        location=None,
        log_limit=0,
        memory_limit=0,
        prefs_js=None,
        extension=None,
    ):
        """Launch a new browser process.

        Args:
            bin_path (str): Path to the Firefox binary.
            env_mod (dict): Environment modifier. Add, remove and update entries
                            in the prepared environment. Add and update by
                            setting value (str) and remove by setting entry
                            value to None.
            launch_timeout (int): Timeout in seconds for launching the browser.
            location (str): URL to navigate to after successfully launch of
                            the browser.
            log_limit (int): Log file size limit in bytes. Browser will be
                             terminated if the log file exceeds the amount
                             specified.
            memory_limit (int): Memory limit in bytes. Browser will be
                                terminated if its memory usage exceeds the
                                amount specified.
            prefs_js (str): Path to a prefs.js file to install in the Firefox
                            profile.
            extension (str): Path to an extension (or list of extension) to be
                             installed.

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
            raise IOError("%s is not an executable" % bin_path)
        # need the path to help find symbols
        self._bin_path = dirname(bin_path)

        LOG.debug("requested location: %r", location)
        if location is not None:
            if isfile(location):
                location = "///".join(
                    ["file:", pathname2url(realpath(location)).lstrip("/")]
                )
            elif re_match(r"http(s)?://", location, IGNORECASE) is None:
                raise IOError("Cannot find %r" % location)

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
            # added `network.proxy.failover_direct` to workaround
            # default prefs.js packaged with Grizzly test cases.
            # This can be removed in the future but for now it unblocks
            # reducing older Grizzly test cases.
            prefs = {
                "capability.policy.localfilelinks.checkloaduri.enabled": "'allAccess'",
                "capability.policy.localfilelinks.sites": "'%s'"
                % bootstrapper.location,
                "capability.policy.policynames": "'localfilelinks'",
                "network.proxy.failover_direct": "false",
                "privacy.partition.network_state": "false",
            }
            if self._dbg in (Debugger.PERNOSCO, Debugger.RR, Debugger.VALGRIND):
                # if the browser is running slowly socket reads can fail if this is > 0
                prefs["network.http.speculative-parallel-limit"] = "0"
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
            stderr.write(b"[ffpuppet] Launch command: ")
            stderr.write(" ".join(cmd).encode("utf-8"))
            stderr.write(b"\n\n")
            stderr.flush()
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
                raise InvalidPrefs("%r is invalid" % prefs_js)

        if log_limit:
            self._checks.append(
                CheckLogSize(
                    log_limit,
                    self._logs.get_fp("stderr").name,
                    self._logs.get_fp("stdout").name,
                )
            )
        if memory_limit:
            self._checks.append(CheckMemoryUsage(self.get_pid(), memory_limit))
        if self._abort_tokens:
            self._checks.append(
                CheckLogContents(
                    [
                        self._logs.get_fp("stderr").name,
                        self._logs.get_fp("stdout").name,
                    ],
                    self._abort_tokens,
                )
            )

        self._launches += 1

    @property
    def launches(self):
        """Number of successful launches.

        Args:
            None

        Returns:
            int: Successful launch count.
        """
        assert self._launches > -1, "clean_up() has been called"
        return self._launches

    def log_length(self, log_id):
        """Get the length of the selected browser log.

        Args:
            log_id (str): ID (key) of the log (stderr, stdout... etc).

        Returns:
            int: Length of the log in bytes.
        """
        return self._logs.log_length(log_id)

    def save_logs(self, dest, logs_only=False, meta=False):
        """The browser logs will be saved to dest. This can only be called
        after close().

        Args:
            dest (str): Destination path for log data. Existing files will
                        be overwritten.
            logs_only (bool): Do not include other data such as debugger
                              output files.
            meta (bool): Output JSON file containing log file meta data.

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

    def wait(self, timeout=None):
        """Wait for browser process(es) to terminate. This call will block until
        all process(es) exit unless a timeout is specified. If a timeout of zero
        or greater is specified the call will block until the timeout expires.

        Args:
            timeout (float): The maximum amount of time in seconds to wait or
                             None (wait indefinitely).

        Returns:
            bool: True if processes exit before timeout expires otherwise False.
        """
        assert timeout is None or timeout >= 0
        pid = self.get_pid()
        if pid is None or not wait_procs(get_processes(pid), timeout=timeout)[1]:
            return True
        LOG.debug("wait(timeout=%0.2f) timed out", timeout)
        return False
