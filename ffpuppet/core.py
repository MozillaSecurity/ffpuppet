# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from logging import getLogger
from os import access, getenv, listdir, stat, X_OK
from os.path import abspath, basename, dirname, isfile, join as pathjoin, realpath
from platform import system
from re import compile as re_compile, match as re_match, IGNORECASE
from shutil import rmtree
from subprocess import check_output, Popen
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
    append_prefs, create_profile, get_processes, onerror,
    prepare_environment, wait_on_files)
from .minidump_parser import process_minidumps
from .puppet_logger import PuppetLogger

LOG = getLogger(__name__)

__author__ = "Tyson Smith"
__all__ = ("FFPuppet",)


class FFPuppet(object):  # pylint: disable=too-many-instance-attributes
    DBG_NONE = 0
    DBG_GDB = 1
    DBG_RR = 2
    DBG_VALGRIND = 3
    LAUNCH_TIMEOUT_MIN = 10  # minimum amount of time to wait for the browser to launch
    RC_ALERT = "ALERT"  # target crashed/aborted/triggered an assertion failure etc...
    RC_CLOSED = "CLOSED"  # target was closed by call to FFPuppet close()
    RC_EXITED = "EXITED"  # target exited
    RC_WORKER = "WORKER"  # target was closed by worker thread
    VALGRIND_MIN_VERSION = 3.14  # minimum allowed version of Valgrind

    __slots__ = ("_abort_tokens", "_bin_path", "_checks", "_dbg",  "_launches",
                 "_logs", "_proc", "_profile_template", "_xvfb", "profile", "reason")

    def __init__(self, use_profile=None, use_valgrind=False, use_xvfb=False, use_gdb=False, use_rr=False):
        self._abort_tokens = set()  # tokens used to notify log scanner to kill the browser process
        self._bin_path = None
        self._checks = list()
        assert sum((use_gdb, use_rr, use_valgrind)) < 2, "multiple debuggers enabled"
        if use_gdb:
            self._dbg = self.DBG_GDB
        elif use_rr:
            self._dbg = self.DBG_RR
        elif use_valgrind:
            self._dbg = self.DBG_VALGRIND
        else:
            self._dbg = self.DBG_NONE
        self._dbg_sanity_check(self._dbg)
        self._launches = 0  # number of successful browser launches
        self._logs = PuppetLogger()
        self._proc = None
        self._profile_template = use_profile  # profile that is used as a template
        self._xvfb = None
        self.profile = None  # path to profile
        self.reason = self.RC_CLOSED  # why the target process was terminated

        if use_xvfb:
            if not system().startswith("Linux"):
                self._logs.close()
                raise EnvironmentError("Xvfb is only supported on Linux")
            try:
                self._xvfb = Xvfb(width=1280, height=1024)
            except NameError:
                self._logs.close()
                raise EnvironmentError("Please install xvfbwrapper") from None
            self._xvfb.start()


    def __enter__(self):
        return self


    def __exit__(self, *exc):
        self.clean_up()


    @classmethod
    def _dbg_sanity_check(cls, dbg_id):
        """Check requested debugger is supported and available.

        Args:
            dbg_id (int): Debugger to sanity check.

        Returns:
            None
        """
        if dbg_id == cls.DBG_GDB:
            if not system().startswith("Linux"):
                raise EnvironmentError("GDB is only supported on Linux")
            try:
                check_output(["gdb", "--version"])
            except OSError:
                raise EnvironmentError("Please install GDB") from None
        elif dbg_id == cls.DBG_RR:
            if not system().startswith("Linux"):
                raise EnvironmentError("rr is only supported on Linux")
            try:
                check_output(["rr", "--version"])
            except OSError:
                raise EnvironmentError("Please install rr") from None
        elif dbg_id == cls.DBG_VALGRIND:
            if not system().startswith("Linux"):
                raise EnvironmentError("Valgrind is only supported on Linux")
            try:
                match = re_match(
                    b"valgrind-(?P<ver>\\d+\\.\\d+)",
                    check_output(["valgrind", "--version"]))
            except OSError:
                raise EnvironmentError("Please install Valgrind") from None
            if not match or float(match.group("ver")) < cls.VALGRIND_MIN_VERSION:
                raise EnvironmentError("Valgrind >= %0.2f is required" % cls.VALGRIND_MIN_VERSION)


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


    def clone_log(self, log_id, offset=None, target_file=None):
        """Create a copy of the selected browser log.

        Args:
            log_id (str): ID (key) of the log to clone (stderr, stdout... etc).
            target_file (str): The log contents will be saved to target_file.
            offset (int):

        Returns:
            str: Name of the file containing the cloned log or None on failure.
        """
        return self._logs.clone_log(log_id, offset=offset, target_file=target_file)


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
            LOG.debug("reason is set to %r", self.reason)
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


    def _crashreports(self, skip_md=False):
        """Collect crash logs/reports.

        Args:
            skip_md (bool): Do not scan for minidumps.

        Yields:
            str: Path to log on the filesystem.
        """
        assert self._logs is not None
        try:
            files = listdir(self._logs.working_path)
        except OSError:  # pragma: no cover
            files = tuple()
        for fname in files:
            # scan for sanitizer logs
            if fname.startswith(self._logs.PREFIX_SAN):
                full_name = pathjoin(self._logs.working_path, fname)
                size = self._logs.watching.get(full_name)
                # skip previously scanned files that have not been updated
                if size is not None and size == stat(full_name).st_size:
                    continue
                try:
                    # WARNING: cannot open files that are already open on Windows
                    with open(full_name, "rb") as log_fp:
                        # NOTE: add only benign single line warnings here
                        for line in log_fp:
                            line = line.rstrip()
                            if not line:
                                continue
                            # entries to ignores
                            if line.endswith(b"==WARNING: Symbolizer buffer too small"):
                                # frequently emitted by TSan
                                continue
                            break
                        else:
                            self._logs.watching[full_name] = log_fp.tell()
                            continue
                except OSError:
                    LOG.debug("failed to scan log %r", full_name)
                yield full_name
            # scan for Valgrind logs
            elif self._dbg == self.DBG_VALGRIND and fname.startswith(self._logs.PREFIX_VALGRIND):
                full_name = pathjoin(self._logs.working_path, fname)
                if stat(full_name).st_size:
                    yield full_name
        # check for minidumps
        if not skip_md:
            assert self.profile is not None
            md_path = pathjoin(self.profile, "minidumps")
            try:
                files = listdir(md_path)
            except OSError:
                files = tuple()
            for fname in files:
                if ".dmp" in fname:
                    yield pathjoin(md_path, fname)


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
        self._logs.save_logs(dest, logs_only=logs_only, meta=meta)


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
        LOG.debug("_terminate(%d, retry_delay=%0.2f, start_mode=%d)",
                  pid, retry_delay, start_mode)
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
                    LOG.warning("Failed to terminate process %d (%s)",
                                proc.pid, proc.name())
                except (AccessDenied, NoSuchProcess):  # pragma: no cover
                    pass
            raise TerminateError("Failed to terminate browser")


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
        crash_reports = set(self._crashreports())
        if crash_reports:
            r_code = self.RC_ALERT
            while True:
                LOG.debug("%d crash report(s) found", len(crash_reports))
                # wait until crash report files are closed
                report_wait = 300 if self._dbg == self.DBG_RR else 90
                if not wait_on_files(procs, crash_reports, timeout=report_wait):
                    LOG.warning("Crash reports still open after %ds", report_wait)
                    break
                new_reports = set(self._crashreports())
                # verify no new reports have appeared
                if not new_reports - crash_reports:
                    break
                LOG.debug("more reports have appeared")
                crash_reports = new_reports
        elif self.is_running():
            r_code = self.RC_CLOSED
        elif self._proc.poll() not in (0, -1, 1, -2):
            r_code = self.RC_ALERT
            LOG.debug("poll() returned %r", self._proc.poll())
        else:
            r_code = self.RC_EXITED
        # close processes
        if self.is_running():
            LOG.debug("browser needs to be terminated")
            # when running under a debugger be less aggressive
            self._terminate(pid, start_mode=1 if self._dbg == self.DBG_NONE else 0)
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
                        r_code = self.RC_WORKER
                        check.dump_log(dst_fp=self._logs.add_log("ffp_worker_%s" % check.name))
                # collect logs (excluding minidumps)
                for fname in self._crashreports(skip_md=True):
                    self._logs.add_log(basename(fname), open(fname, "rb"))
                # check for minidumps in the profile and dump them if possible
                process_minidumps(
                    pathjoin(self.profile, "minidumps"),
                    pathjoin(self._bin_path, "symbols"),
                    self._logs.add_log)
                if self._logs.get_fp("stderr"):
                    self._logs.get_fp("stderr").write(
                        ("[ffpuppet] Reason code: %s\n" % r_code).encode("utf-8"))
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
            LOG.debug("exit reason code %r", r_code)
            self.reason = r_code


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


    def build_launch_cmd(self, bin_path, additional_args=None):
        """Build a command that can be used to launch the browser.

        Args:
            bin_path (str): Path to the browser binary.
            additional_args (list): Additional arguments to pass to the browser.

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

        if self._dbg == self.DBG_VALGRIND:
            valgrind_cmd = [
                "valgrind",
                "-q",
                "--error-exitcode=99",
                "--exit-on-first-error=yes",
                "--expensive-definedness-checks=yes",
                "--fair-sched=try",
                "--gen-suppressions=all",
                "--leak-check=no",
                "--log-file=%s.%%p" % pathjoin(self._logs.working_path, self._logs.PREFIX_VALGRIND),
                "--read-inline-info=no",
                "--show-mismatched-frees=no",
                "--show-possibly-lost=no",
                "--smc-check=all-non-file",
                "--trace-children=yes",
                "--trace-children-skip=python*",
                "--track-origins=yes",
                "--vex-iropt-register-updates=allregs-at-mem-access"]

            sup_file = getenv("VALGRIND_SUP_PATH")
            if sup_file:
                if not isfile(sup_file):
                    raise IOError("Missing Valgrind suppressions %r" % sup_file)
                LOG.debug("using Valgrind suppressions: %r", sup_file)
                valgrind_cmd.append("--suppressions=%s" % sup_file)

            cmd = valgrind_cmd + cmd

        elif self._dbg == self.DBG_GDB:
            cmd = [
                "gdb",
                "-nx",
                "-x", abspath(pathjoin(dirname(__file__), "cmds.gdb")),
                "-ex", "run",
                "-ex", "print $_siginfo",
                "-ex", "info locals",
                "-ex", "info registers",
                "-ex", "backtrace full",
                "-ex", "disassemble",
                "-ex", "symbol-file",
                #"-ex", "symbol-file %s",
                "-ex", "sharedlibrary",
                "-ex", "info proc mappings",
                "-ex", "info threads",
                "-ex", "shared",
                "-ex", "info sharedlibrary",
                #"-ex", "init-if-undefined $_exitcode = -1", # windows
                #"-ex", "quit $_exitcode", # windows
                "-ex", "quit_with_code",
                "-return-child-result",
                "-batch",
                "--args"] + cmd

        elif self._dbg == self.DBG_RR:
            cmd = [
                "rr", "record",
                "--disable-cpuid-features-ext", "0xdc230000,0x2c42,0xc"  # Pernosco support
            ] + cmd

        return cmd


    def launch(self, bin_path, env_mod=None, launch_timeout=300, location=None, log_limit=0,
               memory_limit=0, prefs_js=None, extension=None):
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
                    ["file:", pathname2url(realpath(location)).lstrip("/")])
            elif re_match(r"http(s)?://", location, IGNORECASE) is None:
                raise IOError("Cannot find %r" % location)

        # create and modify a profile
        self.profile = create_profile(
            extension=extension,
            prefs_js=prefs_js,
            template=self._profile_template)
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
            prefs = {
                "capability.policy.policynames": "'localfilelinks'",
                "capability.policy.localfilelinks.sites": "'%s'" % bootstrapper.location,
                "capability.policy.localfilelinks.checkloaduri.enabled": "'allAccess'",
                "privacy.partition.network_state": "false"}
            if self._dbg in (self.DBG_RR, self.DBG_VALGRIND):
                # when the browser is running slowly socket reads can fail if this is > 0
                prefs["network.http.speculative-parallel-limit"] = "0"
            append_prefs(self.profile, prefs)

            launch_args = [bootstrapper.location]
            is_windows = system().startswith("Windows")
            if is_windows:
                # disable launcher process
                launch_args.append("-no-deelevate")
                launch_args.append("-wait-for-browser")
            cmd = self.build_launch_cmd(bin_path, additional_args=launch_args)

            if self._dbg == self.DBG_RR:
                if env_mod is None:
                    env_mod = dict()
                env_mod["_RR_TRACE_DIR"] = self._logs.add_path(self._logs.PATH_RR)
            elif self._dbg == self.DBG_VALGRIND:
                if env_mod is None:
                    env_mod = dict()
                # https://developer.gimp.org/api/2.0/glib/glib-running.html#G_DEBUG
                env_mod["G_DEBUG"] = "gc-friendly"
                env_mod["MOZ_AVOID_OPENGL_ALTOGETHER"] = "1"
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
            self._proc = Popen(
                cmd,
                bufsize=0,  # unbuffered (for log scanners)
                creationflags=CREATE_NEW_PROCESS_GROUP if is_windows else 0,
                env=prepare_environment(self._bin_path, sanitizer_logs, env_mod=env_mod),
                shell=False,
                stderr=stderr,
                stdout=self._logs.get_fp("stdout"))
            LOG.debug("launched process %r", self.get_pid())
            bootstrapper.wait(self.is_healthy, timeout=launch_timeout, url=location)
        finally:
            bootstrapper.close()
            if prefs_js is not None and isfile(pathjoin(self.profile, "Invalidprefs.js")):
                raise InvalidPrefs("%r is invalid" % prefs_js)

        if log_limit:
            self._checks.append(CheckLogSize(
                log_limit,
                self._logs.get_fp("stderr").name,
                self._logs.get_fp("stdout").name))
        if memory_limit:
            self._checks.append(CheckMemoryUsage(self.get_pid(), memory_limit))
        if self._abort_tokens:
            self._checks.append(CheckLogContents(
                [self._logs.get_fp("stderr").name, self._logs.get_fp("stdout").name],
                self._abort_tokens))

        self._launches += 1


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
