# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import platform
import re
import shutil
import subprocess
import sys

try:  # py 2-3 compatibility
    from urllib import pathname2url  # pylint: disable=no-name-in-module
except ImportError:
    from urllib.request import pathname2url  # pylint: disable=no-name-in-module,import-error

import psutil
try:
    import xvfbwrapper
except ImportError:
    pass

from .checks import CheckLogContents, CheckLogSize, CheckMemoryUsage
from .exceptions import InvalidPrefs, LaunchError, TerminateError
from .helpers import (
    append_prefs, Bootstrapper, create_profile, get_processes, onerror,
    prepare_environment, wait_on_files)
from .minidump_parser import process_minidumps
from .puppet_logger import PuppetLogger

log = logging.getLogger("ffpuppet")  # pylint: disable=invalid-name

__author__ = "Tyson Smith"
__all__ = ("FFPuppet",)


class FFPuppet(object):  # pylint: disable=too-many-instance-attributes
    LAUNCH_TIMEOUT_MIN = 10  # minimum amount of time to wait for the browser to launch
    RC_ALERT = "ALERT"  # target crashed/aborted/triggered an assertion failure etc...
    RC_CLOSED = "CLOSED"  # target was closed by call to FFPuppet close()
    RC_EXITED = "EXITED"  # target exited
    RC_WORKER = "WORKER"  # target was closed by worker thread
    VALGRIND_MIN_VERSION = 3.14  # minimum allowed version of Valgrind

    def __init__(self, use_profile=None, use_valgrind=False, use_xvfb=False, use_gdb=False, use_rr=False):
        self._abort_tokens = set()  # tokens used to notify log scanner to kill the browser process
        self._checks = list()
        self._last_bin_path = None
        self._launches = 0  # number of successful browser launches
        self._logs = PuppetLogger()
        self._proc = None
        self._profile_template = use_profile  # profile that is used as a template
        self._use_valgrind = use_valgrind
        self._use_gdb = use_gdb
        self._use_rr = use_rr
        self._xvfb = None
        self.profile = None  # path to profile
        self.reason = self.RC_CLOSED  # why the target process was terminated

        plat = platform.system().lower()
        if use_valgrind:
            assert not (use_gdb or use_rr), "only a single debugger can be enabled"
            if not plat.startswith("linux"):
                raise EnvironmentError("Valgrind is only supported on Linux")
            try:
                match = re.match(
                    b"valgrind-(?P<ver>\\d+\\.\\d+)",
                    subprocess.check_output(["valgrind", "--version"]))
            except OSError:
                raise EnvironmentError("Please install Valgrind")
            if not match or float(match.group("ver")) < FFPuppet.VALGRIND_MIN_VERSION:
                raise EnvironmentError("Valgrind >= %0.2f is required" % FFPuppet.VALGRIND_MIN_VERSION)

        if use_gdb:
            assert not (use_rr or use_valgrind), "only a single debugger can be enabled"
            if not plat.startswith("linux"):
                raise EnvironmentError("GDB is only supported on Linux")
            try:
                subprocess.check_output(["gdb", "--version"])
            except OSError:
                raise EnvironmentError("Please install GDB")

        if use_rr:
            assert not (use_gdb or use_valgrind), "only a single debugger can be enabled"
            if not plat.startswith("linux"):
                raise EnvironmentError("rr is only supported on Linux")
            try:
                subprocess.check_output(["rr", "--version"])
            except OSError:
                raise EnvironmentError("Please install rr")

        if use_xvfb:
            if not plat.startswith("linux"):
                raise EnvironmentError("Xvfb is only supported on Linux")
            try:
                self._xvfb = xvfbwrapper.Xvfb(width=1280, height=1024)
            except NameError:
                raise EnvironmentError("Please install xvfbwrapper")
            self._xvfb.start()


    def add_abort_token(self, token):
        """
        Add a token that when present in the browser log will have the browser process terminated.

        @type token: String
        @param token: String to search for in the browser log.

        @rtype: None
        @return: None
        """
        assert isinstance(token, str)
        self._abort_tokens.add(re.compile(token))


    def available_logs(self):
        """
        List of IDs for the currently available logs.

        @rtype: list
        @return: A list containing 'log_id's
        """
        return self._logs.available_logs()


    def clone_log(self, log_id, offset=None, target_file=None):
        """
        Create a copy of the current browser log.

        @type log_id: String
        @param log_id: The id (key) of the log to clone (stderr, stdout... etc).

        @type target_file: String
        @param target_file: The log contents will be saved to target_file.

        @type offset: int
        @param offset: Where to begin reading the log from

        @rtype: String or None
        @return: Name of the file containing the cloned log or None on failure
        """
        return self._logs.clone_log(log_id, offset=offset, target_file=target_file)


    def is_healthy(self):
        """
        Verify the browser is in a known good state by performing a series
        of checks.

        @rtype: bool
        @return: True if the browser is running and determined to be
                 in a valid functioning state otherwise False.
        """
        if self.reason is not None:
            log.debug("reason is set to %r", self.reason)
            return False
        if not self.is_running():
            log.debug("is_running() returned False")
            return False
        if any(self._crashreports()):
            log.debug("crash report found")
            return False
        for check in self._checks:
            if check.check():
                log.debug("%r check abort conditions met", check.name)
                return False
        return True


    def _crashreports(self, skip_md=False):
        # check for *San and Valgrind logs
        if os.path.isdir(self._logs.working_path):
            for fname in os.listdir(self._logs.working_path):
                if fname.startswith(self._logs.PREFIX_SAN):
                    yield os.path.join(self._logs.working_path, fname)
                elif self._use_valgrind and fname.startswith(self._logs.PREFIX_VALGRIND):
                    full_name = os.path.join(self._logs.working_path, fname)
                    if os.stat(full_name).st_size:
                        yield full_name

        # check for minidumps
        if not skip_md:
            md_path = os.path.join(self.profile, "minidumps")
            if os.path.isdir(md_path):
                for fname in os.listdir(md_path):
                    if ".dmp" in fname:
                        yield os.path.join(md_path, fname)


    def log_length(self, log_id):
        """
        Get the length of the current browser log.

        @type log_id: String
        @param log_id: The id (key) of the log to clone (stderr, stdout... etc).

        @rtype: int
        @return: length of the current browser log in bytes.
        """
        return self._logs.log_length(log_id)


    def save_logs(self, dest, logs_only=False, meta=False):
        """
        The browser logs will be saved to dest.
        This should only be called after close().

        @type dest: String
        @param dest: Destination path for log data. Existing files will be overwritten.

        @type logs_only: bool
        @param logs_only: Do not include other data, including debugger output files.

        @type meta: bool
        @param meta: Output JSON file containing log file meta data.

        @rtype: None
        @return: None
        """

        log.debug("save_logs() called, dest=%r, logs_only=%r, meta=%r", dest, logs_only, meta)
        assert self._launches > -1, "clean_up() has been called"
        assert self._logs.closed, "Logs are still in use. Call close() first!"

        self._logs.save_logs(dest, logs_only=logs_only, meta=meta)


    def clean_up(self):
        """
        Remove all remaining files created during execution.
        This will clear some state information and should only be called once
        the FFPuppet object is no longer needed. Using the FFPuppet object after
        calling clean_up() is not supported.

        @rtype: None
        @return: None
        """

        if self._launches < 0:
            log.debug("clean_up() call ignored")
            return

        log.debug("clean_up() called")
        self.close(force_close=True)
        self._logs.clean_up(ignore_errors=True)

        # close Xvfb
        if self._xvfb is not None:
            self._xvfb.stop()
            self._xvfb = None

        # at this point everything should be cleaned up
        assert self.reason is not None, "self.reason is None"
        assert self._logs.closed, "self._logs.closed is not True"
        assert self._proc is None, "self._proc is not None"
        assert self.profile is None, "self.profile is not None"

        # negative 'self._launches' indicates clean_up() has been called
        self._launches = -1


    @staticmethod
    def _terminate(pid, kill_delay=30):
        log.debug("_terminate(%d, kill_delay=%0.2f)", pid, kill_delay)
        procs = get_processes(pid)
        mode = 0
        while mode < 2:
            log.debug("%d running process(es)", len(procs))
            # iterate over and terminate/kill processes
            for proc in procs:
                try:
                    proc.kill() if mode > 0 else proc.terminate()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
            procs = psutil.wait_procs(procs, timeout=kill_delay)[1]
            if not procs:
                log.debug("_terminate() was successful")
                break
            log.debug("timed out (%0.2f), mode %d", kill_delay, mode)
            mode += 1
        else:
            for proc in procs:
                try:
                    log.warning("Failed to terminate process %d (%s)", proc.pid, proc.name())
                except (psutil.AccessDenied, psutil.NoSuchProcess):  # pragma: no cover
                    pass
            raise TerminateError("Failed to terminate browser")


    def close(self, force_close=False):
        """
        Terminate the browser process and clean up all processes.

        @type force_close: bool
        @param force_close: Do not collect logs... etc, just make sure everything is closed

        @rtype: None
        @return: None
        """

        log.debug("close(force_close=%r) called", force_close)
        assert self._launches > -1, "clean_up() has been called"
        if self.reason is not None:
            self._logs.close()  # make sure browser logs are also closed
            return

        if self._proc is not None:
            log.debug("browser pid: %r", self._proc.pid)
            crash_reports = set(self._crashreports())
            # set reason code
            if crash_reports:
                r_code = self.RC_ALERT
            elif self.is_running():
                r_code = self.RC_CLOSED
            else:
                r_code = self.RC_EXITED

            while crash_reports:
                log.debug("%d crash report(s) are available", len(crash_reports))
                # wait until all open files are closed (except stdout & stderr)
                report_wait = 300 if self._use_rr else 90
                if not wait_on_files(crash_reports, timeout=report_wait):
                    log.warning("wait_on_files() Timed out")
                    break
                new_reports = set(self._crashreports())
                # verify no new reports have appeared
                if not new_reports - crash_reports:
                    break
                log.debug("more reports have appeared")
                crash_reports = new_reports

            # terminate the browser process if needed
            if self.wait(timeout=0) is None:
                log.debug("browser needs to be terminated")
                self._terminate(self._proc.pid)
                # wait for reports triggered by the call to _terminate()
                wait_on_files(self._crashreports(), timeout=10)

            # check the process exit code if needed
            if r_code == self.RC_EXITED and self._proc.poll() not in (0, -1, 1):
                log.debug("poll() returned %r", self._proc.poll())
                r_code = self.RC_ALERT
        else:
            r_code = self.RC_CLOSED
            log.debug("browser process was 'None'")

        if not force_close:
            log.debug("reviewing %d check(s)", len(self._checks))
            for check in self._checks:
                if check.message is not None:
                    r_code = self.RC_WORKER
                    check.dump_log(dst_fp=self._logs.add_log("ffp_worker_%s" % check.name))

            # collect logs (excluding minidumps)
            for fname in self._crashreports(skip_md=True):
                self._logs.add_log(os.path.basename(fname), open(fname, "rb"))
            # check for minidumps in the profile and dump them if possible
            if self.profile is not None:
                process_minidumps(
                    os.path.join(self.profile, "minidumps"),
                    os.path.join(self._last_bin_path, "symbols"),
                    self._logs.add_log)
            if self._logs.get_fp("stderr"):
                self._logs.get_fp("stderr").write(
                    ("[ffpuppet] Reason code: %s\n" % r_code).encode("utf-8"))

        self._proc = None
        self._logs.close()
        self._checks = list()
        # remove temporary profile directory if necessary
        if self.profile is not None and os.path.isdir(self.profile):
            shutil.rmtree(self.profile, onerror=onerror)
            self.profile = None
        log.debug("exit reason code %r", r_code)
        if self.reason is None:
            self.reason = r_code


    @property
    def launches(self):
        """
        Get the number of successful launches

        @rtype: int
        @return: successful launch count
        """
        assert self._launches > -1, "clean_up() has been called"
        return self._launches


    def get_pid(self):
        """
        Get the browser process ID

        @rtype: int
        @return: browser process ID
        """
        try:
            return self._proc.pid
        except AttributeError:
            return None


    def build_launch_cmd(self, bin_path, additional_args=None):
        """
        Build a command that can be used to launch the browser.

        @type bin_path: String
        @param bin_path: Path to the Firefox binary

        @type additional_args: list
        @param additional_args: Additional arguments passed to Firefox.

        @rtype: list
        @return: List of arguments that make up the launch command
        """

        assert isinstance(bin_path, str), "bin_path must be 'str'"

        # if a python script is passed use 'sys.executable' as the binary
        # this is used by the test framework
        if bin_path.lower().endswith(".py"):
            cmd = [sys.executable]
        else:
            cmd = []

        cmd += [bin_path, "-no-remote"]
        if self.profile is not None:
            cmd += ["-profile", self.profile]

        if additional_args:
            assert isinstance(additional_args, list), "additional_args must be 'list'"
            for add_arg in additional_args:
                assert isinstance(add_arg, str), "additional arguments must be 'str'"
            cmd.extend(additional_args)

        if self._use_valgrind:
            valgrind_cmd = [
                "valgrind",
                "-q",
                "--error-exitcode=99",
                "--exit-on-first-error=yes",
                "--expensive-definedness-checks=yes",
                "--fair-sched=try",
                "--gen-suppressions=all",
                "--leak-check=no",
                "--log-file=%s.%%p" % os.path.join(self._logs.working_path, self._logs.PREFIX_VALGRIND),
                "--read-inline-info=no",
                "--show-mismatched-frees=no",
                "--show-possibly-lost=no",
                "--smc-check=all-non-file",
                "--trace-children=yes",
                "--track-origins=yes",
                "--vex-iropt-register-updates=allregs-at-mem-access"]

            sup_file = os.environ.get("VALGRIND_SUP_PATH", None)
            if sup_file:
                if not os.path.isfile(sup_file):
                    raise IOError("Missing Valgrind suppressions %r" % sup_file)
                log.debug("using Valgrind suppressions: %r", sup_file)
                valgrind_cmd.append("--suppressions=%s" % sup_file)

            cmd = valgrind_cmd + cmd

        elif self._use_gdb:
            cmd = [
                "gdb",
                "-nx",
                "-x", os.path.abspath(os.path.join(os.path.dirname(__file__), "cmds.gdb")),
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

        elif self._use_rr:
            cmd = ["rr", "record"] + cmd

        return cmd


    def launch(self, bin_path, env_mod=None, launch_timeout=300, location=None, log_limit=0,
               memory_limit=0, prefs_js=None, extension=None):
        """
        Launch a new browser process.

        @type bin_path: String
        @param bin_path: Path to the Firefox binary

        @type env_mod: dict
        @param env_mod: Environment modifier. Add, remove and update entries in the prepared
                        environment via this dict. Add and update using key, value pairs where
                        value is a string and to remove set the value to None. If it is None no
                        extra modifications are made.

        @type launch_timeout: int
        @param launch_timeout: Timeout in seconds for launching the browser

        @type location: String
        @param location: URL to navigate to after successfully starting up the browser

        @type log_limit: int
        @param log_limit: Log file size limit in bytes. Browser will be terminated if the log file
                          exceeds the amount specified here.

        @type memory_limit: int
        @param memory_limit: Memory limit in bytes. Browser will be terminated if its memory usage
                             exceeds the amount specified here.

        @type prefs_js: String
        @param prefs_js: Path to a prefs.js file to install in the Firefox profile.

        @type extension: String, or list of Strings
        @param extension: Path to an extension (e.g. DOMFuzz fuzzPriv extension) to be installed.

        @rtype: None
        @return: None
        """

        assert self._launches > -1, "clean_up() has been called"
        if self._proc is not None:
            raise LaunchError("Process is already running")

        bin_path = os.path.abspath(bin_path)
        if not os.path.isfile(bin_path) or not os.access(bin_path, os.X_OK):
            raise IOError("%s is not an executable" % bin_path)
        self._last_bin_path = os.path.dirname(bin_path)  # need the path for minidump_stackwalk

        log.debug("requested location: %r", location)
        if location is not None:
            if os.path.isfile(location):
                location = "///".join(
                    ["file:", pathname2url(os.path.realpath(location)).lstrip("/")])
            elif re.match(r"http(s)?://", location, re.IGNORECASE) is None:
                raise IOError("Cannot find %r" % location)

        self.reason = None
        log_limit = max(log_limit, 0)
        memory_limit = max(memory_limit, 0)
        launch_timeout = max(launch_timeout, self.LAUNCH_TIMEOUT_MIN)
        log.debug("launch timeout: %d", launch_timeout)

        # create and modify a profile
        self.profile = create_profile(
            extension=extension,
            prefs_js=prefs_js,
            template=self._profile_template)

        # performing the bootstrap helps guarantee that the browser
        # will be loaded and ready to accept input when launch() returns
        bootstrapper = Bootstrapper()
        try:
            prefs = {
                "capability.policy.policynames": "'localfilelinks'",
                "capability.policy.localfilelinks.sites": "'%s'" % bootstrapper.location,
                "capability.policy.localfilelinks.checkloaduri.enabled": "'allAccess'"}
            append_prefs(self.profile, prefs)

            launch_args = [bootstrapper.location]

            # clean up existing log files
            self._logs.reset()

            cmd = self.build_launch_cmd(bin_path, additional_args=launch_args)

            if self._use_rr:
                if env_mod is None:
                    env_mod = dict()
                env_mod["_RR_TRACE_DIR"] = self._logs.add_path(self._logs.PATH_RR)
            elif self._use_valgrind:
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
            sanitizer_logs = os.path.join(self._logs.working_path, self._logs.PREFIX_SAN)
            plat = platform.system().lower()
            # launch the browser
            log.debug("launch command: %r", " ".join(cmd))
            self._proc = subprocess.Popen(
                cmd,
                bufsize=0,  # unbuffered (for log scanners)
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if plat == "windows" else 0,
                env=prepare_environment(self._last_bin_path, sanitizer_logs, env_mod=env_mod),
                shell=False,
                stderr=stderr,
                stdout=self._logs.get_fp("stdout"))
            log.debug("launched firefox with pid: %d", self._proc.pid)
            bootstrapper.wait(self.is_healthy, timeout=launch_timeout, url=location)
        finally:
            bootstrapper.close()
            if prefs_js is not None and os.path.isfile(os.path.join(self.profile, "Invalidprefs.js")):
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
        """
        Check if the browser process is running.

        @rtype: bool
        @return: True if the process is running otherwise False
        """
        try:
            return self._proc.poll() is None
        except AttributeError:
            return False


    def wait(self, timeout=None):
        """
        Wait for process and children to terminate. This call will block until the process exits
        unless a timeout is specified. If a timeout of zero or greater is specified the call will
        only block until the timeout expires.

        @type timeout: float, int or None
        @param timeout: maximum amount of time to wait for process to terminate
                        or None (wait indefinitely)

        @rtype: int or None
        @return: exit code of process if it exits and None if timeout expired or the process does
                 not exist
        """
        assert timeout is None or timeout >= 0
        try:
            # check if the parent process is running before performing lookup
            if self._proc.poll() is not None:
                return self._proc.returncode
            if not psutil.wait_procs(get_processes(self._proc.pid), timeout=timeout)[1]:
                return self._proc.poll()
            log.debug("wait(timeout=%0.2f) timed out", timeout)
        except AttributeError:
            # if close() called in parallel self._proc is set to None
            pass
        return None
