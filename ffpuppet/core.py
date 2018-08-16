# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import errno
import logging
import os
import platform
import random
import re
import shutil
import socket
import subprocess
import time

try:  # py 2-3 compatibility
    from urllib import pathname2url  # pylint: disable=no-name-in-module
except ImportError:
    from urllib.request import pathname2url  # pylint: disable=no-name-in-module,import-error

import psutil
try:
    import xvfbwrapper
except ImportError:
    pass

from .helpers import create_profile, onerror, prepare_environment, wait_on_files
from .minidump_parser import process_minidumps
from .puppet_logger import PuppetLogger
from .workers import log_scanner, log_size_limiter, memory_limiter

log = logging.getLogger("ffpuppet")  # pylint: disable=invalid-name

__author__ = "Tyson Smith"
__all__ = ("FFPuppet", "BrowserTimeoutError", "BrowserTerminatedError", "LaunchError")


class LaunchError(Exception):
    """
    Raised when the browser process does not appear to be in a functional state during launch
    """
    pass

class BrowserTerminatedError(LaunchError):
    """
    Raised when the browser process goes away during launch
    """
    pass

class BrowserTimeoutError(LaunchError):
    """
    Raised when the browser process appears to hang during launch
    """
    pass


class FFPuppet(object):
    BS_PORT_MAX = 0xFFFF # bootstrap range
    BS_PORT_MIN = 0x2000 # bootstrap range
    LAUNCH_TIMEOUT_MIN = 10 # minimum amount of time to wait for the browser to launch
    RC_ALERT = "ALERT"  # target crashed/aborted/triggered an assertion failure etc...
    RC_CLOSED = "CLOSED"  # target was closed by call to FFPuppet close()
    RC_EXITED = "EXITED"  # target exited
    RC_WORKER = "WORKER"  # target was closed by worker thread

    def __init__(self, use_profile=None, use_valgrind=False, use_xvfb=False, use_gdb=False, use_rr=False):
        self._abort_tokens = set() # tokens used to notify log scanner to kill the browser process
        self._last_bin_path = None
        self._launches = 0 # number of successful browser launches
        self._logs = PuppetLogger()
        self._platform = platform.system().lower()
        self._proc = None
        self._profile_template = use_profile # profile that is used as a template
        self._use_valgrind = use_valgrind
        self._use_gdb = use_gdb
        self._use_rr = use_rr
        self._workers = list() # collection of threads and processes
        self._xvfb = None
        self.profile = None # path to profile
        self.reason = self.RC_CLOSED # why the target process was terminated

        if use_valgrind:
            if not self._platform.startswith("linux"):
                raise EnvironmentError("Valgrind is only supported on Linux")
            try:
                with open(os.devnull, "w") as null_fp:
                    subprocess.call(["valgrind", "--version"], stdout=null_fp, stderr=null_fp)
            except OSError:
                raise EnvironmentError("Please install Valgrind")

        if use_gdb:
            if not self._platform.startswith("linux"):
                raise EnvironmentError("GDB is only supported on Linux")
            try:
                with open(os.devnull, "w") as null_fp:
                    subprocess.call(["gdb", "--version"], stdout=null_fp, stderr=null_fp)
            except OSError:
                raise EnvironmentError("Please install GDB")

        if use_rr:
            if not self._platform.startswith("linux"):
                raise EnvironmentError("RR is only supported on Linux")
            try:
                with open(os.devnull, "w") as null_fp:
                    subprocess.check_call(["rr", "--version"], stdout=null_fp, stderr=null_fp)
            except OSError:
                raise EnvironmentError("Please install RR")

        if use_xvfb:
            if not self._platform.startswith("linux"):
                raise EnvironmentError("Xvfb is only supported on Linux")
            try:
                self._xvfb = xvfbwrapper.Xvfb(width=1280, height=1024)
            except NameError:
                raise EnvironmentError("Please install xvfbwrapper")
            self._xvfb.start()


    def add_abort_token(self, token):
        """
        Add a token that when present in the browser log will have the browser process terminated.

        @type token: String or re._pattern_type
        @param token: string or compiled RegEx to search for in the browser log.

        @rtype: None
        @return: None
        """

        if isinstance(token, str):
            token = re.compile(re.escape(token))
        if not isinstance(token, re._pattern_type): # pylint: disable=protected-access
            raise TypeError("Expecting 'str' or 're._pattern_type' got: %r" % type(token).__name__)
        self._abort_tokens.add(token)


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
        Check if the browser has crash reports but the process still running.

        @rtype: bool
        @return: True if the browser process is running and no crash reports can
                 be found otherwise False.
        """

        # the process is closed
        if self.reason is not None or not self.is_running():
            return False

        return False if self._find_dumps() else True


    def _find_dumps(self):
        dumps = list()
        # check for *San logs
        if os.path.isdir(self._logs.working_path):
            for fname in os.listdir(self._logs.working_path):
                if fname.startswith(self._logs.LOG_ASAN_PREFIX):
                    dumps.append(os.path.join(self._logs.working_path, fname))

        # check for minidumps
        md_path = os.path.join(self.profile, "minidumps")
        if os.path.isdir(md_path):
            for fname in os.listdir(md_path):
                if ".dmp" in fname:
                    dumps.append(os.path.join(md_path, fname))

        return dumps


    def log_length(self, log_id):
        """
        Get the length of the current browser log.

        @type log_id: String
        @param log_id: The id (key) of the log to clone (stderr, stdout... etc).

        @rtype: int
        @return: length of the current browser log in bytes.
        """
        return self._logs.log_length(log_id)


    def save_logs(self, log_path, meta=False):
        """
        The browser logs will be saved to log_path.
        This should only be called after close().

        @type log_path: String
        @param log_path: File to create to contain log data. Existing files will be overwritten.

        @type meta: bool
        @param meta: Output JSON file containing log file meta data

        @rtype: None
        @return: None
        """

        log.debug("save_logs() called, log_path=%r, meta=%r", log_path, meta)
        if not self._logs.closed:
            raise RuntimeError("Logs are still in use. Call close() first!")

        self._logs.save_logs(log_path, meta=meta)


    def clean_up(self):
        """
        Remove all the remaining files that could have been created during execution.

        NOTE: Calling launch() after calling clean_up() is not intended and may not work
        as expected.

        @rtype: None
        @return: None
        """

        log.debug("clean_up() called")
        self.close(force_close=True)
        self._logs.clean_up()

        # close Xvfb
        if self._xvfb is not None:
            self._xvfb.stop()
            self._xvfb = None

        # at this point everything should be cleaned up
        assert self.reason is not None, "self.reason is None"
        assert self._logs.closed, "self._logs.closed is not True"
        assert self._proc is None, "self._proc is not None"
        assert self.profile is None, "self.profile is not None"
        assert not self._workers, "self._workers is not empty"


    def _terminate(self, kill_delay=30):
        assert self._proc is not None
        assert isinstance(kill_delay, (float, int)) and kill_delay >= 0
        log.debug("_terminate(kill_delay=%0.2f) called", kill_delay)

        # perform 2 passes with increasingly aggressive mode
        # mode values: 0 = terminate, 1 = kill
        # on all platforms other than windows start in terminate mode
        mode = 1 if self._platform == "windows" else 0
        while mode < 2:
            # collect processes
            procs = list()
            try:
                procs.append(psutil.Process(self._proc.pid))
            except psutil.NoSuchProcess:
                pass
            try:
                procs += procs[0].children(recursive=mode == 1)
                has_children = len(procs) > 1
            except (IndexError, psutil.NoSuchProcess):
                procs = list()
                # if parent proc does not exist look up children the long way...
                for proc in psutil.process_iter(attrs=["ppid"]):
                    if int(proc.info["ppid"]) == self._proc.pid:
                        procs.append(proc)
                has_children = bool(procs)

            # iterate over and terminate/kill processes
            for proc in procs:
                try:
                    if mode == 1:
                        proc.kill()
                    else:
                        proc.terminate()
                except psutil.NoSuchProcess:
                    pass

            if self.wait(recursive=has_children, timeout=kill_delay) is not None:
                break
            log.debug("wait(timeout=%0.2f) timed out, mode %d", kill_delay, mode)
            mode += 1


    def close(self, force_close=False):
        """
        Terminate the browser process and clean up all processes.

        @type force_close: bool
        @param force_close: Do not collect logs... etc, just make sure everything is closed

        @rtype: None
        @return: None
        """

        log.debug("close(force_close=%r) called", force_close)
        if self.reason is not None:
            self._logs.close()  # make sure browser logs are also closed
            return

        if self._proc is not None:
            log.debug("firefox pid: %r", self._proc.pid)
            crash_dumps = self._find_dumps()
            # set reason code
            if crash_dumps:
                r_code = self.RC_ALERT
            elif self.is_running():
                r_code = self.RC_CLOSED
            else:
                r_code = self.RC_EXITED

            if not self.is_healthy():
                log.debug("is_healthy() check failed")
                # wait until all open files are closed (except stdout & stderr)
                dump_timeout = 300 if self._use_rr else 90
                if not wait_on_files(self._proc.pid, crash_dumps, recursive=True, timeout=dump_timeout):
                    log.warning("wait_on_files() Timed out")

            # terminate the browser process if needed
            if self.is_running():
                log.debug("process needs to be terminated")
                if self._use_valgrind:
                    self._terminate(0.1)
                else:
                    self._terminate()

            # just in case check the return code
            if self.wait() in (-6, -11):
                r_code = self.RC_ALERT
        else:
            r_code = self.RC_CLOSED
            log.debug("firefox process was 'None'")

        log.debug("cleaning up %d worker(s)...", len(self._workers))
        for worker in self._workers:
            worker.join()
            if worker.aborted.is_set():
                r_code = self.RC_WORKER
            if not force_close and worker.log_available():
                worker.dump_log(dst_fp=self._logs.add_log("ffp_worker_%s" % worker.name))
            worker.clean_up()
        self._workers = list()

        if not force_close:
            # scan for ASan logs
            for fname in os.listdir(self._logs.working_path):
                if not fname.startswith(self._logs.LOG_ASAN_PREFIX):
                    continue
                self._logs.add_log(fname, open(os.path.join(self._logs.working_path, fname), "rb"))

            # check for minidumps in the profile and dump them if possible
            if self.profile is not None:
                process_minidumps(
                    os.path.join(self.profile, "minidumps"),
                    os.path.join(self._last_bin_path, "symbols"),
                    self._logs.add_log)

        if self._proc is not None:
            self._logs.get_fp("stderr").write(
                ("[ffpuppet] Reason code: %s\n" % r_code).encode("utf-8"))
            self._proc = None

        # close browser logger
        self._logs.close()

        # remove temporary profile directory if necessary
        if self.profile is not None and os.path.isdir(self.profile):
            shutil.rmtree(self.profile, onerror=onerror)
            self.profile = None

        log.debug("exit reason code %r", r_code)
        self.reason = r_code


    @property
    def launches(self):
        """
        Get the number of successful launches

        @rtype: int
        @return: successful launch count
        """
        return self._launches


    def get_pid(self):
        """
        Get the browser process ID

        @rtype: int
        @return: browser process ID
        """
        return None if self._proc is None else self._proc.pid


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

        if not isinstance(bin_path, str):
            raise TypeError("Expecting 'str' got %r" % type(bin_path).__name__)

        cmd = [bin_path, "-no-remote"]
        if self.profile is not None:
            cmd += ["-profile", self.profile]

        if additional_args:
            if not isinstance(additional_args, list):
                raise TypeError("Expecting 'list' got %r" % type(additional_args).__name__)
            for add_arg in additional_args:
                if not isinstance(add_arg, str):
                    raise TypeError("Expecting 'str' got %r" % type(add_arg).__name__)
            cmd.extend(additional_args)

        if self._use_valgrind:
            cmd = [
                "valgrind",
                "-q",
                #"---error-limit=no",
                "--smc-check=all-non-file",
                "--show-mismatched-frees=no",
                "--show-possibly-lost=no",
                "--read-inline-info=yes",
                #"--leak-check=full",
                #"--track-origins=yes",
                "--vex-iropt-register-updates=allregs-at-mem-access"] + cmd

        if self._use_gdb:
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
                "--args"] + cmd # enable gdb

        if self._use_rr:
            cmd = ["rr", "record"] + cmd

        return cmd


    def launch(self, bin_path, env_mod=None, launch_timeout=300, location=None, log_limit=0,
               memory_limit=0, prefs_js=None, safe_mode=False, extension=None):
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

        @type safe_mode: bool
        @param safe_mode: Launch Firefox in safe mode. WARNING: Launching in safe mode blocks with
                          a dialog that must be dismissed manually.

        @type extension: String, or list of Strings
        @param extension: Path to an extension (e.g. DOMFuzz fuzzPriv extension) to be installed.

        @rtype: None
        @return: None
        """
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

        log_limit = max(log_limit, 0)
        memory_limit = max(memory_limit, 0)

        self.reason = None
        launch_timeout = max(launch_timeout, self.LAUNCH_TIMEOUT_MIN) # force minimum launch timeout
        log.debug("launch timeout: %d", launch_timeout)

        # create and modify a profile
        self.profile = create_profile(
            extension=extension,
            prefs_js=prefs_js,
            template=self._profile_template)

        # performing the bootstrap helps guarantee that the browser
        # will be loaded and ready to accept input when launch() returns
        init_soc = self._bootstrap_start()

        launch_args = ["http://127.0.0.1:%d" % init_soc.getsockname()[1]]
        if safe_mode:
            launch_args.insert(0, "-safe-mode")

        cmd = self.build_launch_cmd(
            bin_path,
            additional_args=launch_args)

        if self._use_valgrind:
            if env_mod is None:
                env_mod = dict()
            # https://developer.gimp.org/api/2.0/glib/glib-running.html#G_DEBUG
            env_mod["G_DEBUG"] = "gc-friendly"

        # open logs
        self._logs.reset() # clean up existing log files
        self._logs.add_log("stdout")
        stderr = self._logs.add_log("stderr")
        stderr.write(b"[ffpuppet] Launch command: ")
        stderr.write(" ".join(cmd).encode("utf-8"))
        stderr.write(b"\n\n")
        stderr.flush()
        sanitizer_logs = os.path.join(self._logs.working_path, self._logs.LOG_ASAN_PREFIX)
        # launch the browser
        log.debug("launch command: %r", " ".join(cmd))
        # measure the duration between launch and bootstrap completion
        launch_init = time.time()
        self._proc = subprocess.Popen(
            cmd,
            bufsize=0,  # unbuffered (for log scanners)
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if self._platform == "windows" else 0,
            env=prepare_environment(self._last_bin_path, sanitizer_logs, env_mod=env_mod),
            shell=False,
            stderr=stderr,
            stdout=self._logs.get_fp("stdout"))
        log.debug("launched firefox with pid: %d", self._proc.pid)
        self._bootstrap_finish(init_soc, timeout=launch_timeout, url=location)
        log.debug("bootstrap complete (%0.2fs)", time.time() - launch_init)

        if prefs_js is not None and os.path.isfile(os.path.join(self.profile, "Invalidprefs.js")):
            raise LaunchError("%r is invalid" % prefs_js)

        if log_limit:
            # launch log size monitor thread
            self._workers.append(log_size_limiter.LogSizeLimiterWorker())
            self._workers[-1].start(self, log_limit)

        if memory_limit:
            # launch memory monitor thread
            self._workers.append(memory_limiter.MemoryLimiterWorker())
            self._workers[-1].start(self, memory_limit)

        if self._use_valgrind:
            self.add_abort_token(re.compile(r"==\d+==\s"))

        if self._abort_tokens:
            # launch log scanner thread
            self._workers.append(log_scanner.LogScannerWorker())
            self._workers[-1].start(self)

        self._launches += 1


    def is_running(self):
        """
        Check if the browser process is running.

        @rtype: bool
        @return: True if the process is running otherwise False
        """
        return self._proc is not None and self._proc.poll() is None


    def _bootstrap_start(self):
        assert self.BS_PORT_MAX >= self.BS_PORT_MIN, "Invalid port range"

        init_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self._platform == "windows":
            init_soc.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_EXCLUSIVEADDRUSE,  # pylint: disable=no-member
                1)
        init_soc.settimeout(0.25)
        for _ in range(100):  # number of attempts to find an available port
            try:
                init_soc.bind(("127.0.0.1", random.randint(self.BS_PORT_MIN, self.BS_PORT_MAX)))
                init_soc.listen(5)
                break
            except socket.error as soc_e:
                if soc_e.errno in (errno.EADDRINUSE, 10013):  # Address already in use
                    continue
                raise soc_e
        else:
            raise LaunchError("Could not find available port")
        with open(os.path.join(self.profile, "prefs.js"), "a") as prefs_fp:
            prefs_fp.write("\n") # make sure there is a newline before appending to prefs.js
            prefs_fp.write("user_pref('capability.policy.policynames', 'localfilelinks');\n")
            prefs_fp.write("user_pref('capability.policy.localfilelinks.sites', "
                           "'http://127.0.0.1:%d');\n" % init_soc.getsockname()[1])
            prefs_fp.write("user_pref('capability.policy.localfilelinks.checkloaduri.enabled', "
                           "'allAccess');\n")
        return init_soc


    def _bootstrap_finish(self, init_soc, timeout=60, url=None):
        conn = None
        timer_start = time.time()
        try:
            # wait for browser test connection
            while True:
                try:
                    conn, _ = init_soc.accept()
                    conn.settimeout(timeout)
                except socket.timeout:
                    if (time.time() - timer_start) >= timeout:
                        raise BrowserTimeoutError("Launching browser timed out (%ds)" % timeout)
                    elif not self.is_healthy():
                        raise BrowserTerminatedError("Failure during browser startup")
                    continue  # browser is alive but we have not received a connection
                break  # received connection

            log.debug("waiting to receive browser test connection data")
            while len(conn.recv(4096)) == 4096:
                pass
            log.debug("sending response with redirect url: %r", url)
            response = "<head>" \
                       "<meta http-equiv=\"refresh\" content=\"0; url=%s\"/>" \
                       "</head>" % ("about:blank" if url is None else url)
            response = "HTTP/1.1 200 OK\r\n" \
                       "Content-Length: %d\r\n" \
                       "Content-Type: text/html\r\n" \
                       "Connection: close\r\n\r\n%s" % (len(response), response)
            conn.sendall(response.encode("utf-8"))

        except socket.error as soc_e:
            raise LaunchError("Failed to launch browser: %s" % soc_e)

        except socket.timeout:
            raise BrowserTimeoutError("Test connection timed out (%ds)" % timeout)

        finally:
            if conn is not None:
                conn.close()
            init_soc.close()


    def wait(self, recursive=True, timeout=None):
        """
        Wait for process and children to terminate. This call will block until the process exits
        unless a timeout is specified. If a timeout of zero or greater is specified the call will
        only block until the timeout expires.

        @type recursive: bool
        @param recursive: wait for child processes to exit

        @type timeout: float, int or None
        @param timeout: maximum amount of time to wait for process to terminate
                        or None (wait indefinitely)

        @rtype: int or None
        @return: exit code of process if it exits and None if timeout expired or the process does
                 not exist
        """
        assert timeout is None or (isinstance(timeout, (float, int)) and timeout >= 0)
        blocking_procs = list()
        start_time = time.time()
        while self._proc is not None:
            retval = self._proc.poll()
            if recursive and retval is not None:
                if not blocking_procs:
                    # look up blocking child processes
                    # we want to avoid calling process_iter() so store the blocking procesess
                    for proc in psutil.process_iter(attrs=["ppid"]):
                        if int(proc.info["ppid"]) == self._proc.pid:
                            blocking_procs.append(proc)
                elif blocking_procs:
                    # check status of blocking child processes
                    blocking_procs = [proc for proc in blocking_procs if proc.is_running()]
            if retval is not None and not blocking_procs:
                return retval
            if timeout is not None and (time.time() - start_time >= timeout):
                log.debug("wait() timed out (%0.2fs), %d child proc(s)", timeout, len(blocking_procs))
                break
            time.sleep(0.1)
        return None
