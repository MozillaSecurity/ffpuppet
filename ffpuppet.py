#!/usr/bin/env python2

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import errno
import logging
import os
import platform
import random
import re
import shutil
import socket
import subprocess
import tempfile
import time
try: # py 2-3 compatibility
    from urllib import pathname2url # pylint: disable=no-name-in-module
except ImportError:
    from urllib.request import pathname2url # pylint: disable=no-name-in-module

try:
    import xvfbwrapper
except ImportError:
    pass

try:
    from . import breakpad_syms
    from .workers import log_scanner, memory_limiter
except ImportError:
    logging.error("Can't use ffpuppet.py as a script with Python 3.")
    exit(1)
except ValueError:
    import breakpad_syms
    from workers import log_scanner, memory_limiter

log = logging.getLogger("ffpuppet") # pylint: disable=invalid-name


__author__ = "Tyson Smith"
__all__ = ("FFPuppet", "LaunchError")


def open_unique(mode="w"):
    """
    Create and open a unique file.

    @type mode: String
    @param mode: File mode. See documentation for open().

    @rtype: file object
    @return: An open file object.
    """

    tmp_fd, log_file = tempfile.mkstemp(
        suffix="_log.txt",
        prefix=time.strftime("ffp_%Y-%m-%d_%H-%M-%S_"))
    os.close(tmp_fd)

    # open with 'open' so the file object 'name' attribute is correct
    return open(log_file, mode)


class LaunchError(Exception):
    pass


class FFPuppet(object):
    def __init__(self, use_profile=None, use_valgrind=False, use_xvfb=False, use_gdb=False):
        self._abort_tokens = set() # tokens used to notify log scanner to kill the browser process
        self._launches = 0 # number of times the browser has successfully been launched
        self._log = None
        self._platform = platform.system().lower()
        self._proc = None
        self._profile_template = use_profile # profile that is used as a template
        self._use_valgrind = use_valgrind
        self._use_gdb = use_gdb
        self._workers = list() # collection of threads and processes
        self._xvfb = None
        self.closed = True # False once launch() is called and True once close() is called
        self.launches = 0 # number of times the browser has successfully been launched
        self.profile = None # path to profile

        if use_valgrind:
            if self._platform == "windows":
                raise EnvironmentError("Valgrind is not supported on Windows")
            try:
                with open(os.devnull, "w") as null_fp:
                    subprocess.call(["valgrind", "--version"], stdout=null_fp, stderr=null_fp)
            except OSError:
                raise EnvironmentError("Please install Valgrind")

        if use_gdb:
            try:
                with open(os.devnull, "w") as null_fp:
                    subprocess.call(["gdb", "--version"], stdout=null_fp, stderr=null_fp)
            except OSError:
                raise EnvironmentError("Please install GDB")

        if use_xvfb:
            if self._platform != "linux":
                raise EnvironmentError("Xvfb is only supported on Linux")
            try:
                self._xvfb = xvfbwrapper.Xvfb(width=1280, height=1024)
            except NameError:
                raise EnvironmentError("Please install xvfbwrapper")
            self._xvfb.start()


    def get_environ(self, target_bin):
        """
        Get the string environment that is used when launching the browser.

        @type bin_path: String
        @param bin_path: Path to the Firefox binary

        @rtype: dict
        @return: A dict representing the string environment
        """
        env = dict(os.environ)
        if self._use_valgrind:
            # https://developer.gimp.org/api/2.0/glib/glib-running.html#G_DEBUG
            env["G_DEBUG"] = "gc-friendly"

        # https://developer.gimp.org/api/2.0/glib/glib-running.html#G_SLICE
        env["G_SLICE"] = "always-malloc"
        env["MOZ_CC_RUN_DURING_SHUTDOWN"] = "1"
        env["MOZ_CRASHREPORTER_DISABLE"] = "1"
        env["MOZ_GDB_SLEEP"] = "0"
        env["XRE_NO_WINDOWS_CRASH_DIALOG"] = "1"
        env["XPCOM_DEBUG_BREAK"] = "warn"

        # setup Address Sanitizer options if not set manually
        # https://github.com/google/sanitizers/wiki/AddressSanitizerFlags
        if "ASAN_OPTIONS" not in env:
            env["ASAN_OPTIONS"] = ":".join((
                "abort_on_error=true",
                #"alloc_dealloc_mismatch=false", # different defaults per OS
                "allocator_may_return_null=true",
                "check_initialization_order=true",
                #"check_malloc_usable_size=false", # defaults True
                #"detect_stack_use_after_return=true", # can't launch firefox with this enabled
                "disable_coredump=true",
                "sleep_before_dying=0",
                "strict_init_order=true",
                #"strict_memcmp=false", # defaults True
                "symbolize=true"))

        # default to environment definition
        if "ASAN_SYMBOLIZER_PATH" in os.environ:
            env["ASAN_SYMBOLIZER_PATH"] = os.environ["ASAN_SYMBOLIZER_PATH"]
            env["MSAN_SYMBOLIZER_PATH"] = os.environ["ASAN_SYMBOLIZER_PATH"]
            if not os.path.isfile(env["ASAN_SYMBOLIZER_PATH"]):
                log.warning("Invalid ASAN_SYMBOLIZER_PATH (%s)", env["ASAN_SYMBOLIZER_PATH"])

        # look for llvm-symbolizer bundled with firefox build
        if "ASAN_SYMBOLIZER_PATH" not in env:
            if self._platform == "windows":
                symbolizer_bin = os.path.join(os.path.dirname(target_bin), "llvm-symbolizer.exe")
            else:
                symbolizer_bin = os.path.join(os.path.dirname(target_bin), "llvm-symbolizer")
            if os.path.isfile(symbolizer_bin):
                env["ASAN_SYMBOLIZER_PATH"] = symbolizer_bin
                env["MSAN_SYMBOLIZER_PATH"] = symbolizer_bin

        # https://bugzilla.mozilla.org/show_bug.cgi?id=1305151
        # skia assertions are easily hit and mostly due to precision, disable them.
        if "MOZ_SKIA_DISABLE_ASSERTS" not in env:
            env["MOZ_SKIA_DISABLE_ASSERTS"] = "1"

        if "RUST_BACKTRACE" not in env:
            env["RUST_BACKTRACE"] = "full"

        # setup Undefined Behavior Sanitizer options if not set manually
        if "UBSAN_OPTIONS" not in env:
            env["UBSAN_OPTIONS"] = "print_stacktrace=1"

        return env


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
        if not isinstance(token, re._pattern_type):
            raise TypeError("Expecting 'str' or 're._pattern_type' got: %r" % type(token).__name__)
        self._abort_tokens.add(token)


    def clone_log(self, target_file=None, offset=None, symbolize=False):
        """
        Create a copy of the current browser log.

        @type target_file: String
        @param target_file: The log contents will be saved to target_file.

        @type offset: int
        @param offset: Where to begin reading the log from

        @type symbolize: bool
        @param symbolize: symbolize debug stack trace output. WARNING: calculating a value to be
            used with offset with this set will cause issues.

        @rtype: String or None
        @return: Name of the file containing the cloned log or None on failure
        """

        # check if there is a log to clone
        if self._log is None or not os.path.isfile(self._log.name):
            return None

        try:
            self._log.flush()
        except ValueError: # ignore exception if file is closed
            pass
        with open(self._log.name, "rb") as logfp:
            if offset is not None:
                logfp.seek(offset)
            if target_file is None:
                cpyfp = open_unique("wb")
                target_file = cpyfp.name
            else:
                cpyfp = open(target_file, "wb")
            try:
                if symbolize:
                    cpyfp.write(breakpad_syms.addr2line(logfp.read()))
                else:
                    cpyfp.write(logfp.read())
            finally:
                cpyfp.close()

        return target_file


    def log_length(self):
        """
        Get the length of the current browser log.

        @rtype: int
        @return: length of the current browser log in bytes.
        """
        if self._log is None or not os.path.isfile(self._log.name):
            return 0

        try:
            self._log.flush()
        except ValueError: # ignore exception if file is closed
            pass
        with open(self._log.name, "rb") as logfp:
            logfp.seek(0, os.SEEK_END)
            return logfp.tell()


    def save_log(self, log_file, symbolize=True):
        """
        The browser log will be saved to log_file.
        This should only be called after close().

        @type log_file: String
        @param log_file: File to create to contain log data. Existing files will be overwritten.

        @type symbolize: bool
        @param symbolize: symbolize debug stack trace output

        @rtype: None
        @return: None
        """

        if not self.closed:
            raise RuntimeError("Log is still in use. Call close() first!")

        # copy log to location specified by log_file
        if self._log is not None and os.path.isfile(self._log.name):
            dst_path = os.path.dirname(log_file)
            if not dst_path:
                dst_path = os.getcwd()
            if not os.path.isdir(dst_path):
                os.makedirs(dst_path)
            log_file = os.path.join(os.path.abspath(dst_path), log_file)
            with open(self._log.name, "rb") as logfp, open(log_file, "wb") as cpyfp:
                if symbolize:
                    cpyfp.write(breakpad_syms.addr2line(logfp.read()))
                else:
                    cpyfp.write(logfp.read())


    def clean_up(self):
        """
        Remove all the remaining files that could have been created during execution.

        NOTE: Calling launch() after calling clean_up() is not intended and may not work
        as expected.

        @rtype: None
        @return: None
        """

        log.debug("clean_up() called")

        self.close()

        if self._log is not None and os.path.isfile(self._log.name):
            os.remove(self._log.name)
        self._log = None

        # close Xvfb
        if self._xvfb is not None:
            self._xvfb.stop()
            self._xvfb = None

        # at this point everything should be cleaned up
        assert self.closed, "self.closed is not True"
        assert self._proc is None, "self._proc is not None"
        assert self.profile is None, "self.profile is not None"
        assert not self._workers, "self._workers is not empty"


    def close(self):
        """
        Terminate the browser process and clean up all processes.

        @rtype: None
        @return: None
        """

        log.debug("close() called")

        # terminate the browser process
        if self._proc is not None:
            log.debug("firefox pid: %r", self._proc.pid)
            still_running = self._proc.poll() is None
            if still_running:
                log.debug("process needs to be closed")
                if self._use_valgrind:
                    # XXX: hack to prevent the browser from hanging when
                    # running under Valgrind and pressing ctrl+c...
                    # psutil's terminate() does work though
                    self._proc.kill()
                else:
                    self._proc.terminate()

            self._proc.wait()
            if self._log is not None and not self._log.closed:
                if still_running:
                    self._log.write("[Process was closed by ffpuppet]\n")
                self._log.write("[Exit code: %r]\n" % self._proc.returncode)
            log.debug("exit code: %r", self._proc.returncode)
            self._proc = None

        # join worker threads and processes
        log.debug("joining %d worker(s)...", len(self._workers))
        for worker in self._workers:
            worker.join()

            # copy worker logs to main log if is exists and contains data
            worker_log = None if self._log.closed else worker.collect_log()
            if worker_log:
                self._log.write("\n")
                self._log.write("[Worker: %s]\n" % worker.name)
                self._log.write(worker_log)
                self._log.write("\n")
            worker.clean_up()

        # clear out old workers
        self._workers = list()

        # close log
        if self._log is not None and not self._log.closed:
            self._log.close()

        # remove temporary profile directory if necessary
        if self.profile is not None and os.path.isdir(self.profile):
            shutil.rmtree(self.profile)
            self.profile = None

        self.closed = True


    def get_launch_count(self):
        """
        Get the count of successful launches

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

        return cmd


    def check_prefs(self, input_prefs):
        """
        Check that the current prefs.js file in use by the browser contains all the requested prefs.

        NOTE: There will be false positives if input_prefs does not adhere to the formatting that
        is used in prefs.js file generated by the browser.

        @type input_prefs: String
        @param input_prefs: Path to prefs.js file that contains prefs that should be merged
                            into the prefs.js file generated by the browser

        @rtype: bool
        @return: True if all prefs in input_prefs are merged otherwise False
        """

        if self.profile is None or not os.path.isfile(os.path.join(self.profile, "prefs.js")):
            log.debug("prefs.js not in profile: %r", self.profile)
            return False

        enabled_prefs = list()
        with open(os.path.join(self.profile, "prefs.js"), "r") as prefs_fp:
            for e_pref in prefs_fp:
                e_pref = e_pref.strip()
                if e_pref.startswith("user_pref("):
                    enabled_prefs.append(e_pref)

        with open(input_prefs, "r") as prefs_fp:
            missing_prefs = 0
            for r_pref in prefs_fp:
                r_pref = r_pref.strip()
                if not r_pref.startswith("user_pref("):
                    continue
                found = False
                for e_pref in enabled_prefs:
                    if r_pref.startswith(e_pref):
                        found = True
                        break
                if found:
                    continue
                log.debug("pref not set: %r", r_pref)
                missing_prefs += 1

        log.debug("%r pref(s) not set", missing_prefs)
        return missing_prefs < 1


    @staticmethod
    def create_profile(extension=None, prefs_js=None, template=None):
        """
        Create a profile to be used with Firefox

        @type extension: String
        @param extension: Path to an extension (e.g. DOMFuzz fuzzPriv extension) to be installed.

        @type prefs_js: String
        @param prefs_js: Path to a prefs.js file to install in the Firefox profile.

        @type template: String
        @param template: Path to an existing profile directory to use.

        @rtype: String
        @return: Path to directory to be used as a profile
        """

        profile = tempfile.mkdtemp(prefix="ffprof_")
        log.debug("profile directory: %r", profile)

        if template is not None:
            log.debug("using profile template: %r", template)
            shutil.rmtree(profile) # reuse the directory name
            if not os.path.isdir(template):
                raise IOError("Cannot find template profile: %r" % template)
            shutil.copytree(template, profile)
            invalid_prefs = os.path.join(profile, "Invalidprefs.js")
            # if Invalidprefs.js was copied from the template profile remove it
            if os.path.isfile(invalid_prefs):
                os.remove(invalid_prefs)

        if prefs_js is not None:
            log.debug("using prefs.js: %r", prefs_js)
            if not os.path.isfile(prefs_js):
                shutil.rmtree(profile, True) # clean up on failure
                raise IOError("prefs.js file does not exist: %r" % prefs_js)
            shutil.copyfile(prefs_js, os.path.join(profile, "prefs.js"))

            # times.json only needs to be created when using a custom pref.js
            times_json = os.path.join(profile, "times.json")
            if not os.path.isfile(times_json):
                with open(times_json, "w") as times_fp:
                    times_fp.write('{"created":%d}' % (int(time.time()) * 1000))

        # XXX: fuzzpriv extension support
        # should be removed when bug 1322400 is resolved if it is no longer used
        if extension is not None:
            os.mkdir(os.path.join(profile, "extensions"))
            if os.path.isfile(extension) and extension.endswith(".xpi"):
                shutil.copyfile(
                    extension,
                    os.path.join(profile, "extensions", os.path.basename(extension)))
            elif os.path.isdir(extension):
                shutil.copytree(
                    os.path.abspath(extension),
                    os.path.join(profile, "extensions", "domfuzz@squarefree.com"))
            else:
                shutil.rmtree(profile, True) # clean up on failure
                raise RuntimeError("Unknown extension: %r" % extension)

        return profile


    def launch(self, bin_path, launch_timeout=300, location=None, memory_limit=None,
               prefs_js=None, safe_mode=False, extension=None):
        """
        Launch a new browser process.

        @type bin_path: String
        @param bin_path: Path to the Firefox binary

        @type launch_timeout: int
        @param launch_timeout: Timeout in seconds for launching the browser

        @type location: String
        @param location: URL to navigate to after successfully starting up the browser

        @type memory_limit: int
        @param memory_limit: Memory limit in bytes. Browser will be terminated if its memory usage
                             exceeds the amount specified here.

        @type prefs_js: String
        @param prefs_js: Path to a prefs.js file to install in the Firefox profile.

        @type safe_mode: bool
        @param safe_mode: Launch Firefox in safe mode. WARNING: Launching in safe mode blocks with
                          a dialog that must be dismissed manually.

        @type extension: String
        @param extension: Path to an extension (e.g. DOMFuzz fuzzPriv extension) to be installed.

        @rtype: None
        @return: None
        """
        if self._proc is not None:
            raise LaunchError("Process is already running")

        bin_path = os.path.abspath(bin_path)
        if not os.path.isfile(bin_path) or not os.access(bin_path, os.X_OK):
            raise IOError("%s is not an executable" % bin_path)

        log.debug("requested location: %r", location)
        if location is not None:
            if os.path.isfile(location):
                location = "file:///%s" % pathname2url(os.path.abspath(location).lstrip('/'))
            elif re.match(r"http(s)?://", location, re.IGNORECASE) is None:
                raise IOError("Cannot find %s" % os.path.abspath(location))

        if memory_limit is not None and not memory_limiter.MemoryLimiterWorker.available:
            raise EnvironmentError("Please install psutil")

        self.closed = False
        launch_timeout = max(launch_timeout, 10) # force 10 seconds minimum launch_timeout
        log.debug("launch timeout: %r", launch_timeout)

        # create and modify a profile
        self.profile = self.create_profile(
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

        # clean up existing log file before creating a new one
        if self._log is not None and os.path.isfile(self._log.name):
            os.remove(self._log.name)

        # open log
        self._log = open_unique()
        self._log.write("Launch command: %s\n\n" % " ".join(cmd))
        self._log.flush()

        # launch the browser
        log.debug("launch command: %r", " ".join(cmd))
        self._proc = subprocess.Popen(
            cmd,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if self._platform == "windows" else 0,
            env=self.get_environ(bin_path),
            shell=False,
            stderr=self._log,
            stdout=self._log)
        log.debug("launched firefox with pid: %d", self._proc.pid)

        self._bootstrap_finish(init_soc, timeout=launch_timeout, url=location)
        log.debug("bootstrap complete")

        if prefs_js is not None and os.path.isfile(os.path.join(self.profile, "Invalidprefs.js")):
            raise LaunchError("%r is invalid" % prefs_js)

        if memory_limit is not None:
            # launch memory monitor thread
            self._workers.append(memory_limiter.MemoryLimiterWorker())
            self._workers[-1].start(self._proc.pid, memory_limit)

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
        while True:
            try:
                init_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                init_soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                init_soc.settimeout(0.25)
                init_soc.bind(("127.0.0.1", random.randint(0x2000, 0xFFFF)))
                init_soc.listen(5)
                break
            except socket.error as soc_e:
                if soc_e.errno == errno.EADDRINUSE: # Address already in use
                    continue
                raise soc_e
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
                        raise LaunchError("Launching browser timed out (%ds)" % timeout)
                    elif not self.is_running():
                        raise LaunchError("Failure during browser startup")
                    continue # browser is alive but we have not received a connection
                break # received connection

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
            conn.sendall(response.encode("UTF-8"))

        except socket.error as soc_e:
            raise LaunchError("Failed to launch browser: %s" % soc_e)

        except socket.timeout:
            raise LaunchError("Test connection timed out (%ds)" % timeout)

        finally:
            if conn is not None:
                conn.close()
            init_soc.close()


    def wait(self, timeout=0):
        """
        Wait for process to terminate. This call will block until the process exits unless
        a timeout is specified. If a timeout greater than zero is specified the call will
        only block until the timeout expires.

        @type timeout: float
        @param timeout: maximum amount of time to wait for process to terminate

        @rtype: int or None
        @return: exit code if process exits and None if timeout expired
        """
        timer_exp = time.time() + timeout
        while self._proc is not None:
            if timeout > 0 and timer_exp <= time.time():
                break
            if self._proc.poll() is not None:
                return self._proc.poll()
            time.sleep(0.1)

        return None


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Firefox launcher/wrapper")
    parser.add_argument(
        "binary",
        help="Firefox binary to execute")
    parser.add_argument(
        "-a", "--abort-token", action="append", default=list(),
        help="Scan the log for the given value and close browser on detection. " \
             "For example '-a ###!!! ASSERTION:' would be used to detect soft assertions.")
    parser.add_argument(
        "-d", "--dump", action="store_true",
        help="Display browser log on process exit")
    parser.add_argument(
        "-e", "--extension",
        help="Install the fuzzPriv extension (specify path to funfuzz/dom/extension)")
    parser.add_argument(
        "-g", "--gdb", action="store_true",
        help="Use GDB")
    parser.add_argument(
        "-l", "--log",
        help="log file name")
    parser.add_argument(
        "-m", "--memory", type=int,
        help="Process memory limit in MBs (Requires psutil)")
    parser.add_argument(
        "-p", "--prefs",
        help="prefs.js file to use")
    parser.add_argument(
        "-P", "--profile",
        help="Profile to use. (default: a temporary profile is created)")
    parser.add_argument(
        "--safe-mode", action="store_true",
        help="Launch browser in 'safe-mode'. WARNING: Launching in safe mode blocks with a " \
             "dialog that must be dismissed manually.")
    parser.add_argument(
        "-t", "--timeout", type=int, default=300,
        help="Number of seconds to wait for the browser to become " \
             "responsive after launching. (default: %(default)s)")
    parser.add_argument(
        "-u", "--url",
        help="Server URL or local file to load.")
    parser.add_argument(
        "--valgrind", action="store_true",
        help="Use valgrind")
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Output includes debug prints")
    parser.add_argument(
        "--xvfb", action="store_true",
        help="Use xvfb (Linux only)")
    return parser.parse_args(argv)


def main(argv=None):
    args = _parse_args(argv)

    # set output verbosity
    if args.verbose or bool(os.getenv("DEBUG")):
        log_level = logging.DEBUG
        log_fmt = "%(levelname).1s %(name)s [%(asctime)s] %(message)s"
    else:
        log_level = logging.INFO
        log_fmt = "[%(asctime)s] %(message)s"
    logging.basicConfig(format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level)

    ffp = FFPuppet(
        use_profile=args.profile,
        use_valgrind=args.valgrind,
        use_xvfb=args.xvfb,
        use_gdb=args.gdb)
    for a_token in args.abort_token:
        ffp.add_abort_token(a_token)

    try:
        ffp.launch(
            args.binary,
            location=args.url,
            launch_timeout=args.timeout,
            memory_limit=args.memory * 1024 * 1024 if args.memory else None,
            prefs_js=args.prefs,
            safe_mode=args.safe_mode,
            extension=args.extension)
        if args.prefs is not None and os.path.isfile(args.prefs):
            ffp.check_prefs(args.prefs)
        log.info("Running Firefox (pid: %d)...", ffp.get_pid())
        ffp.wait()
    except KeyboardInterrupt:
        log.info("Ctrl+C detected. Shutting down...")
    finally:
        ffp.close()
        log.info("Firefox process closed")
        output_log = open_unique()
        output_log.close()
        ffp.save_log(output_log.name)
        if args.dump:
            with open(output_log.name, "rb") as log_fp:
                log.info("\n[Browser log start]\n%s\n[Browser log end]", log_fp.read().decode("utf-8", errors="ignore"))
        if args.log is not None:
            shutil.move(output_log.name, args.log)
        else:
            os.remove(output_log.name)
        ffp.clean_up()


if __name__ == "__main__":
    main()
