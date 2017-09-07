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
import stat
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

from .workers import log_scanner, log_size_limiter, memory_limiter

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


def onerror(func, path, exc_info):
    """
    Error handler for `shutil.rmtree`.

    If the error is due to an access error (read only file)
    it attempts to add write permission and then retries.

    If the error is for another reason it re-raises the error.

    Copyright Michael Foord 2004
    Released subject to the BSD License
    ref: http://www.voidspace.org.uk/python/recipebook.shtml#utils

    Usage : `shutil.rmtree(path, onerror=onerror)`
    """
    if not os.access(path, os.W_OK):
        # Is the error an access error?
        os.chmod(path, stat.S_IWUSR)
        func(path)
    else:
        raise


class LaunchError(Exception):
    pass


class FFPuppet(object):
    LAUNCH_TIMEOUT_MIN = 10 # minimum amount of time to wait for the browser to launch
    LOG_BUF_SIZE = 0x10000 # buffer size used to copy logs
    LOG_CLOSE_TIMEOUT = 10
    LOG_POLL_RATE = 1

    def __init__(self, use_profile=None, use_valgrind=False, use_xvfb=False, use_gdb=False):
        self._abort_tokens = set() # tokens used to notify log scanner to kill the browser process
        self._asan_log = os.path.join(tempfile.gettempdir(), "ffp_asan_%d.log" % os.getpid())
        self._last_bin_path = None
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
        self.profile = None # path to profile

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

        if use_xvfb:
            if not self._platform.startswith("linux"):
                raise EnvironmentError("Xvfb is only supported on Linux")
            try:
                self._xvfb = xvfbwrapper.Xvfb(width=1280, height=1024)
            except NameError:
                raise EnvironmentError("Please install xvfbwrapper")
            self._xvfb.start()

        # check for minidump_stackwalk binary
        try:
            with open(os.devnull, "w") as null_fp:
                subprocess.call(["minidump_stackwalk"], stdout=null_fp, stderr=null_fp)
            self._have_mdsw = True
        except OSError:
            self._have_mdsw = False


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
        env["MOZ_CRASHREPORTER"] = "1"
        env["MOZ_CRASHREPORTER_NO_REPORT"] = "1"
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
                "log_path=%s" % self._asan_log,
                "sleep_before_dying=0",
                "strict_init_order=true",
                #"strict_memcmp=false", # defaults True
                "symbolize=true"))

        # default to environment definition
        if "ASAN_SYMBOLIZER_PATH" in env:
            env["ASAN_SYMBOLIZER_PATH"] = os.environ["ASAN_SYMBOLIZER_PATH"]
            env["MSAN_SYMBOLIZER_PATH"] = os.environ["ASAN_SYMBOLIZER_PATH"]
            if not os.path.isfile(env["ASAN_SYMBOLIZER_PATH"]):
                log.warning("Invalid ASAN_SYMBOLIZER_PATH (%s)", env["ASAN_SYMBOLIZER_PATH"])
        else: # look for llvm-symbolizer bundled with firefox build
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
        if not isinstance(token, re._pattern_type): # pylint: disable=protected-access
            raise TypeError("Expecting 'str' or 're._pattern_type' got: %r" % type(token).__name__)
        self._abort_tokens.add(token)


    def clone_log(self, target_file=None, offset=None):
        """
        Create a copy of the current browser log.

        @type target_file: String
        @param target_file: The log contents will be saved to target_file.

        @type offset: int
        @param offset: Where to begin reading the log from

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
                shutil.copyfileobj(logfp, cpyfp, self.LOG_BUF_SIZE)
            finally:
                cpyfp.close()

        return target_file


    def _dump_minidump_stacks(self):
        log.debug("symbolize minidumps")

        if self._log is None or self._log.closed:
            log.debug("can't symbolize: no log handle")
            return

        if self.profile is None:
            log.debug("can't symbolize: profile is None")
            return

        minidumps_path = os.path.join(self.profile, "minidumps")
        if not os.path.isdir(minidumps_path):
            log.debug("can't symbolize: no minidumps folder in profile")
            return

        if self._last_bin_path is None:
            log.debug("can't symbolize: no value for bin_path")
            return

        symbols_path = os.path.join(self._last_bin_path, "symbols")

        if not os.path.isdir(symbols_path):
            log.debug("can't symbolize: no symbols at: %s", symbols_path)
            return

        found = 0
        for dumpfile in os.listdir(minidumps_path):
            if not dumpfile.endswith(".dmp"):
                continue
            found += 1
            if self._have_mdsw:
                dump_path = os.path.join(minidumps_path, dumpfile)
                log.debug("calling minidump_stackwalk on %s", dump_path)
                with open(os.devnull, "w") as null_fp:
                    subprocess.check_call(["minidump_stackwalk", "-m", dump_path, symbols_path],
                                          stdout=self._log, stderr=null_fp)
            else:
                log.warning("Found a minidump, but can't process it without minidump_stackwalk."
                            " See README.md for how to obtain it.")
        if found > 1:
            log.warning("Found %d minidumps! Expecting 0 or 1", found)


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


    def save_log(self, log_file):
        """
        The browser log will be saved to log_file.
        This should only be called after close().

        @type log_file: String
        @param log_file: File to create to contain log data. Existing files will be overwritten.

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
            shutil.copy(self._log.name, log_file)


    def clean_up(self):
        """
        Remove all the remaining files that could have been created during execution.

        NOTE: Calling launch() after calling clean_up() is not intended and may not work
        as expected.

        @rtype: None
        @return: None
        """

        log.debug("clean_up() called")

        self.close(ignore_logs=True)

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


    def _merge_logs(self, close_needed=False):
        log.debug("merge logs")

        # collect browser log data
        if self._proc is not None:
            log.debug("wait for browser log dump to complete")
            time_limit = time.time() + self.LOG_CLOSE_TIMEOUT
            # this helps collect complete logs from multiprocess targets
            while True:
                log_pos = self._log.tell()
                time.sleep(self.LOG_POLL_RATE)
                self._log.flush()
                if log_pos == self._log.tell(): # this isn't bullet proof but it works
                    break
                if time_limit < time.time():
                    log.warning("Log may be incomplete!")
                    self._log.write("[ffpuppet] WARNING! Log may be incomplete!\n")
                    break
            if close_needed:
                self._log.write("[ffpuppet] Process was closed by ffpuppet\n")
            log.debug("exit code: %r", self._proc.returncode)

        log.debug("copying ASan logs")
        # this is a HACK to try to order ASan logs
        # It attempts to locate the null deref in the child process (MOZ_CRASH)
        # triggered by closing the parent process (when e10s is enabled) and place it
        # at the bottom of the merged log.
        # This is done to allow FuzzManager to bucket the results properly
        asan_logs = list()
        re_asan_null = re.compile(r"==\d+==ERROR:.+?SEGV\son\sunknown\saddress\s0x[0]+\s\(.+?T2\)")
        for tmp_file in os.listdir(tempfile.gettempdir()):
            tmp_file = os.path.join(tempfile.gettempdir(), tmp_file)
            if not tmp_file.startswith(self._asan_log):
                continue
            with open(tmp_file, "r") as log_fp:
                lines = log_fp.readlines(4096)[:7] # don't bother reading more than 4KB
                if len(lines) < 6 or re.match(re_asan_null, lines[1]):
                    asan_logs.append(tmp_file)
                else:
                    asan_logs.insert(0, tmp_file)
        for asan_log in asan_logs:
            self._log.write("\n")
            self._log.write("[ffpuppet] Read from %s:\n" % asan_log)
            with open(asan_log, "r") as log_fp:
                shutil.copyfileobj(log_fp, self._log, self.LOG_BUF_SIZE)
            self._log.write("\n")

        log.debug("copying worker logs to main log")
        for worker in self._workers:
            if worker.log_available():
                self._log.write("\n")
                self._log.write("[ffpuppet worker]: %s\n" % worker.name)
                worker.collect_log(dst_fp=self._log)
                self._log.write("\n")


    def _terminate(self, kill_delay=30):
        kill_delay = max(kill_delay, 0)
        try:
            log.debug("calling terminate()")
            self._proc.terminate()
            # call kill() immediately if Valgrind is used otherwise wait for "kill_delay"
            if self.wait(kill_delay if not self._use_valgrind else 0.1) is None:
                log.debug("calling kill()")
                self._proc.kill()
        except AttributeError:
            pass # in case self._proc is None


    def close(self, ignore_logs=False):
        """
        Terminate the browser process and clean up all processes.

        @rtype: None
        @return: None
        """

        log.debug("close() called")

        # terminate the browser process
        still_running = self._proc is not None and self._proc.poll() is None
        if self._proc is not None:
            log.debug("firefox pid: %r", self._proc.pid)
            if still_running:
                log.debug("process needs to be closed")
                self._terminate()
            self._proc.wait()

        # join worker threads and processes
        log.debug("joining %d worker(s)...", len(self._workers))
        for worker in self._workers:
            worker.join()

        if not ignore_logs and self._log is not None and not self._log.closed:
            self._merge_logs(close_needed=still_running)

        if self._proc is not None:
            self._log.write("[ffpuppet] Exit code: %r\n" % self._proc.returncode)
            self._proc = None

        log.debug("cleaning up workers...")
        for worker in self._workers:
            worker.clean_up()
        self._workers = list()

        # check for minidumps in the profile and dump them if possible
        self._dump_minidump_stacks()

        # close browser log
        if self._log is not None and not self._log.closed:
            self._log.close()

        # remove ASan logs
        for tmp_file in os.listdir(tempfile.gettempdir()):
            tmp_file = os.path.join(tempfile.gettempdir(), tmp_file)
            if tmp_file.startswith(self._asan_log):
                os.remove(tmp_file)

        # remove temporary profile directory if necessary
        if self.profile is not None and os.path.isdir(self.profile):
            shutil.rmtree(self.profile, onerror=onerror)
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
            shutil.rmtree(profile, onerror=onerror)  # reuse the directory name
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
                shutil.rmtree(profile, True, onerror=onerror)  # clean up on failure
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
                shutil.rmtree(profile, True, onerror=onerror)  # clean up on failure
                raise RuntimeError("Unknown extension: %r" % extension)

        return profile


    def launch(self, bin_path, launch_timeout=300, location=None, log_limit=0, memory_limit=0,
               prefs_js=None, safe_mode=False, extension=None):
        """
        Launch a new browser process.

        @type bin_path: String
        @param bin_path: Path to the Firefox binary

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
        self._last_bin_path = os.path.dirname(bin_path)  # need the path for minidump_stackwalk

        log.debug("requested location: %r", location)
        if location is not None:
            if os.path.isfile(location):
                location = "file:///%s" % pathname2url(os.path.abspath(location).lstrip('/'))
            elif re.match(r"http(s)?://", location, re.IGNORECASE) is None:
                raise IOError("Cannot find %s" % os.path.abspath(location))

        log_limit = max(log_limit, 0)
        memory_limit = max(memory_limit, 0)

        if memory_limit and not memory_limiter.MemoryLimiterWorker.available:
            raise EnvironmentError("Please install psutil")

        self.closed = False
        launch_timeout = max(launch_timeout, self.LAUNCH_TIMEOUT_MIN) # force minimum launch timeout
        log.debug("launch timeout: %d", launch_timeout)

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
        self._log.write("[ffpuppet] Launch command: %s\n\n" % " ".join(cmd))
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

        if log_limit:
            # launch log size monitor thread
            self._workers.append(log_size_limiter.LogSizeLimiterWorker())
            self._workers[-1].start(self, log_limit)

        if memory_limit:
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


    def wait(self, timeout=None):
        """
        Wait for process to terminate. This call will block until the process exits unless
        a timeout is specified. If a timeout greater than zero is specified the call will
        only block until the timeout expires.

        @type timeout: float or None
        @param timeout: maximum amount of time to wait for process to terminate
                        or None (wait indefinitely)

        @rtype: int or None
        @return: exit code if process exits and None if timeout expired
        """
        if timeout is not None:
            timeout = max(timeout, 0)
            timer_exp = time.time() + timeout
        else:
            timer_exp = 0
        while self._proc is not None:
            retval = self._proc.poll()
            if retval is not None:
                return retval
            if timeout is not None and time.time() >= timer_exp:
                log.debug("wait() timed out (%0.2fs)", timeout)
                break
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
        help="Use GDB (Linux only)")
    parser.add_argument(
        "-l", "--log",
        help="log file name")
    parser.add_argument(
        "--log-limit", type=int,
        help="Log file size limit in MBs (default: 'no limit')")
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
        help="Use Valgrind (Linux only)")
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Output includes debug prints")
    parser.add_argument(
        "--xvfb", action="store_true",
        help="Use Xvfb (Linux only)")
    return parser.parse_args(argv)


def main(argv=None): # pylint: disable=missing-docstring
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
            log_limit=args.log_limit * 1024 * 1024 if args.log_limit else 0,
            memory_limit=args.memory * 1024 * 1024 if args.memory else 0,
            prefs_js=args.prefs,
            safe_mode=args.safe_mode,
            extension=args.extension)
        if args.prefs is not None and os.path.isfile(args.prefs):
            ffp.check_prefs(args.prefs)
        log.info("Running Firefox (pid: %d)...", ffp.get_pid())
        ffp.wait()
    except KeyboardInterrupt:
        log.info("Ctrl+C detected.")
    finally:
        log.info("Shutting down...")
        ffp.close()
        log.info("Firefox process closed")
        output_log = open_unique()
        output_log.close()
        ffp.save_log(output_log.name)
        if args.dump:
            dump_limit = 131072 # limit max console dump size to 128KB
            with open(output_log.name, "rb") as log_fp:
                log_fp.seek(0, os.SEEK_END)
                if log_fp.tell() > dump_limit:
                    log_fp.seek(dump_limit * -1, 2)
                else:
                    log_fp.seek(0)
                log.info("Dumping browser log...\n%s\n",
                    log_fp.read().decode("utf-8", errors="ignore"))
                if log_fp.tell() > dump_limit:
                    log.warning("Output exceeds 128KB! Use '--log' to capture full log.")
        if args.log is not None:
            shutil.move(output_log.name, args.log)
        else:
            os.remove(output_log.name)
        ffp.clean_up()
