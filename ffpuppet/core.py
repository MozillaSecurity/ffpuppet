#!/usr/bin/env python2

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import errno
import json
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
from xml.etree import ElementTree
try: # py 2-3 compatibility
    from urllib import pathname2url # pylint: disable=no-name-in-module
except ImportError:
    from urllib.request import pathname2url # pylint: disable=no-name-in-module

try:
    import xvfbwrapper
except ImportError:
    pass

from .puppet_logger import PuppetLogger
from .workers import log_scanner, log_size_limiter, memory_limiter

log = logging.getLogger("ffpuppet") # pylint: disable=invalid-name

__author__ = "Tyson Smith"
__all__ = ("FFPuppet", "LaunchError")


class LaunchError(Exception):
    pass


class FFPuppet(object):
    LAUNCH_TIMEOUT_MIN = 10 # minimum amount of time to wait for the browser to launch
    LOG_ASAN_PATH = tempfile.gettempdir() # where ASan logs will be temporarily stored
    LOG_BUF_SIZE = 0x10000 # buffer size used to copy logs
    LOG_CLOSE_TIMEOUT = 10
    LOG_POLL_RATE = 1
    MDSW_BIN = "minidump_stackwalk"
    MDSW_MAX_LINES = 150

    def __init__(self, use_profile=None, use_valgrind=False, use_xvfb=False, use_gdb=False):
        self._abort_tokens = set() # tokens used to notify log scanner to kill the browser process
        self._asan_prefix = os.path.join(self.LOG_ASAN_PATH, "ffp_asan_%d.log" % os.getpid())
        self._last_bin_path = None
        self._launches = 0 # number of times the browser has successfully been launched
        self._logs = PuppetLogger()
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
                subprocess.call([self.MDSW_BIN], stdout=null_fp, stderr=null_fp)
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
                "log_path=%s" % self._asan_prefix,
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


    def _dump_minidump_stacks(self):
        log.debug("symbolize minidumps")

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
        for fname in os.listdir(minidumps_path):
            if not fname.endswith(".dmp"):
                continue
            found += 1

            if not self._have_mdsw:
                log.warning("Found a minidump, but can't process it without minidump_stackwalk."
                            " See README.md for how to obtain it.")
                break

            md_log = "minidump"
            self._logs.add_log(md_log)
            dump_path = os.path.join(minidumps_path, fname)
            self.poll_file(dump_path)
            log.debug("calling minidump_stackwalk on %s", dump_path)

            with tempfile.TemporaryFile() as out_fp, open(os.devnull, "w") as null_fp:
                ret_val = subprocess.call([self.MDSW_BIN, "-m", dump_path, symbols_path],
                                          stdout=out_fp, stderr=null_fp)
                if ret_val != 0:
                    log.warning("minidump_stackwalk returned %r", ret_val)

                out_fp.seek(0)
                crash_thread = None
                line_count = 0 # lines added to the log so far
                minidump_log = self._logs.get_fp(md_log)
                for line in out_fp: # pylint: disable=not-an-iterable
                    if not line.rstrip() or line.startswith(b"Module|"):
                        continue # ignore line

                    # check if this is a stack entry (starts with '#|')
                    try:
                        t_id = int(line.split(b"|")[0])
                        # assume that the first entry in the stack is the crash_thread
                        # NOTE: an alternative would be to parse the 'Crash|' line
                        if crash_thread is None:
                            crash_thread = t_id
                        elif t_id != crash_thread:
                            break
                    except ValueError:
                        pass # not a stack entry

                    minidump_log.write(line)
                    line_count += 1
                    if line_count >= self.MDSW_MAX_LINES:
                        log.warning("MDSW_MAX_LINES (%d) limit reached", self.MDSW_MAX_LINES)
                        minidump_log.write(b"WARNING: Hit line output limit!")
                        break

                if line_count < 1:
                    log.warning("minidump_stackwalk log was empty")
                    minidump_log.write(b"WARNING: minidump_stackwalk log was empty")

        if found > 1:
            log.warning("Found %d minidumps! Expecting 0 or 1", found)


    @staticmethod
    def poll_file(filename, poll_rate=0.1, idle_wait=1.5, timeout=60):
        """
        Wait for file modification to complete. This is done by monitoring the
        last modified time of the specified file.
        NOTE: This depends on file system data being updated and this might not be uniform
        across platforms, even different file systems on the same platform may act differently.

        @type filename: String
        @param filename: Name of the file to poll.

        @type poll_rate: float
        @param poll_rate: Frequency to check the file modification time.

        @type idle_wait: float
        @param idle_wait: Amount of time that must elapse without file modification to exit.

        @type timeout: float
        @param timeout: Amount of time in seconds to poll, None will poll forever.

        @rtype: int
        @return: file size in bytes or None on failure/timeout.
        """

        assert timeout is None or timeout > idle_wait, "timeout must be greater than idle_wait time"
        assert poll_rate <= idle_wait, "poll_rate must be less then or equal to idle_wait"
        if not os.path.isfile(filename):
            log.debug("Cannot poll %r. File does not exist", filename)
            return None
        start_time = time.time()
        while time.time() - os.stat(filename).st_mtime < idle_wait:
            if timeout is not None and start_time + timeout < time.time():
                log.warning("%r was still being modified after %0.2f seconds", filename, timeout)
                return None
            time.sleep(poll_rate)
        return os.stat(filename).st_size


    def log_length(self, log_id):
        """
        Get the length of the current browser log.

        @type log_id: String
        @param log_id: The id (key) of the log to clone (stderr, stdout... etc).

        @rtype: int
        @return: length of the current browser log in bytes.
        """
        return self._logs.log_length(log_id)


    def save_logs(self, log_path):
        """
        The browser logs will be saved to log_path.
        This should only be called after close().

        @type log_path: String
        @param log_path: File to create to contain log data. Existing files will be overwritten.

        @rtype: None
        @return: None
        """

        log.debug("save_logs() called, log_path is %r", log_path)
        if not self._logs.closed:
            raise RuntimeError("Logs are still in use. Call close() first!")

        self._logs.save_logs(log_path)


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
        assert self.closed, "self.closed is not True"
        assert self._logs.closed, "self._logs.closed is not True"
        assert self._proc is None, "self._proc is not None"
        assert self.profile is None, "self.profile is not None"
        assert not self._workers, "self._workers is not empty"


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


    def close(self, force_close=False):
        """
        Terminate the browser process and clean up all processes.

        @type force_close: bool
        @param force_close: Do not collect logs... etc, just make sure everything is closed

        @rtype: None
        @return: None
        """

        log.debug("close() called")
        if self.closed:
            self._logs.close() # make sure browser logs are also closed
            return

        # terminate the browser process
        if self._proc is not None:
            log.debug("firefox pid: %r", self._proc.pid)
            if self._proc.poll() is None:
                log.debug("process needs to be closed")
                self._terminate()
            self._proc.wait()

        # join worker threads and processes
        log.debug("joining %d worker(s)...", len(self._workers))
        for worker in self._workers:
            worker.join()

        log.debug("cleaning up workers...")
        log.debug("copying worker logs to stderr")
        stderr_log_fp = self._logs.get_fp("stderr")
        for worker in self._workers:
            if not force_close and worker.log_available():
                stderr_log_fp.write(b"\n")
                stderr_log_fp.write(("[ffpuppet worker]: %s\n" % worker.name).encode("utf-8"))
                worker.collect_log(dst_fp=stderr_log_fp)
                stderr_log_fp.write(b"\n")
            worker.clean_up()
        self._workers = list()

        if not force_close:
            # scan for ASan logs
            for fname in os.listdir(os.path.dirname(self._asan_prefix)):
                tmp_file = os.path.join(tempfile.gettempdir(), fname)
                if tmp_file.startswith(self._asan_prefix):
                    self.poll_file(tmp_file)
                    self._logs.add_log(fname, open(tmp_file, "rb"))

            # check for minidumps in the profile and dump them if possible
            self._dump_minidump_stacks()

        if self._proc is not None:
            self._logs.get_fp("stderr").write(
                ("[ffpuppet] Exit code: %r\n" % self._proc.returncode).encode("utf-8"))
            self._proc = None

        # close browser logger
        self._logs.close()

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

        @type extension: String, or list of Strings
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

        # extension support
        try:
            if extension is None:
                extensions = []
            elif isinstance(extension, (list, tuple)):
                extensions = extension
            else:
                extensions = [extension]
            if extensions and not os.path.isdir(os.path.join(profile, "extensions")):
                os.mkdir(os.path.join(profile, "extensions"))
            for ext in extensions:
                if os.path.isfile(ext) and ext.endswith(".xpi"):
                    shutil.copyfile(
                        ext,
                        os.path.join(profile, "extensions", os.path.basename(ext)))
                elif os.path.isdir(ext):
                    # read manifest to see what the folder should be named
                    ext_name = None
                    if os.path.isfile(os.path.join(ext, "manifest.json")):
                        try:
                            with open(os.path.join(ext, "manifest.json")) as manifest:
                                manifest = json.load(manifest)
                            ext_name = manifest["applications"]["gecko"]["id"]
                        except (IOError, KeyError, ValueError) as exc:
                            log.debug("Failed to parse manifest.json: %s", exc)
                    elif os.path.isfile(os.path.join(ext, "install.rdf")):
                        try:
                            xmlns = {"x": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                                     "em": "http://www.mozilla.org/2004/em-rdf#"}
                            tree = ElementTree.parse(os.path.join(ext, "install.rdf"))
                            assert tree.getroot().tag == "{%s}RDF" % xmlns["x"]
                            ids = tree.findall("./x:Description/em:id", namespaces=xmlns)
                            assert len(ids) == 1
                            ext_name = ids[0].text
                        except (AssertionError, IOError, ElementTree.ParseError) as exc:
                            log.debug("Failed to parse install.rdf: %s", exc)
                    if ext_name is None:
                        raise RuntimeError("Failed to find extension id in manifest: %r" % ext)
                    shutil.copytree(
                        os.path.abspath(ext),
                        os.path.join(profile, "extensions", ext_name))
                else:
                    raise RuntimeError("Unknown extension: %r" % ext)
        except:
            shutil.rmtree(profile, True) # clean up on failure
            raise
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

        # open logs
        self._logs.reset() # clean up existing log files
        self._logs.add_log("stderr")
        self._logs.add_log("stdout")
        stderr = self._logs.get_fp("stderr")
        stderr.write(b"[ffpuppet] Launch command: ")
        stderr.write(" ".join(cmd).encode("utf-8"))
        stderr.write(b"\n\n")
        stderr.flush()

        # launch the browser
        log.debug("launch command: %r", " ".join(cmd))
        self._proc = subprocess.Popen(
            cmd,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if self._platform == "windows" else 0,
            env=self.get_environ(bin_path),
            shell=False,
            stderr=stderr,
            stdout=self._logs.get_fp("stdout"))
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
            conn.sendall(response.encode("utf-8"))

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
        "-e", "--extension", action="append",
        help="Install the fuzzPriv extension (specify path to funfuzz/dom/extension)")
    parser.add_argument(
        "-g", "--gdb", action="store_true",
        help="Use GDB (Linux only)")
    parser.add_argument(
        "-l", "--log",
        help="Location to save log files")
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


def _dump_to_console(log_dir, dump_limit=0x20000):
    # order logs, make sure log_stderr is on the end
    log_list = os.listdir(log_dir)
    log_list.sort() # sort alphabetically
    order = ("log_stdout", "log_stderr")
    for l_order in order:
        found = None
        for fname in log_list:
            if fname.startswith(l_order):
                found = fname
                break
        # move to the end of the print list
        if found and log_list[-1] != found:
            log_list.remove(found)
            log_list.append(found)

    with tempfile.SpooledTemporaryFile(max_size=0x40000, mode="w+") as out_fp:
        for fname in log_list:
            full_path = os.path.join(log_dir, fname)
            fsize = os.stat(full_path).st_size / 1024.0
            out_fp.write("\n[Dumping log %r (%0.2fKB)]\n" % (fname, fsize))
            with open(full_path, "rb") as log_fp:
                out_fp.write(log_fp.read(dump_limit).decode("utf-8", errors="ignore"))
            if out_fp.tell() > dump_limit:
                out_fp.write("\nOutput exceeds %dKB! Log tailed. " % (dump_limit / 1024))
                out_fp.write("Use '--log' to capture full log.")
                break
        # python 3.2 and up only supports seeking from the start unless in binary mode
        dump_pos = max((out_fp.tell() - dump_limit), 0)
        out_fp.seek(dump_pos)
        return out_fp.read()


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
        if args.log is not None:
            ffp.save_logs(args.log)
        if args.dump:
            log_dir = tempfile.mkdtemp(prefix="ffp_log_")
            try:
                ffp.save_logs(log_dir)
                log.info("Dumping browser log...\n%s", _dump_to_console(log_dir))
            finally:
                if os.path.isdir(log_dir):
                    shutil.rmtree(log_dir)
        ffp.clean_up()
