#!/usr/bin/env python2
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
import urllib

try:
    import xvfbwrapper
except ImportError:
    pass

import debugger_windbg
import log_scanner
import memory_limiter


log = logging.getLogger("ffpuppet") # pylint: disable=invalid-name


def open_unique():
    """
    open_unique()
    Create a unique file.

    returns a File Object
    """

    tmp_fd, log_file = tempfile.mkstemp(
        suffix="_log.txt",
        prefix=time.strftime("ffp_%Y-%m-%d_%H-%M-%S_")
    )
    os.close(tmp_fd)

    # open with 'open' so the file object 'name' attribute is correct
    return open(log_file, "wb")


class LaunchError(Exception):
    pass


class FFPuppet(object):
    def __init__(self, use_profile=None, use_valgrind=False, use_windbg=False, use_xvfb=False):
        self._abort_tokens = set() # tokens used to notify log_scanner to kill the browser process
        self._log = None
        self._platform = platform.system().lower()
        self._proc = None
        self._profile = use_profile
        self._remove_profile = None # profile that needs to be removed when complete
        self._use_valgrind = use_valgrind
        self._windbg = use_windbg
        self._workers = list() # collection of threads and processes
        self._xvfb = None
        self._log_trim_pos = None

        if self._profile is not None:
            if not os.path.isdir(self._profile):
                raise IOError("Cannot find profile %s" % self._profile)
            self._profile = os.path.abspath(self._profile)

        if use_valgrind:
            try:
                with open(os.devnull, "w") as null_fp:
                    subprocess.call(["valgrind", "--version"], stdout=null_fp, stderr=null_fp)
            except OSError:
                raise EnvironmentError("Please install Valgrind")

        if use_windbg:
            if self._platform != "windows":
                raise EnvironmentError("WinDBG only available on Windows")
            if debugger_windbg.IMPORT_ERR:
                raise EnvironmentError("Please install PyKD")

        if use_xvfb:
            if self._platform != "linux":
                raise EnvironmentError("Xvfb is only supported on Linux")

            # This loop is a hack and is here because xvfbwrapper 0.2.8 doesn't
            # do a good job ensuring the process is running
            for tries_left in range(10, -1, -1):
                try:
                    try:
                        self._xvfb = xvfbwrapper.Xvfb(width=1280, height=1024)
                    except NameError:
                        raise EnvironmentError("Please install xvfbwrapper")
                    self._xvfb.start()
                    time.sleep(1)
                    if self._xvfb.proc.poll() is not None:
                        raise RuntimeError("Xvfb isn't running after start() is called")
                except RuntimeError:
                    if tries_left:
                        continue
                    raise
                break


    def _create_environ(self, target_bin):
        env = os.environ
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
                #"alloc_dealloc_mismatch=false", # different defaults per OS
                "allocator_may_return_null=false",
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
            symbolizer_bin = os.path.join(os.path.dirname(target_bin), "llvm-symbolizer")
            if os.path.isfile(symbolizer_bin):
                env["ASAN_SYMBOLIZER_PATH"] = symbolizer_bin
                env["MSAN_SYMBOLIZER_PATH"] = symbolizer_bin

        return env


    def add_abort_token(self, token):
        self._abort_tokens.add(token)


    def trim_log(self):
        self._log_trim_pos = self._log.tell()


    def save_log(self, log_file):
        """
        save_log(log_file) -> None
        The log will be saved to log_file. Should only be called after close().

        Return None
        """

        if self._log is None:
            return

        if self.is_running():
            raise RuntimeError("Log is still in use. Call close() first!")

        if self._log_trim_pos is None:
            with open(log_file, "w") as out_file:
                with open(self._log.name) as in_file:
                    in_file.seek(self._log_trim_pos)
                    out_file.write(in_file.read())
            os.unlink(self._log.name)
        else:
            # move log to location specified by log_file
            if os.path.isfile(self._log.name):
                if not os.path.dirname(log_file):
                    log_file = os.path.join(os.getcwd(), log_file)
                shutil.move(self._log.name, log_file)


    def clean_up(self):
        """
        clean_up() -> None
        Remove all the remaining files that could have been created during execution.

        returns None
        """

        self._abort_tokens = set()
        self._proc = None
        if self._log is not None and os.path.isfile(self._log.name):
            os.remove(self._log.name)


    def close(self):
        """
        close() -> None
        Terminate the browser process and clean up all processes.

        returns None
        """

        # terminate the browser process
        if self._proc is not None:
            if self._proc.poll() is None:
                self._proc.terminate()
            self._proc.wait()
            if not self._log.closed:
                self._log.write("[Exit code: %r]\n" % self._proc.poll())

        # join worker threads and processes
        for worker in self._workers:
            worker.join()
            worker_log = None if self._log.closed else worker.collect_log()

            # copy worker logs to main log if is exists and contains data
            if worker_log:
                self._log.write("\n")
                self._log.write("[Worker: %s]\n" % worker.name)
                self._log.write(worker_log)
                self._log.write("\n")
            worker.clean_up()

        # clear out old workers
        self._workers = list()

        # close Xfvb
        if self._xvfb is not None:
            self._xvfb.stop()

        # close log
        if self._log is not None and not self._log.closed:
            self._log.close()

        # remove temporary profile directory if necessary
        if self._remove_profile and os.path.isdir(self._remove_profile):
            shutil.rmtree(self._remove_profile)
            self._profile = None # a temporary profile was use so reset self._profile


    def get_pid(self):
        """
        get_pid() -> int

        returns the process ID of the browser process
        """
        return None if self._proc is None else self._proc.pid


    def launch(self, bin_path, launch_timeout=300, location=None, memory_limit=None,
               prefs_js=None, safe_mode=False):
        """
        launch(bin_path[, launch_timout, location, memory_limit, pref_js, safe_mode])
        Launch a new browser process using the binary specified with bin_path. Optional limits
        can be set for time to launch the browser by setting launch_timeout (default: 300 seconds)
        or the maximum amount of memory the browser can use by setting memory_limit (default: None).
        The URL loaded by default can be set with location. prefs_js allows a custom prefs.js
        file to be specified. safe_mode is a boolean indicating whether or not to launch the
        browser in "safe mode". WARNING: Launching in safe mode blocks with a dialog that must be
        dismissed manually.

        returns None
        """
        if self._proc is not None:
            raise LaunchError("Process is already running")

        bin_path = os.path.abspath(bin_path)
        if not os.path.isfile(bin_path) or not os.access(bin_path, os.X_OK):
            raise IOError("%s is not an executable" % bin_path)

        if memory_limit is not None and memory_limiter.IMPORT_ERR:
            raise EnvironmentError("Please install psutil")

        env = self._create_environ(bin_path)
        launch_timeout = max(launch_timeout, 10) # force 10 seconds minimum launch_timeout

        # create temp profile directory if needed
        if self._profile is None:
            self._profile = tempfile.mkdtemp(prefix="ffprof_")
            if prefs_js:
                shutil.copyfile(prefs_js, os.path.join(self._profile, "prefs.js"))
            # since this is a temp profile director it should be removed
            self._remove_profile = self._profile

        # Performing the bootstrap helps guarantee that the browser
        # will be loaded and ready to accept input when launch() returns
        init_soc = self._bootstrap_start(timeout=launch_timeout)

        # build Firefox launch command
        cmd = [
            bin_path,
            "-no-remote",
            "-profile",
            self._profile,
            "http://127.0.0.1:%d" % init_soc.getsockname()[1]]

        if safe_mode:
            cmd.append("-safe-mode")

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
                "--trace-children=yes",
                #"--track-origins=yes",
                "--vex-iropt-register-updates=allregs-at-mem-access"] + cmd # enable valgrind

        self._log = open_unique()
        self._log.write("Launch command: %s\n\n" % " ".join(cmd))
        self._log.flush()

        # launch the browser
        self._proc = subprocess.Popen(
            cmd,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if self._platform == "windows" else 0,
            env=env,
            shell=False,
            stderr=self._log,
            stdout=self._log)

        self._bootstrap_finish(init_soc, timeout=launch_timeout, url=location)

        if memory_limit is not None:
            # launch memory monitor thread
            self._workers.append(memory_limiter.MemoryLimiterWorker())
            self._workers[-1].start(self._proc.pid, memory_limit)

        if self._windbg:
            # launch pykd debugger
            self._workers.append(debugger_windbg.DebuggerPyKDWorker())
            self._workers[-1].start(self._proc.pid)

        if self._use_valgrind:
            self._abort_tokens.add(re.compile(r"==\d+==\s"))

        if self._abort_tokens:
            # launch log scanner thread
            self._workers.append(log_scanner.LogScannerWorker())
            self._workers[-1].start(self)


    def is_running(self):
        """
        is_running() -> bool
        Check if the browser process is running.

        returns True if the process is running otherwise False
        """
        return self._proc is not None and self._proc.poll() is None


    def _bootstrap_start(self, timeout=60):
        while True:
            try:
                init_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                init_soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                init_soc.settimeout(timeout) # don't catch socket.timeout
                init_soc.bind(("127.0.0.1", random.randint(0x2000, 0xFFFF)))
                init_soc.listen(5)
                break
            except socket.error as soc_e:
                if soc_e.errno == errno.EADDRINUSE: # Address already in use
                    continue
                raise soc_e
        with open(os.path.join(self._profile, "prefs.js"), "a") as prefs_fp:
            prefs_fp.write("user_pref('capability.policy.policynames', 'localfilelinks');\n")
            prefs_fp.write("user_pref('capability.policy.localfilelinks.sites', "
                           "'http://127.0.0.1:%d');\n" % init_soc.getsockname()[1])
            prefs_fp.write("user_pref('capability.policy.localfilelinks.checkloaduri.enabled', 'allAccess');\n")
        return init_soc


    def _bootstrap_finish(self, init_soc, timeout=60, url=None):
        conn = None
        timer_start = time.time()
        try:
            # wait for browser test connection
            while True:
                try:
                    init_soc.settimeout(1.0)
                    conn, _ = init_soc.accept()
                    conn.settimeout(timeout)
                except socket.timeout:
                    if (time.time() - timer_start) >= timeout:
                        # timeout waiting browser connection
                        raise LaunchError("Launching browser timed out")
                    elif not self.is_running():
                        # browser must have died
                        raise LaunchError("Failure during browser startup")
                    continue # have not received connection
                break # received connection

            # handle browser test connection incoming data
            while len(conn.recv(4096)) == 4096:
                pass

            if url is not None and os.path.isfile(url):
                url = 'file:%s' % urllib.pathname2url(os.path.abspath(url))

            # redirect to about:blank
            body = "<script>window.onload=function(){window.location='%s'}</script>" % (
                "about:blank" if url is None else url)

            # send response
            conn.sendall(
                "HTTP/1.1 200 OK\r\n" \
                "Cache-Control: max-age=0, no-cache\r\n" \
                "Content-Length: %s\r\n" \
                "Content-Type: text/html; charset=UTF-8\r\n" \
                "Connection: close\r\n\r\n%s" % (len(body), body)
            )

        except socket.error:
            raise LaunchError("Failed to launch browser")

        except socket.timeout:
            raise LaunchError("Test connection timed out")

        finally:
            if conn is not None:
                conn.close()
            init_soc.close()


    def wait(self, timeout=0):
        """
        wait([timeout]) -> int
        Wait for process to terminate. This call will block until the process exits unless
        a timeout is specified. If a timeout greater than zero is specified the call will
        only block until the timeout expires.

        returns exit code if process exits and None if timeout expired
        """
        timer_exp = time.time() + timeout
        while True:
            if timeout > 0 and timer_exp <= time.time():
                break
            if self._proc.poll() is not None:
                return self._proc.poll()
            time.sleep(0.1)

        return None


def main():

    if len(logging.getLogger().handlers) == 0:
        logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)

    parser = argparse.ArgumentParser(description="Firefox launcher/wrapper")
    parser.add_argument(
        "binary",
        help="Firefox binary to execute")
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
        help="Profile to use. A temporary profile is generated by default.")
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
        "--windbg", action="store_true",
        help="Collect crash log with WinDBG (Windows only)")
    parser.add_argument(
        "--xvfb", action="store_true",
        help="Use xvfb (Linux only)")

    args = parser.parse_args()

    ffp = FFPuppet(
        use_profile=args.profile,
        use_valgrind=args.valgrind,
        use_windbg=args.windbg,
        use_xvfb=args.xvfb)
    try:
        ffp.launch(
            args.binary,
            location=args.url,
            launch_timeout=args.timeout,
            memory_limit=args.memory * 1024 * 1024 if args.memory else None,
            prefs_js=args.prefs,
            safe_mode=args.safe_mode)
        log.info("Running firefox (pid: %d)...", ffp.get_pid())
        ffp.wait()
    except KeyboardInterrupt:
        log.info("Ctrl+C detected. Shutting down...")
    finally:
        ffp.close()
        if args.log:
            ffp.save_log(args.log)
        ffp.clean_up()


if __name__ == "__main__":
    main()

