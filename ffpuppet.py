#!/usr/bin/env python2
import argparse
import os
import platform
import random
import shutil
import socket
import subprocess
import tempfile
import threading
import time

try:
    import psutil
except ImportError:
    pass


def proc_memory_monitor(proc, limit):
    """
    proc_memory_monitor(proc, limit)
    Use psutil to actively monitor the amount of memory in use by proc. If that
    amount exceeds limit the process will be terminated.

    returns None
    """
    try:
        ps_proc = psutil.Process(proc.pid)
    except psutil.NoSuchProcess:
        # process is dead?
        return

    while proc.poll() is None:
        try:
            proc_mem = ps_proc.memory_info().rss
            for child in ps_proc.children(recursive=True):
                try:
                    proc_mem += child.memory_info().rss
                except psutil.NoSuchProcess:
                    pass
        except psutil.NoSuchProcess:
            # process is dead?
            break

        # did we hit the memory limit?
        if proc_mem >= limit:
            proc.terminate()
            break

        time.sleep(0.1) # check 10x a second


class LaunchException(Exception):
    pass


class FFPuppet(object):
    def __init__(self, use_profile=None, use_valgrind=False, use_xvfb=False):
        self._display = ":0"
        self._exit_code = None
        self._log = None
        self._log_fp = None
        self._nul = None
        self._mem_mon_thread = None
        self._platform = platform.system().lower()
        self._proc = None
        self._profile_dir = use_profile
        self._tmp_prof = use_profile is None # remove temp profile
        self._use_valgrind = use_valgrind
        self._xvfb = None

        if self._profile_dir is not None:
            if not os.path.isdir(self._profile_dir):
                raise IOError("Cannot find profile %s" % self._profile_dir)
            self._profile_dir = os.path.abspath(self._profile_dir)

        if use_valgrind:
            with open(os.devnull, "w") as fp:
                subprocess.call(
                    ["valgrind", "--version"],
                    stdout=fp,
                    stderr=fp) # TODO: improve this check

        if use_xvfb:
            self._nul = open(os.devnull, "w")
            # launch Xvfb
            for _ in range(10):
                # Find a screen value not in use.
                # NOTE: this limits number of possible Xvfb instances but 255 is lots
                self._display = ":%d" % random.randint(1, 255)
                try:
                    self._xvfb = subprocess.Popen(
                        ["/usr/bin/Xvfb", self._display, "-screen", "0", "1280x1024x24"],
                        shell=False,
                        stdout=self._nul,
                        stderr=self._nul
                    )
                    time.sleep(0.5) # wait to be sure Xvfb is running and doesn't just exit
                    if self._xvfb.poll() is None:
                        break # xvfb is running
                except OSError:
                    self._nul.close()
                    raise LaunchException("Could not find Xvfb!")

            if self._xvfb.poll() is not None:
                self._nul.close()
                raise LaunchException("Could not launch Xvfb!")


    def close(self, save_log=None):
        """
        close([save_log])
        Terminate the browser process and clean up all other open files and processes. The log will
        be saved to save_log if a file name is given.

        returns None
        """
        if self._proc is not None:
            if self._proc.poll() is None:
                self._proc.terminate()
            self._exit_code = self._proc.wait()

        if self._log_fp is not None:
            self._log_fp.write("[Exit code: %r]\n" % self._exit_code)
            self._log_fp.close()

            if save_log and os.path.isfile(self._log):
                if not os.path.dirname(save_log):
                    save_log = os.path.join(os.getcwd(), save_log)
                shutil.move(self._log, save_log)
            elif os.path.isfile(self._log):
                os.remove(self._log)

        # remove temporary profile directory
        if self._tmp_prof and self._profile_dir is not None and os.path.isdir(self._profile_dir):
            shutil.rmtree(self._profile_dir)

        # close Xfvb
        if self._xvfb is not None and self._xvfb.poll() is None:
            self._xvfb.terminate()
            self._xvfb.wait()

        if self._nul is not None:
            self._nul.close()

        if self._mem_mon_thread is not None:
            self._mem_mon_thread.join()


    def get_pid(self):
        """
        get_pid() -> int

        returns the process ID of the browser process
        """
        return None if self._proc is None else self._proc.pid


    def launch(self, bin_path, launch_timeout=300, location=None, memory_limit=None, prefs_js=None):
        """
        launch(bin_path[, launch_timout, location, memory_limit, pref_js])
        Launch a new browser process using the binary specified with bin_path. Optional limits
        can be set for time to launch the browser by setting launch_timeout (default: 300 seconds)
        or the maximum amount of memory the browser can use by setting memory_limit (default: None).
        The URL loaded by default can be set with location. A custom prefs.js file can also be
        specified.

        returns None
        """
        if launch_timeout is None or launch_timeout < 1:
            raise LaunchException("Launch timeout must be >= 1")

        bin_path = os.path.abspath(bin_path)
        if not os.path.isfile(bin_path):
            raise IOError("%s does not exist" % bin_path)

        env = os.environ
        env["DISPLAY"] = self._display
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
        if "ASAN_OPTIONS" not in env:
            env["ASAN_OPTIONS"] = " ".join((
                "alloc_dealloc_mismatch=0",
                "allocator_may_return_null=0",
                "check_initialization_order=1",
                "check_malloc_usable_size=0",
                #"detect_leaks=1",
                "detect_stack_use_after_return=0",
                "disable_core=1",
                "strict_init_order=1",
                "strict_memcmp=0",
                "symbolize=1"
            ))

        if os.path.isfile(os.path.join(os.path.dirname(bin_path), "llvm-symbolizer")):
            env["ASAN_SYMBOLIZER_PATH"] = os.path.join(os.path.dirname(bin_path), "llvm-symbolizer")
            env["MSAN_SYMBOLIZER_PATH"] = os.path.join(os.path.dirname(bin_path), "llvm-symbolizer")
        if "ASAN_SYMBOLIZER_PATH" in os.environ:
            env["ASAN_SYMBOLIZER_PATH"] = os.environ["ASAN_SYMBOLIZER_PATH"]
            env["MSAN_SYMBOLIZER_PATH"] = os.environ["ASAN_SYMBOLIZER_PATH"]
            if not os.path.isfile(env["ASAN_SYMBOLIZER_PATH"]):
                print("WARNING: Invalid ASAN_SYMBOLIZER_PATH (%s)" % (
                    env["ASAN_SYMBOLIZER_PATH"]
                ))

        if self._profile_dir is None:
            self._profile_dir = tempfile.mkdtemp(prefix="ffprof_")
            if prefs_js:
                shutil.copyfile(prefs_js, os.path.join(self._profile_dir, "prefs.js"))

        fd, self._log = tempfile.mkstemp(
            suffix="_log.txt",
            prefix=time.strftime("ffp_%Y-%m-%d_%H-%M-%S_")
        )
        self._log_fp = os.fdopen(fd, "wb")

        init_soc = self._bootstrap_start(timeout=launch_timeout)
        # build Firefox launch command
        cmd = [
            bin_path,
            "-no-remote",
            "-profile",
            self._profile_dir,
            "http://127.0.0.1:%d" % init_soc.getsockname()[1]
        ]

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
                "--vex-iropt-register-updates=allregs-at-mem-access"
            ] + cmd # enable valgrind

        if self._platform == "windows":
            self._proc = subprocess.Popen(
                cmd,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                env=env,
                shell=False,
                stderr=self._log_fp,
                stdout=self._log_fp
            )
        else: # not windows
            self._proc = subprocess.Popen(
                cmd,
                env=env,
                shell=False,
                stderr=self._log_fp,
                stdout=self._log_fp
            )

        self._bootstrap_finish(init_soc, timeout=launch_timeout, url=location)

        if memory_limit is not None:
            # launch memory monitor thread
            self._mem_mon_thread = threading.Thread(
                target=proc_memory_monitor,
                args=(self._proc, memory_limit)
            )
            self._mem_mon_thread.start()


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
                init_soc.settimeout(timeout) # don"t catch socket.timeout
                init_soc.bind(("127.0.0.1", random.randint(1024, 0xFFFF)))
                init_soc.listen(0)
                break
            except socket.error as soc_e:
                if soc_e.errno == 98: # Address already in use
                    continue
                raise soc_e
        with open(os.path.join(self._profile_dir, "prefs.js"), "a") as fp:
            fp.write("user_pref('capability.policy.policynames', 'localfilelinks');\n")
            fp.write("user_pref('capability.policy.localfilelinks.sites', 'http://127.0.0.1:%d');\n" % init_soc.getsockname()[1])
            fp.write("user_pref('capability.policy.localfilelinks.checkloaduri.enabled', 'allAccess');\n")
        return init_soc


    def _bootstrap_finish(self, init_soc, timeout=60, url=None):
        conn = None
        max_wait_time = time.time() + timeout
        try:
            # wait for browser test connection
            while True:
                try:
                    init_soc.settimeout(1.0)
                    conn, _ = init_soc.accept()
                    conn.settimeout(timeout)
                except socket.timeout:
                    if max_wait_time <= time.time():
                        # timeout waiting browser connection
                        raise LaunchException("Launching browser timed out")
                    elif not self.is_running():
                        # browser must have died
                        raise LaunchException("Failure during browser startup")
                    continue # have not received connection
                break # received connection

            # handle browser test connection in coming data
            while len(conn.recv(4096)) == 4096:
                pass

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
            raise LaunchException("Failed to launch browser")

        except socket.timeout:
            raise LaunchException("Test connection timed out")

        finally:
            if conn is not None:
                conn.close()
            init_soc.close()


    def read_log(self, offset=None, from_what=os.SEEK_SET, count=None):
        """
        read_log([offset, from_what, count]) -> string
        Read the contents of the log file. offset specifies where to move to before reading,
        from_what specified where to move from and count is the number of bytes to read.

        returns a string containing the contents for the log file
        """

        with open(self._log, "r") as fp:
            if offset is not None:
                fp.seek(offset, from_what)

            if count:
                return fp.read(count)
            return fp.read()


    def wait(self, timeout=0):
        """
        wait([timeout]) -> int
        Wait for process to terminate. This call will block until the process exits unless
        a timeout is specified. If a timeout is specified the call will only block until the
        timeout expires.

        returns return code if process exits and None if timeout expired
        """

        if timeout <= 0:
            return self._proc.wait() # blocks until process exits

        end = time.time() + timeout
        while time.time() < end:
            if self._proc.poll() is not None:
                return self._proc.poll()
            time.sleep(0.1)

        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firefox launcher/wrapper")
    parser.add_argument(
        "binary",
        help="Binary to run")
    parser.add_argument(
        "-l", "--log",
        help="log file name")
    parser.add_argument(
        "-m", "--memory", type=int,
        help="Process memory limit in MBs")
    parser.add_argument(
        "-p", "--prefs",
        help="prefs.js file to use")
    parser.add_argument(
        "-P", "--profile",
        help="profile to use")
    parser.add_argument(
        "-t", "--timeout", type=int, default=60,
        help="launch timeout")
    parser.add_argument(
        "-u", "--url",
        help="URL to load")
    parser.add_argument(
        "--valgrind", default=False, action="store_true",
        help="Use valgrind")
    parser.add_argument(
        "--xvfb", default=False, action="store_true",
        help="Use xvfb")

    args = parser.parse_args()

    ffp = FFPuppet(
        use_profile=args.profile,
        use_valgrind=args.valgrind,
        use_xvfb=args.xvfb)
    try:
        ffp.launch(
            args.binary,
            location=args.url,
            launch_timeout=args.timeout,
            memory_limit=args.memory * 1024 * 1024 if args.memory else None,
            prefs_js=args.prefs)
        ffp.wait()
    except KeyboardInterrupt:
        print("Ctrl+C detected. Shutting down...")
    finally:
        ffp.close(args.log)

