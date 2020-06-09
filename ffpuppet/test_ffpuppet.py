# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=invalid-name,protected-access
"""ffpuppet tests"""
import errno
from http.server import HTTPServer, BaseHTTPRequestHandler
import os
import platform
import shutil
import socket
import stat
from subprocess import call, check_output
import threading
import time

from psutil import AccessDenied, NoSuchProcess, Process, wait_procs
import pytest

from .core import FFPuppet
from .exceptions import BrowserTimeoutError, BrowserTerminatedError, LaunchError
from .helpers import get_processes
from .minidump_parser import MinidumpParser

CWD = os.path.realpath(os.path.dirname(__file__))
TESTFF_BIN = os.path.join(CWD, "resources", "testff.py")
TESTMDSW_BIN = os.path.join(CWD, "resources", "testmdsw.py")

MinidumpParser.MDSW_BIN = TESTMDSW_BIN
MinidumpParser.MDSW_MAX_STACK = 8


class ReqHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"hello world")


class HTTPTestServer(object):
    def __init__(self, handler=None):
        self._handler = handler if handler is not None else ReqHandler
        while True:
            try:
                self._httpd = HTTPServer(("127.0.0.1", 0), self._handler)
            except socket.error as soc_e:
                if soc_e.errno in (errno.EADDRINUSE, 10013):  # Address already in use
                    continue
                raise
            break
        self._thread = threading.Thread(target=HTTPTestServer._srv_thread, args=(self._httpd,))
        self._thread.start()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.shutdown()

    def get_addr(self):
        return "http://127.0.0.1:%d" % (self._httpd.server_address[1],)

    def shutdown(self):
        if self._httpd is not None:
            self._httpd.shutdown()
        if self._thread is not None:
            self._thread.join()

    @staticmethod
    def _srv_thread(httpd):
        try:
            httpd.serve_forever()
        finally:
            httpd.socket.close()


@pytest.mark.skipif(platform.system() == "Windows",
                    reason="Unsupported on Windows")
def test_ffpuppet_00(tmp_path):
    """test that invalid executables raise the right exception"""
    with FFPuppet() as ffp:
        with pytest.raises(IOError, match="is not an executable"):
            ffp.launch(str(tmp_path))

def test_ffpuppet_01():
    """test basic launch and close"""
    with FFPuppet() as ffp:
        assert ffp.launches == 0
        assert ffp.reason == ffp.RC_CLOSED
        with HTTPTestServer() as srv:
            ffp.launch(TESTFF_BIN, location=srv.get_addr())
        assert not ffp._checks
        assert ffp.launches == 1
        assert not ffp.wait(timeout=0)
        assert ffp.is_running()
        assert ffp.is_healthy()
        assert ffp.reason is None
        ffp.close()
        assert ffp.reason == ffp.RC_CLOSED
        assert ffp._proc is None
        assert not ffp.is_running()
        assert not ffp.is_healthy()
        assert ffp.wait(timeout=10)

def test_ffpuppet_02(tmp_path):
    """test crash on start"""
    with FFPuppet() as ffp:
        prefs = (tmp_path / "prefs.js")
        prefs.write_bytes(b"//fftest_startup_crash\n")
        with pytest.raises(BrowserTerminatedError, match="Failure waiting for browser connection"):
            ffp.launch(TESTFF_BIN, prefs_js=str(prefs))
        ffp.close()
        assert not ffp.is_running()  # process should be gone
        assert ffp.launches == 0
        assert ffp.reason == ffp.RC_ALERT

def test_ffpuppet_03(tmp_path):
    """test hang on start"""
    with FFPuppet() as ffp:
        ffp.LAUNCH_TIMEOUT_MIN = 1
        prefs = (tmp_path / "prefs.js")
        prefs.write_bytes(b"//fftest_startup_hang\n")
        start = time.time()
        with pytest.raises(BrowserTimeoutError, match="Timeout waiting for browser connection"):
            ffp.launch(TESTFF_BIN, prefs_js=str(prefs), launch_timeout=1)
        duration = time.time() - start
        ffp.close()
        assert ffp.reason == ffp.RC_CLOSED
        assert duration >= ffp.LAUNCH_TIMEOUT_MIN
        assert duration < 30

def test_ffpuppet_04(tmp_path):
    """test logging"""
    with FFPuppet() as ffp:
        ffp.close()
        ffp.save_logs(str(tmp_path / "no_logs"))
        prefs = (tmp_path / "prefs.js")
        prefs.write_bytes(b"//fftest_exit_code_0\n")
        with HTTPTestServer() as srv:
            ffp.launch(TESTFF_BIN, location=srv.get_addr(), prefs_js=str(prefs))
            ffp.wait(timeout=10)
            ffp.close()
        assert ffp._logs.closed
        log_ids = ffp.available_logs()
        assert len(log_ids) == 2
        assert "stderr" in log_ids
        assert "stdout" in log_ids
        logs = (tmp_path / "logs")  # nonexistent directory
        ffp.save_logs(str(logs), meta=True)
        assert logs.is_dir()
        assert len(tuple(logs.glob("*"))) == 3
        log_data = (logs / "log_stderr.txt").read_text()
        assert "[ffpuppet] Launch command:" in log_data
        assert "[ffpuppet] Reason code:" in log_data
        log_data = (logs / "log_stdout.txt").read_text()
        assert "url: 'http://" in log_data
        assert "hello world" in log_data
        assert any(logs.glob(ffp._logs.META_FILE))

def test_ffpuppet_05():
    """test get_pid()"""
    with FFPuppet() as ffp:
        assert ffp.get_pid() is None
        with HTTPTestServer() as srv:
            ffp.launch(TESTFF_BIN, location=srv.get_addr())
            assert ffp.get_pid() > 0
            ffp.close()
        assert ffp.get_pid() is None

def test_ffpuppet_06():
    """test is_running()"""
    with FFPuppet() as ffp:
        assert not ffp.is_running()
        with HTTPTestServer() as srv:
            ffp.launch(TESTFF_BIN, location=srv.get_addr())
            assert ffp.is_running()
            ffp.close()
        assert not ffp.is_running()
        assert not ffp.is_running()  # call 2x

def test_ffpuppet_07(tmp_path):
    """test wait()"""
    with FFPuppet() as ffp:
        assert ffp.wait()
        prefs = (tmp_path / "prefs.js")
        prefs.write_bytes(b"//fftest_exit_code_0\n")
        with HTTPTestServer() as srv:
            ffp.launch(TESTFF_BIN, location=srv.get_addr(), prefs_js=str(prefs))
            assert ffp.wait(timeout=10)
            ffp.close()
            assert ffp.reason == ffp.RC_EXITED
            ffp.launch(TESTFF_BIN, location=srv.get_addr())
            assert ffp.is_running()
            assert not ffp.wait(timeout=0)
            ffp.close()
            assert ffp.reason == ffp.RC_CLOSED
            assert ffp.wait(timeout=0)

def test_ffpuppet_08(tmp_path):
    """test clone_log()"""
    logs = (tmp_path / "logs.txt")
    with FFPuppet() as ffp:
        assert ffp.clone_log("stdout", target_file=str(logs)) is None
        with HTTPTestServer() as srv:
            ffp.launch(TESTFF_BIN, location=srv.get_addr())
            ffp.wait(timeout=0.25)  # wait for log prints
            # make sure logs are available
            assert ffp.clone_log("stdout", target_file=str(logs)) == str(logs)
            orig = logs.read_text()
            assert len(orig) > 5
            assert ffp.clone_log("stdout", target_file=str(logs), offset=5) == str(logs)
            assert logs.read_text() == orig[5:]
            # grab log without giving a target file name
            rnd_log = ffp.clone_log("stdout")
            assert rnd_log is not None
            try:
                ffp.close()
                # make sure logs are available
                assert ffp.clone_log("stdout", target_file=str(logs)) == str(logs)
                assert logs.read_text().startswith(orig)
            finally:
                if os.path.isfile(rnd_log):
                    os.remove(rnd_log)
        ffp.clean_up()
        # verify clean_up() removed the logs
        assert ffp.clone_log("stdout", target_file=str(logs)) is None

def test_ffpuppet_09(tmp_path):
    """test hitting memory limit"""
    with FFPuppet() as ffp:
        prefs = (tmp_path / "prefs.js")
        prefs.write_bytes(b"//fftest_memory\n")
        with HTTPTestServer() as srv:
            # launch with 1MB memory limit
            ffp.launch(TESTFF_BIN, location=srv.get_addr(), prefs_js=str(prefs), memory_limit=0x100000)
            for _ in range(100):
                if not ffp.is_healthy():
                    break
                time.sleep(0.1)
            ffp.close()
        assert ffp.reason == ffp.RC_WORKER
        assert len(ffp.available_logs()) == 3
        logs = (tmp_path / "logs")
        ffp.save_logs(str(logs))
    worker_log = (logs / "log_ffp_worker_memory_usage.txt")
    assert worker_log.is_file()
    assert "MEMORY_LIMIT_EXCEEDED" in worker_log.read_text()

def test_ffpuppet_10():
    """test calling launch() multiple times"""
    with FFPuppet() as ffp:
        with HTTPTestServer() as srv:
            for _ in range(10):
                ffp.launch(TESTFF_BIN, location=srv.get_addr())
                ffp.close()
            # call 2x without calling close()
            ffp.launch(TESTFF_BIN, location=srv.get_addr())
        with pytest.raises(LaunchError, match="Process is already running"):
            ffp.launch(TESTFF_BIN)
        assert ffp.launches == 11
        ffp.close()

def test_ffpuppet_11(tmp_path):
    """test abort tokens"""
    prefs = (tmp_path / "prefs.js")
    prefs.write_bytes(b"//fftest_soft_assert\n")
    with FFPuppet() as ffp:
        ffp.add_abort_token(r"TEST\dREGEX\.+")
        ffp.add_abort_token("simple_string")
        with pytest.raises(AssertionError):
            ffp.add_abort_token(None)
        ffp.add_abort_token(r"ASSERTION:\s\w+")
        with HTTPTestServer() as srv:
            ffp.launch(TESTFF_BIN, location=srv.get_addr(), prefs_js=str(prefs))
            for _ in range(200):
                if not ffp.is_healthy():
                    break
                time.sleep(0.05)
            ffp.close()
        assert ffp.reason == ffp.RC_WORKER
        assert len(ffp.available_logs()) == 3
        logs = (tmp_path / "logs")
        ffp.save_logs(str(logs))
        worker_log = (logs / "log_ffp_worker_log_contents.txt")
        assert worker_log.is_file()
        assert b"TOKEN_LOCATED: ASSERTION: test" in worker_log.read_bytes()

def test_ffpuppet_12(tmp_path):
    """test using an existing profile directory"""
    prf_dir = tmp_path / "ffp_test_prof"
    prf_dir.mkdir()
    with FFPuppet(use_profile=str(prf_dir)) as ffp:
        ffp.launch(TESTFF_BIN)
    assert prf_dir.is_dir()

def test_ffpuppet_13():
    """test calling close() and clean_up() in multiple states"""
    with FFPuppet() as ffp:
        ffp.close()
        with HTTPTestServer() as srv:
            ffp.launch(TESTFF_BIN, location=srv.get_addr())
            assert ffp.reason is None
            ffp.close()
            ffp.clean_up()
            with pytest.raises(AssertionError):
                ffp.launch(TESTFF_BIN, location=srv.get_addr())
            with pytest.raises(AssertionError):
                ffp.close()

def test_ffpuppet_14():
    """test launching under Xvfb"""
    if platform.system() != "Linux":
        with pytest.raises(EnvironmentError, match="Xvfb is only supported on Linux"):
            FFPuppet(use_xvfb=True)
    else:
        with FFPuppet(use_xvfb=True) as _:
            pass

def test_ffpuppet_15(tmp_path):
    """test passing a file and a non existing file to launch() via location"""
    with FFPuppet() as ffp:
        with pytest.raises(IOError, match="Cannot find"):
            ffp.launch(TESTFF_BIN, location="missing.file")
        ffp.close()
        prefs = (tmp_path / "prefs.js")
        prefs.write_bytes(b"//fftest_exit_code_0\n")
        test_file = (tmp_path / "test_file")
        test_file.write_bytes(b"test")
        # needs realpath() for OSX & normcase() for Windows
        fname = os.path.normcase(os.path.realpath(str(test_file)))
        ffp.launch(TESTFF_BIN, location=fname, prefs_js=str(prefs))
        ffp.wait(timeout=10)
        ffp.close()
        logs = (tmp_path / "logs")
        ffp.save_logs(str(logs))
        with (logs / "log_stdout.txt").open("r") as log_fp:
            assert "url: 'file:///" in log_fp.read()
            log_fp.seek(0)
            for line in log_fp:
                if "file:///" in line:
                    location = os.path.normcase(line.split("'")[1].split("file:///")[1])
                    break
            else:
                assert False, "Could not parse location"
        assert not location.startswith("/")
        assert os.path.normpath(os.path.join("/", location)) == fname

def test_ffpuppet_16():
    """test passing nonexistent file to launch() via prefs_js"""
    with FFPuppet() as ffp:
        with pytest.raises(IOError, match="prefs.js file does not exist"):
            ffp.launch(TESTFF_BIN, prefs_js="missing.js")

@pytest.mark.skipif(platform.system() == "Linux" and call(["which", "gdb"]),
                    reason="GDB not installed")
def test_ffpuppet_17(tmp_path):
    """test launching with gdb"""
    if platform.system() != "Linux":
        with pytest.raises(EnvironmentError, match="GDB is only supported on Linux"):
            FFPuppet(use_gdb=True)
        return
    with FFPuppet(use_gdb=True) as ffp:
        bin_path = str(check_output(["which", "echo"]).strip().decode("ascii"))
        # launch will fail b/c 'echo' will exit right away but that's fine
        with pytest.raises(LaunchError, match="Failure waiting for browser connection"):
            ffp.launch(bin_path)
        ffp.close()
        logs = (tmp_path / "logs")
        ffp.save_logs(str(logs))
        log_data = (logs / "log_stdout.txt").read_bytes()
        # verify GDB ran and executed the script
        assert b"[Inferior " in log_data
        assert b"quit_with_code" in log_data

def test_ffpuppet_18(tmp_path):
    """test calling save_logs() before close()"""
    with FFPuppet() as ffp:
        with HTTPTestServer() as srv:
            ffp.launch(TESTFF_BIN, location=srv.get_addr())
            with pytest.raises(AssertionError):
                ffp.save_logs(str(tmp_path / "logs"))

@pytest.mark.skipif(platform.system() == "Linux" and call(["which", "valgrind"]),
                    reason="Valgrind not installed")
def test_ffpuppet_19(tmp_path):
    """test launching with Valgrind"""
    if platform.system() != "Linux":
        with pytest.raises(EnvironmentError, match="Valgrind is only supported on Linux"):
            FFPuppet(use_valgrind=True)
        return
    vmv = FFPuppet.VALGRIND_MIN_VERSION
    try:
        FFPuppet.VALGRIND_MIN_VERSION = 9999999999.99
        with pytest.raises(EnvironmentError, match=r"Valgrind >= \d+\.\d+ is required"):
            FFPuppet(use_valgrind=True)
        FFPuppet.VALGRIND_MIN_VERSION = 0
        with FFPuppet(use_valgrind=True) as ffp:
            bin_path = str(check_output(["which", "echo"]).strip().decode("ascii"))
            # launch will fail b/c 'echo' will exit right away but that's fine
            with pytest.raises(LaunchError, match="Failure waiting for browser connection"):
                ffp.launch(bin_path)
            ffp.close()
            ffp.save_logs(str(tmp_path / "logs"))
        log_data = (tmp_path / "logs" / "log_stderr.txt").read_bytes()
        # verify Valgrind ran and executed the script
        assert b"valgrind -q" in log_data
        assert b"[ffpuppet] Reason code: EXITED" in log_data
    finally:
        FFPuppet.VALGRIND_MIN_VERSION = vmv

def test_ffpuppet_20(tmp_path):
    """test detecting invalid prefs file"""
    prefs = (tmp_path / "prefs.js")
    prefs.write_bytes(b"//fftest_invalid_js\n")
    with FFPuppet() as ffp:
        with HTTPTestServer() as srv:
            with pytest.raises(LaunchError, match="'.+?' is invalid"):
                ffp.launch(TESTFF_BIN, location=srv.get_addr(), prefs_js=str(prefs))

def test_ffpuppet_21():
    """test log_length()"""
    with FFPuppet() as ffp:
        assert ffp.log_length("INVALID") is None
        assert ffp.log_length("stderr") is None
        ffp.launch(TESTFF_BIN)
        assert ffp.log_length("stderr") > 0
        ffp.close()
        assert ffp.log_length("stderr") > 0
        ffp.clean_up()
        # verify clean_up() removed the logs
        assert ffp.log_length("stderr") is None

def test_ffpuppet_22():
    """test running multiple instances in parallel"""
    ffps = list()
    try:
        with HTTPTestServer() as srv:
            # use test pool size of 10
            for _ in range(10):
                ffps.append(FFPuppet())
                # NOTE: launching truly in parallel can DoS the test webserver
                ffps[-1].launch(TESTFF_BIN, location=srv.get_addr())
            # list of ffps needs to be reversed to deal with inheriting open file handles in Popen
            # this is not a problem in production only in the test environment
            for ffp in reversed(ffps):
                assert ffp.launches == 1
                ffp.close()
    finally:
        for ffp in ffps:
            ffp.clean_up()

def test_ffpuppet_23(tmp_path):
    """test hitting log size limit"""
    prefs = (tmp_path / "prefs.js")
    prefs.write_bytes(b"//fftest_big_log\n")
    with FFPuppet() as ffp:
        limit = 0x100000 # 1MB
        ffp.launch(TESTFF_BIN, prefs_js=str(prefs), log_limit=limit)
        for _ in range(100):
            if not ffp.is_healthy():
                break
            time.sleep(0.1)
        ffp.close()
        assert ffp.reason == ffp.RC_WORKER
        logs = (tmp_path / "logs")
        ffp.save_logs(str(logs))
        logfiles = tuple(logs.glob("*"))
        assert len(logfiles) == 3
        assert sum(x.stat().st_size for x in logfiles) > limit
        assert b"LOG_SIZE_LIMIT_EXCEEDED" in (logs / "log_ffp_worker_log_size.txt").read_bytes()

def test_ffpuppet_24(tmp_path):
    """test collecting and cleaning up ASan logs"""
    test_logs = list()
    with FFPuppet() as ffp:
        ffp.launch(TESTFF_BIN)
        asan_prefix = os.path.join(ffp._logs.working_path, ffp._logs.PREFIX_SAN)
        for i in range(3):
            test_logs.append(".".join([asan_prefix, str(i)]))
        # small log with nothing interesting
        with open(test_logs[0], "w") as log_fp:
            log_fp.write("SHORT LOG\n")
            log_fp.write("filler line")
        # crash on another thread
        with open(test_logs[1], "w") as log_fp:
            log_fp.write("GOOD LOG\n")
            log_fp.write("==70811==ERROR: AddressSanitizer: SEGV on unknown address 0x00000BADF00D")
            log_fp.write(" (pc 0x7f4c0bb54c67 bp 0x7f4c07bea380 sp 0x7f4c07bea360 T0)\n") # must be 2nd line
            for _ in range(4): # pad out to 6 lines
                log_fp.write("filler line\n")
        # child log that should be ignored (created when parent crashes)
        with open(test_logs[2], "w") as log_fp:
            log_fp.write("BAD LOG\n")
            log_fp.write("==70811==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000")
            log_fp.write(" (pc 0x7f4c0bb54c67 bp 0x7f4c07bea380 sp 0x7f4c07bea360 T2)\n") # must be 2nd line
            for _ in range(4): # pad out to 6 lines
                log_fp.write("filler line\n")
        assert not ffp.is_healthy()
        assert ffp.is_running()
        ffp.close()
        logs = (tmp_path / "logs")
        ffp.save_logs(str(logs))
        logfiles = tuple(logs.glob("*"))
        assert len(logfiles) == 5
        for logfile in logfiles:
            if "log_ffp_asan_" not in str(logfile):
                assert logfile.name in ("log_stderr.txt", "log_stdout.txt")
                continue
            with logfile.open("r") as log_fp:
                assert log_fp.readline() in ("BAD LOG\n", "GOOD LOG\n", "SHORT LOG\n")
    assert not any(os.path.isfile(f) for f in test_logs)

def test_ffpuppet_25(tmp_path):
    """test multiple minidumps"""
    profile = (tmp_path / "profile")
    profile.mkdir()
    (profile / "minidumps").mkdir()
    # 'symbols' directory needs to exist to satisfy a check
    (profile / "symbols").mkdir()
    with FFPuppet(use_profile=str(profile)) as ffp:
        ffp.launch(TESTFF_BIN)
        ffp._last_bin_path = ffp.profile
        # create "test.dmp" files
        md_path = os.path.join(ffp._last_bin_path, "minidumps")
        with open(os.path.join(md_path, "test1.dmp"), "w") as out_fp:
            out_fp.write("1a\n1b")
        with open(os.path.join(md_path, "test2.dmp"), "w") as out_fp:
            out_fp.write("2a\n2b")
        with open(os.path.join(md_path, "test3.dmp"), "w") as out_fp:
            out_fp.write("3a\n3b")
        assert not ffp.is_healthy()
        ffp.close()
        logs = (tmp_path / "logs")
        ffp.save_logs(str(logs))
        assert any(logs.glob("log_minidump_01.txt"))
        assert any(logs.glob("log_minidump_02.txt"))
        assert any(logs.glob("log_minidump_03.txt"))

def test_ffpuppet_26(tmp_path):
    """test multiprocess target"""
    prefs = (tmp_path / "prefs.js")
    prefs.write_bytes(b"//fftest_multi_proc\n")
    with FFPuppet() as ffp:
        with HTTPTestServer() as srv:
            ffp.launch(TESTFF_BIN, prefs_js=str(prefs), location=srv.get_addr())
            assert ffp.is_running()
            assert not ffp.wait(timeout=0)
            c_procs = Process(ffp.get_pid()).children()
            assert c_procs
            # terminate one of the child processes
            c_procs[-1].terminate()
            assert ffp.is_running()
            ffp.close()
        assert not ffp.is_running()
        assert ffp.wait(timeout=0)

def test_ffpuppet_27(tmp_path):
    """test multiprocess (target terminated)"""
    prefs = (tmp_path / "prefs.js")
    prefs.write_bytes(b"//fftest_multi_proc\n")
    with FFPuppet() as ffp:
        with HTTPTestServer() as srv:
            ffp.launch(TESTFF_BIN, prefs_js=str(prefs), location=srv.get_addr())
            assert ffp.is_running()
            procs = get_processes(ffp.get_pid())
            # when running the browser the children exit if the parent disappears
            # since the first item in procs is the parent iterate over the list
            # calling terminate()
            for proc in procs:
                try:
                    proc.terminate()
                except (AccessDenied, NoSuchProcess):
                    pass
            assert not wait_procs(procs, timeout=10)[1]
            ffp.close()
        assert not ffp.is_running()
        assert ffp.wait(timeout=0)

@pytest.mark.skipif(platform.system() == "Linux" and call(["which", "rr"]),
                    reason="rr not installed")
def test_ffpuppet_28(tmp_path):
    """test launching with rr"""
    if platform.system() != "Linux":
        with pytest.raises(EnvironmentError, match="rr is only supported on Linux"):
            FFPuppet(use_rr=True)
        return
    # NOTE: this can hang if ptrace is blocked by seccomp
    if call(["rr", "record", "echo"]) != 0:
        pytest.skip("Environment not configured to run rr")
    with FFPuppet(use_rr=True) as ffp:
        bin_path = str(check_output(["which", "echo"]).strip().decode("ascii"))
        # launch will fail b/c 'echo' will exit right away but that's fine
        with pytest.raises(LaunchError, match="Failure during browser startup"):
            ffp.launch(bin_path, env_mod={"_RR_TRACE_DIR": str(tmp_path / "rr_wp")})
        ffp.close()
        assert ffp.reason == ffp.RC_EXITED
        logs = (tmp_path / "logs")
        ffp.save_logs(str(logs))
        log_data = (logs / "log_stderr.txt").read_bytes()
        # verify rr ran and executed the script
        assert b"rr record" in log_data
        assert b"[ffpuppet] Reason code:" in log_data

def test_ffpuppet_29(tmp_path):
    """test rmtree error handler"""
    # normal profile creation
    # - just create a puppet, write a readonly file in its profile, then call close()
    with FFPuppet() as ffp:
        ffp.launch(TESTFF_BIN)
        ro_file = os.path.join(ffp.profile, "read-only-test.txt")
        with open(ro_file, "w"):
            pass
        os.chmod(ro_file, stat.S_IREAD)
        ffp.close()
        assert not os.path.isfile(ro_file)
        ffp.clean_up()
    # use template profile that contains a readonly file
    profile = (tmp_path / "profile")
    profile.mkdir()
    ro_file = (profile / "read-only.txt")
    ro_file.touch()
    os.chmod(str(ro_file), stat.S_IREAD)
    with FFPuppet(use_profile=str(profile)) as ffp:
        ffp.launch(TESTFF_BIN)
        prof_path = ffp.profile
        assert os.path.isdir(prof_path)
        ffp.close()
        assert not os.path.isdir(prof_path)

def test_ffpuppet_30(tmp_path):
    """test using a readonly prefs.js and extension"""
    prefs = (tmp_path / "prefs.js")
    prefs.touch()
    os.chmod(str(prefs), stat.S_IREAD)
    ext = (tmp_path / "ext.xpi")
    ext.touch()
    os.chmod(str(ext), stat.S_IREAD)
    with FFPuppet() as ffp:
        ffp.launch(TESTFF_BIN, extension=str(ext), prefs_js=str(prefs))
        prof_path = ffp.profile
        ffp.close()
        assert not os.path.isdir(prof_path)

def test_ffpuppet_31(tmp_path):
    """test _crashreports()"""
    class StubbedLaunch(FFPuppet):
        def __init__(self):
            super(StubbedLaunch, self).__init__()
            self._use_valgrind = True
        def launch(self):  # pylint: disable=arguments-differ
            profile = (tmp_path / "profile")
            profile.mkdir()
            (profile / "minidumps").mkdir()
            self.profile = str(profile)
        def close(self, force_close=False):
            if os.path.isdir(self.profile):
                shutil.rmtree(self.profile)
            self.profile = None
    with StubbedLaunch() as ffp:
        ffp.launch()
        assert not any(ffp._crashreports())
        ign_log = "%s.1" % (ffp._logs.PREFIX_SAN,)
        san_log = "%s.2" % (ffp._logs.PREFIX_SAN,)
        vg1_log = "%s.1" % (ffp._logs.PREFIX_VALGRIND,)
        vg2_log = "%s.2" % (ffp._logs.PREFIX_VALGRIND,)
        with open(os.path.join(ffp._logs.working_path, ign_log), "w") as ofp:
            ofp.write("==123==WARNING: Symbolizer buffer too small\n")
            ofp.write("==123==WARNING: Symbolizer buffer too small\n\n")
        with open(os.path.join(ffp._logs.working_path, san_log), "w") as ofp:
            ofp.write("test\n")
        with open(os.path.join(ffp._logs.working_path, vg1_log), "w") as ofp:
            ofp.write("test\n")
        with open(os.path.join(ffp._logs.working_path, vg2_log), "w") as ofp:
            pass
        with open(os.path.join(ffp._logs.working_path, "junk.log"), "w") as ofp:
            ofp.write("test\n")
        with open(os.path.join(ffp.profile, "minidumps", "test.dmp"), "w") as ofp:
            ofp.write("test\n")
        with open(os.path.join(ffp.profile, "minidumps", "test.junk"), "w") as ofp:
            pass
        assert len(list(ffp._crashreports())) == 3
        assert len(list(ffp._crashreports(skip_md=True))) == 2

def test_ffpuppet_32(tmp_path):
    """test build_launch_cmd()"""
    with FFPuppet() as ffp:
        cmd = ffp.build_launch_cmd("bin_path", ["test"])
        assert len(cmd) == 3
        assert cmd[0] == "bin_path"
        assert cmd[-1] == "test"
        # GDB
        ffp._use_gdb = True
        cmd = ffp.build_launch_cmd("bin_path")
        assert len(cmd) > 2
        assert cmd[0] == "gdb"
        ffp._use_gdb = False
        # RR
        ffp._use_rr = True
        cmd = ffp.build_launch_cmd("bin_path")
        assert len(cmd) > 2
        assert cmd[0] == "rr"
        ffp._use_rr = False
        # Valgrind
        ffp._use_valgrind = True
        try:
            os.environ["VALGRIND_SUP_PATH"] = "blah"
            with pytest.raises(IOError):
                ffp.build_launch_cmd("bin_path")
            supp = (tmp_path / "suppressions.txt")
            supp.touch()
            os.environ["VALGRIND_SUP_PATH"] = str(supp)
            cmd = ffp.build_launch_cmd("bin_path")
            assert len(cmd) > 2
            assert cmd[0] == "valgrind"
        finally:
            os.environ.pop("VALGRIND_SUP_PATH")
        ffp._use_valgrind = False

def test_ffpuppet_33():
    """test cpu_usage()"""
    with FFPuppet() as ffp:
        assert not any(ffp.cpu_usage())
        with HTTPTestServer() as srv:
            ffp.launch(TESTFF_BIN, location=srv.get_addr())
            usage = tuple(ffp.cpu_usage())
            assert len(usage) == 1
            assert len(usage[0]) == 2
            assert usage[0][0] == ffp.get_pid()
            assert usage[0][1] <= 100
            assert usage[0][1] >= 0
        ffp.close()
        assert ffp.wait(timeout=10)
