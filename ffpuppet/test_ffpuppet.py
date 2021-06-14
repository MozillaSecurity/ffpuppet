# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=invalid-name,missing-docstring,protected-access
"""ffpuppet tests"""
import errno
import os
import platform
import shutil
import socket
import stat
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from subprocess import Popen

import pytest
from psutil import Process

from .bootstrapper import Bootstrapper
from .core import Debugger, FFPuppet, Reason
from .exceptions import (
    BrowserTerminatedError,
    BrowserTimeoutError,
    LaunchError,
    TerminateError,
)
from .minidump_parser import MinidumpParser

Bootstrapper.POLL_WAIT = 0.2
CWD = os.path.realpath(os.path.dirname(__file__))
TESTFF_BIN = os.path.join(CWD, "resources", "testff.py")

MinidumpParser.MDSW_MAX_STACK = 8


class ReqHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"hello world")


class HTTPTestServer:
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
        self._thread = threading.Thread(
            target=HTTPTestServer._srv_thread, args=(self._httpd,)
        )
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


@pytest.mark.skipif(platform.system() == "Windows", reason="Unsupported on Windows")
def test_ffpuppet_00(tmp_path):
    """test that invalid executables raise the right exception"""
    with FFPuppet() as ffp:
        with pytest.raises(IOError, match="is not an executable"):
            ffp.launch(str(tmp_path))


def test_ffpuppet_01():
    """test basic launch and close"""
    with FFPuppet() as ffp:
        assert ffp._dbg == Debugger.NONE
        assert ffp.launches == 0
        assert ffp.reason == Reason.CLOSED
        assert not ffp.is_running()
        with HTTPTestServer() as srv:
            ffp.launch(TESTFF_BIN, location=srv.get_addr())
        assert not ffp._checks
        assert ffp.launches == 1
        assert not ffp.wait(timeout=0)
        assert ffp.is_running()
        assert ffp.is_healthy()
        assert ffp.reason is None
        ffp.close()
        assert ffp.reason == Reason.CLOSED
        assert ffp._proc is None
        assert not ffp.is_running()
        assert not ffp.is_healthy()
        assert ffp.wait(timeout=10)


def test_ffpuppet_02(mocker):
    """test launch failures"""
    fake_bts = mocker.patch("ffpuppet.core.Bootstrapper", autospec=True)
    bts = mocker.Mock(spec=Bootstrapper, location="")
    fake_bts.return_value = bts
    proc = mocker.Mock(spec=Popen, pid=0xFFFF)
    mocker.patch("ffpuppet.core.Popen", autospec=True, return_value=proc)
    # startup crash
    with FFPuppet() as ffp:
        bts.wait.side_effect = BrowserTerminatedError("test")
        with pytest.raises(BrowserTerminatedError, match="test"):
            ffp.launch(TESTFF_BIN)
        assert not ffp.is_running()
        assert ffp.launches == 0
    # startup hang
    with FFPuppet() as ffp:
        bts.wait.side_effect = BrowserTimeoutError("test")
        with pytest.raises(BrowserTimeoutError, match="test"):
            ffp.launch(TESTFF_BIN)
        assert not ffp.is_healthy()
        assert ffp.launches == 0


def test_ffpuppet_03(tmp_path):
    """test logging"""
    with FFPuppet() as ffp:
        ffp.close()
        ffp.save_logs(str(tmp_path / "no_logs"))
        prefs = tmp_path / "prefs.js"
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
        logs = tmp_path / "logs"  # nonexistent directory
        ffp.save_logs(str(logs), meta=True)
        assert logs.is_dir()
        assert len(tuple(logs.iterdir())) == 3
        log_data = (logs / "log_stderr.txt").read_text()
        assert "[ffpuppet] Launch command:" in log_data
        assert "[ffpuppet] Reason code:" in log_data
        log_data = (logs / "log_stdout.txt").read_text()
        assert "url: 'http://" in log_data
        assert "hello world" in log_data
        assert any(logs.glob(ffp._logs.META_FILE))


def test_ffpuppet_04(mocker):
    """test get_pid()"""
    with FFPuppet() as ffp:
        assert ffp.get_pid() is None
        ffp._proc = mocker.Mock(pid=123)
        assert ffp.get_pid() == 123
        ffp._proc = None


def test_ffpuppet_05(mocker):
    """test is_running()"""
    with FFPuppet() as ffp:
        assert not ffp.is_running()
        ffp._proc = mocker.Mock(pid=123)
        ffp._proc.poll.return_value = None
        assert ffp.is_running()
        ffp._proc.poll.return_value = 0
        assert not ffp.is_running()
        ffp._proc = None
        assert not ffp.is_running()


def test_ffpuppet_06(mocker):
    """test wait()"""

    class StubbedProc(FFPuppet):
        def close(self, **_):  # pylint: disable=arguments-differ
            self.reason = Reason.CLOSED

        def launch(self):  # pylint: disable=arguments-differ
            self.reason = None

        def get_pid(self):
            if self.reason is None:
                return 123
            return None

    fake_wait_procs = mocker.patch("ffpuppet.core.wait_procs", autospec=True)
    with StubbedProc() as ffp:
        # process not running
        assert ffp.wait()
        assert fake_wait_procs.call_count == 0
        # process closed
        fake_wait_procs.return_value = ([], [])
        ffp.launch()
        assert ffp.wait()
        assert fake_wait_procs.call_count == 1
        fake_wait_procs.reset_mock()
        # process did not close
        fake_wait_procs.return_value = ([], [mocker.Mock(spec=Process)])
        assert not ffp.wait(timeout=10)
        assert fake_wait_procs.call_count == 1


def test_ffpuppet_07(tmp_path):
    """test clone_log()"""
    logs = tmp_path / "logs.txt"
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


def test_ffpuppet_08(tmp_path):
    """test hitting memory limit"""
    with FFPuppet() as ffp:
        prefs = tmp_path / "prefs.js"
        prefs.write_bytes(b"//fftest_memory\n")
        with HTTPTestServer() as srv:
            # launch with 1MB memory limit
            ffp.launch(
                TESTFF_BIN,
                location=srv.get_addr(),
                prefs_js=str(prefs),
                memory_limit=0x100000,
            )
            for _ in range(100):
                if not ffp.is_healthy():
                    break
                time.sleep(0.1)
            ffp.close()
        assert ffp.reason == Reason.WORKER
        assert len(ffp.available_logs()) == 3
        logs = tmp_path / "logs"
        ffp.save_logs(str(logs))
    worker_log = logs / "log_ffp_worker_memory_usage.txt"
    assert worker_log.is_file()
    assert "MEMORY_LIMIT_EXCEEDED" in worker_log.read_text()


def test_ffpuppet_09():
    """test calling launch() multiple times"""
    with FFPuppet() as ffp:
        with HTTPTestServer() as srv:
            # call launch() then close() multiple times
            for _ in range(10):
                ffp.launch(TESTFF_BIN, location=srv.get_addr())
                ffp.close()
            # call 2x without calling close()
            ffp.launch(TESTFF_BIN, location=srv.get_addr())
            with pytest.raises(LaunchError, match="Process is already running"):
                ffp.launch(TESTFF_BIN)
        assert ffp.launches == 11
        ffp.close()


def test_ffpuppet_10(tmp_path):
    """test abort tokens"""
    prefs = tmp_path / "prefs.js"
    prefs.write_bytes(b"//fftest_soft_assert\n")
    with FFPuppet() as ffp:
        ffp.add_abort_token(r"TEST\dREGEX\.+")
        ffp.add_abort_token("simple_string")
        ffp.add_abort_token(r"ASSERTION:\s\w+")
        with HTTPTestServer() as srv:
            ffp.launch(TESTFF_BIN, location=srv.get_addr(), prefs_js=str(prefs))
            for _ in range(200):
                if not ffp.is_healthy():
                    break
                time.sleep(0.05)
            ffp.close()
        assert ffp.reason == Reason.WORKER
        assert len(ffp.available_logs()) == 3
        logs = tmp_path / "logs"
        ffp.save_logs(str(logs))
        worker_log = logs / "log_ffp_worker_log_contents.txt"
        assert worker_log.is_file()
        assert b"TOKEN_LOCATED: ASSERTION: test" in worker_log.read_bytes()


def test_ffpuppet_11(tmp_path):
    """test using an existing profile directory"""
    prf_dir = tmp_path / "ffp_test_prof"
    prf_dir.mkdir()
    with FFPuppet(use_profile=str(prf_dir)) as ffp:
        ffp.launch(TESTFF_BIN)
    assert prf_dir.is_dir()


def test_ffpuppet_12():
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


def test_ffpuppet_13(mocker):
    """test launching under Xvfb"""
    fake_system = mocker.patch("ffpuppet.core.system", autospec=True)
    is_linux = platform.system() == "Linux"
    fake_xvfb = mocker.patch(
        "ffpuppet.core.Xvfb", autospec=is_linux, create=not is_linux
    )
    # success
    fake_system.return_value = "Linux"
    with FFPuppet(use_xvfb=True):
        pass
    assert fake_xvfb.call_count == 1
    assert fake_xvfb.return_value.start.call_count == 1
    fake_xvfb.reset_mock()
    # not installed
    fake_xvfb.side_effect = NameError
    with pytest.raises(EnvironmentError, match="Please install xvfbwrapper"):
        FFPuppet(use_xvfb=True)
    assert fake_xvfb.start.call_count == 0
    # unsupported os
    fake_system.return_value = "Windows"
    with pytest.raises(EnvironmentError, match="Xvfb is only supported on Linux"):
        FFPuppet(use_xvfb=True)
    assert fake_xvfb.start.call_count == 0


def test_ffpuppet_14(tmp_path):
    """test passing a file and a non existing file to launch() via location"""
    with FFPuppet() as ffp:
        with pytest.raises(IOError, match="Cannot find"):
            ffp.launch(TESTFF_BIN, location="missing.file")
        ffp.close()
        prefs = tmp_path / "prefs.js"
        prefs.write_bytes(b"//fftest_exit_code_0\n")
        test_file = tmp_path / "test_file"
        test_file.write_bytes(b"test")
        # needs realpath() for OSX & normcase() for Windows
        fname = os.path.normcase(os.path.realpath(str(test_file)))
        ffp.launch(TESTFF_BIN, location=fname, prefs_js=str(prefs))
        ffp.wait(timeout=10)
        ffp.close()
        logs = tmp_path / "logs"
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


def test_ffpuppet_15(mocker, tmp_path):
    """test launching with gdb"""
    mocker.patch("ffpuppet.core.check_output", autospec=True)
    mocker.patch("ffpuppet.core.get_processes", autospec=True, return_value=[])
    mocker.patch("ffpuppet.core.system", autospec=True, return_value="Linux")
    fake_bts = mocker.patch("ffpuppet.core.Bootstrapper", autospec=True)
    fake_bts.return_value.location = "http://test:123"
    fake_proc = mocker.patch("ffpuppet.core.Popen", autospec=True)
    fake_proc.return_value.pid = 0xFFFF
    fake_proc.return_value.poll.return_value = None
    with FFPuppet(debugger=Debugger.GDB) as ffp:
        assert ffp._dbg == Debugger.GDB
        ffp.launch(TESTFF_BIN)
        ffp.close()
        assert ffp.reason == Reason.CLOSED
        logs = tmp_path / "logs"
        ffp.save_logs(str(logs))
    log_data = (logs / "log_stderr.txt").read_bytes()
    # verify launch command was correct
    assert b"gdb" in log_data
    assert b"[ffpuppet] Reason code:" in log_data


def test_ffpuppet_16(tmp_path):
    """test calling save_logs() before close()"""
    with FFPuppet() as ffp:
        with HTTPTestServer() as srv:
            ffp.launch(TESTFF_BIN, location=srv.get_addr())
            with pytest.raises(AssertionError):
                ffp.save_logs(str(tmp_path / "logs"))


def test_ffpuppet_17(mocker, tmp_path):
    """test launching with Valgrind"""
    mocker.patch(
        "ffpuppet.core.check_output", autospec=True, return_value=b"valgrind-99.0"
    )
    mocker.patch("ffpuppet.core.get_processes", autospec=True, return_value=[])
    mocker.patch("ffpuppet.core.system", autospec=True, return_value="Linux")
    fake_bts = mocker.patch("ffpuppet.core.Bootstrapper", autospec=True)
    fake_bts.return_value.location = "http://test:123"
    fake_proc = mocker.patch("ffpuppet.core.Popen", autospec=True)
    fake_proc.return_value.pid = 0xFFFF
    fake_proc.return_value.poll.return_value = None
    with FFPuppet(debugger=Debugger.VALGRIND) as ffp:
        assert ffp._dbg == Debugger.VALGRIND
        ffp.launch(TESTFF_BIN)
        ffp.close()
        assert ffp.reason == Reason.CLOSED
        logs = tmp_path / "logs"
        ffp.save_logs(str(logs))
    log_data = (logs / "log_stderr.txt").read_bytes()
    # verify launch command was correct
    assert b"valgrind -q" in log_data
    assert b"[ffpuppet] Reason code:" in log_data


def test_ffpuppet_18(tmp_path):
    """test detecting invalid prefs file"""
    prefs = tmp_path / "prefs.js"
    prefs.write_bytes(b"//fftest_invalid_js\n")
    with FFPuppet() as ffp:
        with HTTPTestServer() as srv:
            with pytest.raises(LaunchError, match="'.+?' is invalid"):
                ffp.launch(TESTFF_BIN, location=srv.get_addr(), prefs_js=str(prefs))


def test_ffpuppet_19():
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


def test_ffpuppet_20():
    """test running multiple instances in parallel"""
    ffps = list()
    try:
        with HTTPTestServer() as srv:
            # use test pool size of 10
            for _ in range(10):
                ffps.append(FFPuppet())
                # NOTE: launching truly in parallel can DoS the test webserver
                ffps[-1].launch(TESTFF_BIN, location=srv.get_addr())
            # list of ffps needs to be reversed to deal with inheriting open
            # file handles in Popen
            # this is not a problem in production only in the test environment
            for ffp in reversed(ffps):
                assert ffp.launches == 1
                ffp.close()
    finally:
        for ffp in ffps:
            ffp.clean_up()


def test_ffpuppet_21(tmp_path):
    """test hitting log size limit"""
    prefs = tmp_path / "prefs.js"
    prefs.write_bytes(b"//fftest_big_log\n")
    with FFPuppet() as ffp:
        limit = 0x100000  # 1MB
        ffp.launch(TESTFF_BIN, prefs_js=str(prefs), log_limit=limit)
        for _ in range(100):
            if not ffp.is_healthy():
                break
            time.sleep(0.1)
        ffp.close()
        assert ffp.reason == Reason.WORKER
        logs = tmp_path / "logs"
        ffp.save_logs(str(logs))
        logfiles = tuple(logs.iterdir())
        assert len(logfiles) == 3
        assert sum(x.stat().st_size for x in logfiles) > limit
        assert (
            b"LOG_SIZE_LIMIT_EXCEEDED"
            in (logs / "log_ffp_worker_log_size.txt").read_bytes()
        )


def test_ffpuppet_22(tmp_path):
    """test collecting and cleaning up ASan logs"""
    test_logs = list()
    with FFPuppet() as ffp:
        ffp.launch(TESTFF_BIN)
        asan_prefix = os.path.join(ffp._logs.working_path, ffp._logs.PREFIX_SAN)
        for i in range(4):
            test_logs.append(".".join([asan_prefix, str(i)]))
        # ignore benign ASan warning
        with open(test_logs[0], "w") as log_fp:
            log_fp.write("==123==WARNING: Symbolizer buffer too small")
        assert ffp.is_healthy()
        # small log with nothing interesting
        with open(test_logs[1], "w") as log_fp:
            log_fp.write("SHORT LOG\n")
            log_fp.write("filler line")
        # crash on another thread
        with open(test_logs[2], "w") as log_fp:
            log_fp.write("GOOD LOG\n")
            log_fp.write(
                "==70811==ERROR: AddressSanitizer:"
                " SEGV on unknown address 0x00000BADF00D"
                " (pc 0x7f4c0bb54c67 bp 0x7f4c07bea380 sp 0x7f4c07bea360 T0)\n"
            )  # must be 2nd line
            for _ in range(4):  # pad out to 6 lines
                log_fp.write("filler line\n")
        # child log that should be ignored (created when parent crashes)
        with open(test_logs[3], "w") as log_fp:
            log_fp.write("BAD LOG\n")
            log_fp.write(
                "==70811==ERROR: AddressSanitizer:"
                " SEGV on unknown address 0x000000000000"
                " (pc 0x7f4c0bb54c67 bp 0x7f4c07bea380 sp 0x7f4c07bea360 T2)\n"
            )  # must be 2nd line
            for _ in range(4):  # pad out to 6 lines
                log_fp.write("filler line\n")
        assert not ffp.is_healthy()
        assert ffp.is_running()
        ffp.close()
        assert ffp.reason == Reason.ALERT
        logs = tmp_path / "logs"
        ffp.save_logs(str(logs))
        logfiles = tuple(logs.iterdir())
        assert len(logfiles) == 6
        for logfile in logfiles:
            if "log_ffp_asan_" not in str(logfile):
                assert logfile.name in ("log_stderr.txt", "log_stdout.txt")
                continue
            with logfile.open("r") as log_fp:
                assert log_fp.readline() in (
                    "BAD LOG\n",
                    "GOOD LOG\n",
                    "SHORT LOG\n",
                    "==123==WARNING: Symbolizer buffer too small",
                )
    assert not any(os.path.isfile(f) for f in test_logs)


def test_ffpuppet_23(mocker, tmp_path):
    """test multiple minidumps"""

    # pylint: disable=unused-argument
    def _fake_process_minidumps(dmps, _, add_log, working_path=None):
        for num, _ in enumerate(x for x in os.listdir(dmps) if x.endswith(".dmp")):
            lfp = add_log("minidump_%02d" % (num + 1,))
            lfp.write(b"test")

    mocker.patch("ffpuppet.core.process_minidumps", side_effect=_fake_process_minidumps)
    profile = tmp_path / "profile"
    profile.mkdir()
    (profile / "minidumps").mkdir()
    with FFPuppet(use_profile=str(profile)) as ffp:
        ffp.launch(TESTFF_BIN)
        ffp._bin_path = ffp.profile
        # create "test.dmp" files
        md_path = os.path.join(ffp._bin_path, "minidumps")
        with open(os.path.join(md_path, "test1.dmp"), "w") as out_fp:
            out_fp.write("1a\n1b")
        with open(os.path.join(md_path, "test2.dmp"), "w") as out_fp:
            out_fp.write("2a\n2b")
        with open(os.path.join(md_path, "test3.dmp"), "w") as out_fp:
            out_fp.write("3a\n3b")
        assert not ffp.is_healthy()
        ffp.close()
        logs = tmp_path / "logs"
        ffp.save_logs(str(logs))
        assert any(logs.glob("log_minidump_01.txt"))
        assert any(logs.glob("log_minidump_02.txt"))
        assert any(logs.glob("log_minidump_03.txt"))


def test_ffpuppet_24(mocker, tmp_path):
    """test launching with rr"""
    mocker.patch("ffpuppet.core.check_output", autospec=True)
    mocker.patch("ffpuppet.core.get_processes", autospec=True, return_value=[])
    mocker.patch("ffpuppet.core.system", autospec=True, return_value="Linux")
    fake_bts = mocker.patch("ffpuppet.core.Bootstrapper", autospec=True)
    fake_bts.return_value.location = "http://test:123"
    fake_proc = mocker.patch("ffpuppet.core.Popen", autospec=True)
    fake_proc.return_value.pid = 0xFFFF
    fake_proc.return_value.poll.return_value = None
    with FFPuppet(debugger=Debugger.RR) as ffp:
        assert ffp._dbg == Debugger.RR
        ffp.launch(TESTFF_BIN)
        ffp.close()
        assert ffp.reason == Reason.CLOSED
        logs = tmp_path / "logs"
        ffp.save_logs(str(logs))
    log_data = (logs / "log_stderr.txt").read_bytes()
    # verify launch command was correct
    assert b"rr record" in log_data
    assert b"[ffpuppet] Reason code:" in log_data


def test_ffpuppet_25(tmp_path):
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
    profile = tmp_path / "profile"
    profile.mkdir()
    ro_file = profile / "read-only.txt"
    ro_file.touch()
    os.chmod(str(ro_file), stat.S_IREAD)
    with FFPuppet(use_profile=str(profile)) as ffp:
        ffp.launch(TESTFF_BIN)
        prof_path = ffp.profile
        assert os.path.isdir(prof_path)
        ffp.close()
        assert not os.path.isdir(prof_path)


def test_ffpuppet_26(tmp_path):
    """test using a readonly prefs.js and extension"""
    prefs = tmp_path / "prefs.js"
    prefs.touch()
    os.chmod(str(prefs), stat.S_IREAD)
    ext = tmp_path / "ext.xpi"
    ext.touch()
    os.chmod(str(ext), stat.S_IREAD)
    with FFPuppet() as ffp:
        ffp.launch(TESTFF_BIN, extension=str(ext), prefs_js=str(prefs))
        prof_path = ffp.profile
        ffp.close()
        assert not os.path.isdir(prof_path)


def test_ffpuppet_27(mocker, tmp_path):
    """test _crashreports()"""
    mocker.patch(
        "ffpuppet.core.check_output", autospec=True, return_value=b"valgrind-99.0"
    )

    class StubbedLaunch(FFPuppet):
        def launch(self):  # pylint: disable=arguments-differ
            profile = tmp_path / "profile"
            profile.mkdir()
            (profile / "minidumps").mkdir()
            self.profile = str(profile)

        def close(self, force_close=False):
            if os.path.isdir(self.profile):
                shutil.rmtree(self.profile)
            self.profile = None

    is_linux = platform.system() == "Linux"
    debugger = Debugger.VALGRIND if is_linux else Debugger.NONE
    with StubbedLaunch(debugger=debugger) as ffp:
        assert ffp._dbg == debugger
        ffp.launch()
        assert not any(ffp._crashreports())
        # benign sanitizer warnings
        ign_log = "%s.1" % (ffp._logs.PREFIX_SAN,)
        with open(os.path.join(ffp._logs.working_path, ign_log), "w") as ofp:
            ofp.write(
                "==123==WARNING: Symbolizer buffer too small\n\n"
                "==123==WARNING: Symbolizer buffer too small\n\n"
                "==123==WARNING: AddressSanitizer failed to allocate 0xFFFFFF bytes\n"
                "==123==AddressSanitizer: soft rss limit exhausted (5000Mb vs 5026Mb)\n"
            )
        assert any(ffp._crashreports(skip_benign=False))
        # valid sanitizer log
        san_log = "%s.2" % (ffp._logs.PREFIX_SAN,)
        with open(os.path.join(ffp._logs.working_path, san_log), "w") as ofp:
            ofp.write("test\n")
        # valid Valgrind log - with error
        vg1_log = "%s.1" % (ffp._logs.PREFIX_VALGRIND,)
        with open(os.path.join(ffp._logs.working_path, vg1_log), "w") as ofp:
            ofp.write("test\n")
        # valid Valgrind log - without error
        vg2_log = "%s.2" % (ffp._logs.PREFIX_VALGRIND,)
        with open(os.path.join(ffp._logs.working_path, vg2_log), "w") as ofp:
            pass
        # nothing interesting
        with open(os.path.join(ffp._logs.working_path, "junk.log"), "w") as ofp:
            ofp.write("test\n")
        # valid minidump
        with open(os.path.join(ffp.profile, "minidumps", "test.dmp"), "w") as ofp:
            ofp.write("test\n")
        # nothing interesting
        with open(os.path.join(ffp.profile, "minidumps", "test.junk"), "w") as ofp:
            pass
        assert not ffp._logs.watching
        # NOTE: Valgrind logs are only checked on Linux
        assert len(list(ffp._crashreports())) == (3 if is_linux else 2)
        assert ffp._logs.watching
        assert len(list(ffp._crashreports(skip_md=True))) == (2 if is_linux else 1)
        # fail to open and scan sanitizer file
        ffp._logs.watching.clear()
        mocker.patch("ffpuppet.core.open", side_effect=OSError)
        assert len(list(ffp._crashreports())) == (4 if is_linux else 3)
        assert not ffp._logs.watching


def test_ffpuppet_28(tmp_path):
    """test build_launch_cmd()"""
    with FFPuppet() as ffp:
        cmd = ffp.build_launch_cmd("bin_path", ["test"])
        assert len(cmd) == 3
        assert cmd[0] == "bin_path"
        assert cmd[-1] == "test"
        # GDB
        ffp._dbg = Debugger.GDB
        cmd = ffp.build_launch_cmd("bin_path")
        assert len(cmd) > 2
        assert cmd[0] == "gdb"
        # Pernosco
        ffp._dbg = Debugger.PERNOSCO
        cmd = ffp.build_launch_cmd("bin_path")
        assert len(cmd) > 2
        assert cmd[0] == "rr"
        assert "--chaos" in cmd
        # RR
        ffp._dbg = Debugger.RR
        cmd = ffp.build_launch_cmd("bin_path")
        assert len(cmd) > 2
        assert cmd[0] == "rr"
        assert "--chaos" not in cmd
        # Valgrind
        ffp._dbg = Debugger.VALGRIND
        try:
            os.environ["VALGRIND_SUP_PATH"] = "blah"
            with pytest.raises(IOError):
                ffp.build_launch_cmd("bin_path")
            supp = tmp_path / "suppressions.txt"
            supp.touch()
            os.environ["VALGRIND_SUP_PATH"] = str(supp)
            cmd = ffp.build_launch_cmd("bin_path")
            assert len(cmd) > 2
            assert cmd[0] == "valgrind"
        finally:
            os.environ.pop("VALGRIND_SUP_PATH")


def test_ffpuppet_29():
    """test cpu_usage()"""
    with FFPuppet() as ffp:
        assert not any(ffp.cpu_usage())
        with HTTPTestServer() as srv:
            ffp.launch(TESTFF_BIN, location=srv.get_addr())
            usage = next(ffp.cpu_usage())
            assert usage
            assert usage[0] == ffp.get_pid()
            assert usage[1] <= 100
            assert usage[1] >= 0
        ffp.close()
        assert ffp.wait(timeout=10)


def test_ffpuppet_30(mocker):
    """test _dbg_sanity_check()"""
    fake_system = mocker.patch("ffpuppet.core.system", autospec=True)
    fake_chkout = mocker.patch("ffpuppet.core.check_output", autospec=True)
    # gdb - success
    fake_system.return_value = "Linux"
    FFPuppet._dbg_sanity_check(Debugger.GDB)
    assert fake_chkout.call_count == 1
    fake_chkout.reset_mock()
    # gdb - not installed
    fake_chkout.side_effect = OSError
    with pytest.raises(EnvironmentError, match="Please install GDB"):
        FFPuppet._dbg_sanity_check(Debugger.GDB)
    fake_chkout.reset_mock()
    fake_chkout.side_effect = None
    # gdb - unsupported OS
    fake_system.return_value = "Windows"
    with pytest.raises(EnvironmentError, match="GDB is only supported on Linux"):
        FFPuppet._dbg_sanity_check(Debugger.GDB)
    # rr - success
    fake_system.return_value = "Linux"
    FFPuppet._dbg_sanity_check(Debugger.RR)
    assert fake_chkout.call_count == 1
    fake_chkout.reset_mock()
    # rr - not installed
    fake_chkout.side_effect = OSError
    with pytest.raises(EnvironmentError, match="Please install rr"):
        FFPuppet._dbg_sanity_check(Debugger.RR)
    fake_chkout.reset_mock()
    fake_chkout.side_effect = None
    # rr - unsupported OS
    fake_system.return_value = "Windows"
    with pytest.raises(EnvironmentError, match="rr is only supported on Linux"):
        FFPuppet._dbg_sanity_check(Debugger.RR)
    # valgrind - success
    fake_system.return_value = "Linux"
    fake_chkout.return_value = b"valgrind-%0.2f" % (FFPuppet.VALGRIND_MIN_VERSION)
    FFPuppet._dbg_sanity_check(Debugger.VALGRIND)
    assert fake_chkout.call_count == 1
    fake_chkout.reset_mock()
    # valgrind - old version
    fake_system.return_value = "Linux"
    fake_chkout.return_value = b"valgrind-0.1"
    with pytest.raises(EnvironmentError, match=r"Valgrind >= \d+\.\d+ is required"):
        FFPuppet._dbg_sanity_check(Debugger.VALGRIND)
    assert fake_chkout.call_count == 1
    fake_chkout.reset_mock()
    # valgrind - not installed
    fake_chkout.side_effect = OSError
    with pytest.raises(EnvironmentError, match="Please install Valgrind"):
        FFPuppet._dbg_sanity_check(Debugger.VALGRIND)
    fake_chkout.reset_mock()
    fake_chkout.side_effect = None
    # valgrind - unsupported OS
    fake_system.return_value = "Windows"
    with pytest.raises(EnvironmentError, match="Valgrind is only supported on Linux"):
        FFPuppet._dbg_sanity_check(Debugger.VALGRIND)


def test_ffpuppet_31(mocker):
    """test _terminate()"""
    procs = [mocker.Mock(spec=Process, pid=123), mocker.Mock(spec=Process, pid=124)]
    mocker.patch("ffpuppet.core.get_processes", autospec=True, return_value=procs)
    fake_wait_procs = mocker.patch("ffpuppet.core.wait_procs", autospec=True)
    # successful call to terminate (parent process only)
    fake_wait_procs.return_value = ([], [])
    FFPuppet._terminate(1234)
    assert sum(x.terminate.call_count for x in procs) == 1
    assert not sum(x.kill.call_count for x in procs)
    assert procs[0].terminate.call_count == 1
    for proc in procs:
        proc.reset_mock()
    # successful call to terminate (all processes)
    fake_wait_procs.return_value = None
    fake_wait_procs.side_effect = (([], [procs[-1]]), ([], []))
    FFPuppet._terminate(1234)
    assert sum(x.terminate.call_count for x in procs) == 2
    assert not sum(x.kill.call_count for x in procs)
    for proc in procs:
        proc.reset_mock()
    # successful call to kill
    fake_wait_procs.return_value = None
    fake_wait_procs.side_effect = (([], procs), ([], procs), ([], []))
    FFPuppet._terminate(1234)
    assert sum(x.terminate.call_count for x in procs) == 3
    assert sum(x.kill.call_count for x in procs) == 2
    for proc in procs:
        proc.reset_mock()
    # failed call to kill
    fake_wait_procs.return_value = ([], procs)
    fake_wait_procs.side_effect = None
    with pytest.raises(TerminateError):
        FFPuppet._terminate(1234)


def test_ffpuppet_32(mocker, tmp_path):
    """test FFPuppet.close() setting reason"""

    class StubbedProc(FFPuppet):
        def launch(self):  # pylint: disable=arguments-differ
            self.reason = None
            self._bin_path = str(tmp_path)
            self._logs.reset()
            self._proc = mocker.Mock(spec=Popen, pid=123)
            self._proc.poll.return_value = None
            profile = tmp_path / "profile"
            profile.mkdir(exist_ok=True)
            self.profile = str(profile)

        @staticmethod
        def _terminate(pid, *_a, **_kw):  # pylint: disable=signature-differs
            assert isinstance(pid, int)

    fake_reports = mocker.patch("ffpuppet.core.FFPuppet._crashreports", autospec=True)
    fake_reports.return_value = ()
    fake_wait_files = mocker.patch("ffpuppet.core.wait_on_files", autospec=True)
    fake_wait_files.return_value = True
    mocker.patch("ffpuppet.core.wait_procs", autospec=True)
    # process exited - no crash
    with StubbedProc() as ffp:
        ffp.launch()
        ffp._proc.poll.return_value = 0
        ffp.close()
        assert ffp._proc is None
        assert ffp._logs.closed
        assert ffp.reason == Reason.EXITED
    # process exited - exit code - crash
    with StubbedProc() as ffp:
        ffp.launch()
        ffp._proc.poll.return_value = -11
        ffp.close()
        assert ffp._proc is None
        assert ffp._logs.closed
        assert ffp.reason == Reason.ALERT
    # process running - no crash reports
    with StubbedProc() as ffp:
        ffp.launch()
        ffp._proc.poll.return_value = None
        ffp.close()
        assert ffp._proc is None
        assert ffp._logs.closed
        assert ffp.reason == Reason.CLOSED
    # process running - with crash reports, hang waiting to close
    (tmp_path / "fake_report1").touch()
    with StubbedProc() as ffp:
        ffp.launch()
        ffp._proc.poll.return_value = None
        fake_reports.return_value = (str(tmp_path / "fake_report1"),)
        fake_wait_files.return_value = False
        ffp.close()
        assert ffp._proc is None
        assert ffp._logs.closed
        assert ffp.reason == Reason.ALERT
    # process running - with crash reports, multiple logs
    (tmp_path / "fake_report2").touch()
    with StubbedProc() as ffp:
        ffp.launch()
        ffp._proc.poll.return_value = None
        fake_reports.return_value = None
        fake_reports.side_effect = (
            (str(tmp_path / "fake_report1"),),
            (
                str(tmp_path / "fake_report1"),
                str(tmp_path / "fake_report2"),
            ),
            (
                str(tmp_path / "fake_report1"),
                str(tmp_path / "fake_report2"),
            ),
            (
                str(tmp_path / "fake_report1"),
                str(tmp_path / "fake_report2"),
            ),
            (
                str(tmp_path / "fake_report1"),
                str(tmp_path / "fake_report2"),
            ),
        )
        fake_wait_files.return_value = True
        ffp.close()
        assert ffp._proc is None
        assert ffp._logs.closed
        assert ffp.reason == Reason.ALERT


def test_ffpuppet_33():
    """test ignoring benign sanitizer logs"""
    with FFPuppet() as ffp:
        ffp.launch(TESTFF_BIN)
        san_log = "%s.1" % os.path.join(ffp._logs.working_path, ffp._logs.PREFIX_SAN)
        assert not ffp._logs.watching
        # ignore benign ASan warning
        with open(san_log, "w") as log_fp:
            log_fp.write("==123==WARNING: Symbolizer buffer too small")
        assert ffp.is_healthy()
        assert san_log in ffp._logs.watching
        ffp.close()
        assert ffp.reason == Reason.CLOSED
