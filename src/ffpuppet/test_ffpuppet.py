# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=invalid-name,missing-docstring,protected-access
"""ffpuppet tests"""

import os
from errno import EADDRINUSE
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from platform import system
from stat import S_IREAD, S_IWRITE
from threading import Thread
from time import sleep

from psutil import Process
from pytest import mark, raises

from .bootstrapper import Bootstrapper
from .core import Debugger, FFPuppet, ProcessTree, Reason
from .exceptions import (
    BrowserExecutionError,
    BrowserTerminatedError,
    BrowserTimeoutError,
    LaunchError,
)
from .profile import Profile

Bootstrapper.POLL_WAIT = 0.2
TESTFF_BIN = Path(__file__).parent / "resources" / "testff.py"


class ReqHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"hello world")


class HTTPTestServer:
    def __init__(self):
        self._handler = ReqHandler
        while True:
            try:
                self._httpd = HTTPServer(("127.0.0.1", 0), self._handler)
            except OSError as soc_e:
                if soc_e.errno in (EADDRINUSE, 10013):
                    # Address already in use
                    continue
                raise
            break
        self._thread = Thread(target=HTTPTestServer._srv_thread, args=(self._httpd,))
        self._thread.start()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.shutdown()

    def get_addr(self):
        return f"http://127.0.0.1:{self._httpd.server_address[1]}"

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


@mark.skipif(system() == "Windows", reason="Unsupported on Windows")
def test_ffpuppet_00(tmp_path):
    """test that invalid executables raise the right exception"""
    with FFPuppet() as ffp:
        with raises(OSError, match="is not an executable"):
            ffp.launch(tmp_path)


def test_ffpuppet_01():
    """test basic launch and close"""
    with FFPuppet() as ffp:
        assert ffp._dbg == Debugger.NONE
        assert ffp.launches == 0
        assert ffp.reason == Reason.CLOSED
        assert not ffp.is_running()
        with HTTPTestServer() as srv:
            ffp.launch(TESTFF_BIN, location=srv.get_addr())
            assert ffp._proc_tree is not None
            assert not ffp._checks
            assert ffp.launches == 1
            assert not ffp.wait(timeout=0)
            assert ffp.is_running()
            assert ffp.is_healthy()
            assert ffp.reason is None
            assert ffp.get_pid() is not None
            ffp.close()
        assert ffp.reason == Reason.CLOSED
        assert ffp._proc_tree is None
        assert not ffp.is_running()
        assert not ffp.is_healthy()
        assert ffp.wait(timeout=10)


@mark.parametrize(
    "exc_type",
    [
        # startup crash
        BrowserTerminatedError,
        # startup hang
        BrowserTimeoutError,
    ],
)
def test_ffpuppet_02(mocker, exc_type):
    """test launch failures"""
    mocker.patch("ffpuppet.core.Popen", autospec=True)
    mocker.patch("ffpuppet.core.ProcessTree", autospec=True)
    fake_bts = mocker.patch("ffpuppet.core.Bootstrapper", autospec=True)
    fake_bts.create.return_value.location = "http://fake.location"
    fake_bts.create.return_value.wait.side_effect = exc_type("test")
    with FFPuppet() as ffp:
        with raises(exc_type, match="test"):
            ffp.launch(TESTFF_BIN)
        assert ffp.launches == 0


def test_ffpuppet_03(tmp_path):
    """test logging"""
    with FFPuppet() as ffp:
        ffp.close()
        ffp.save_logs(tmp_path / "no_logs")
        prefs = tmp_path / "prefs.js"
        prefs.write_bytes(b"//fftest_exit_code_0\n")
        with HTTPTestServer() as srv:
            ffp.launch(TESTFF_BIN, location=srv.get_addr(), prefs_js=prefs)
            ffp.wait(timeout=10)
            ffp.close()
        assert ffp._logs.closed
        log_ids = ffp.available_logs()
        assert len(log_ids) == 2
        assert "stderr" in log_ids
        assert "stdout" in log_ids
        logs = tmp_path / "logs"  # nonexistent directory
        ffp.save_logs(logs)
        assert logs.is_dir()
        assert len(tuple(logs.iterdir())) == 2
        log_data = (logs / "log_stderr.txt").read_text()
        assert "[ffpuppet] Launch command:" in log_data
        assert "[ffpuppet] Reason code:" in log_data
        log_data = (logs / "log_stdout.txt").read_text()
        assert "url: 'http://" in log_data
        assert "hello world" in log_data


def test_ffpuppet_04(mocker):
    """test get_pid()"""
    with FFPuppet() as ffp:
        assert ffp.get_pid() is None
        ffp._proc_tree = mocker.Mock(spec_set=ProcessTree)
        ffp._proc_tree.parent = mocker.Mock(spec_set=Process, pid=123)
        assert ffp.get_pid() == 123
        ffp._proc_tree = None


def test_ffpuppet_05(mocker):
    """test is_running()"""
    with FFPuppet() as ffp:
        assert not ffp.is_running()
        ffp._proc_tree = mocker.Mock(spec_set=ProcessTree)
        ffp._proc_tree.is_running.side_effect = (True, False)
        assert ffp.is_running()
        assert not ffp.is_running()
        ffp._proc_tree = None


def test_ffpuppet_06(mocker):
    """test wait()"""
    with FFPuppet() as ffp:
        # process not running
        assert ffp._proc_tree is None
        assert ffp.wait()
        # process is shutting down
        ffp._proc_tree = mocker.Mock(spec_set=ProcessTree)
        ffp._proc_tree.wait_procs.return_value = 0
        assert ffp.wait()
        assert ffp._proc_tree.wait_procs.call_count == 1
        ffp._proc_tree.wait_procs.reset_mock()
        # process did not close
        ffp._proc_tree.wait_procs.return_value = 1
        assert not ffp.wait(timeout=10)
        assert ffp._proc_tree.wait_procs.call_count == 1
        ffp._proc_tree = None


def test_ffpuppet_07(tmp_path):
    """test clone_log()"""
    logs = tmp_path / "logs.txt"
    with FFPuppet() as ffp:
        assert ffp.clone_log("stdout", target_file=str(logs)) is None
        with HTTPTestServer() as srv:
            ffp.launch(TESTFF_BIN, location=srv.get_addr())
            ffp.wait(timeout=0.25)  # wait for log prints
            # make sure logs are available
            assert ffp.clone_log("stdout", target_file=str(logs)) == logs
            orig = logs.read_text()
            assert len(orig) > 5
            assert ffp.clone_log("stdout", target_file=str(logs), offset=5) == logs
            assert logs.read_text() == orig[5:]
            # grab log without giving a target file name
            rnd_log = ffp.clone_log("stdout")
            assert rnd_log is not None
            try:
                ffp.close()
                # make sure logs are available
                assert ffp.clone_log("stdout", target_file=str(logs)) == logs
                assert logs.read_text().startswith(orig)
            finally:
                if rnd_log:
                    rnd_log.unlink()
        ffp.clean_up()
        # verify clean_up() removed the logs
        assert ffp.clone_log("stdout", target_file=str(logs)) is None


@mark.skipif(system() == "Windows", reason="Unsupported on Windows")
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
                prefs_js=prefs,
                memory_limit=0x100000,
            )
            for _ in range(100):
                if not ffp.is_healthy():
                    break
                sleep(0.1)
            ffp.close()
        assert ffp.reason == Reason.WORKER
        assert len(ffp.available_logs()) == 3
        logs = tmp_path / "logs"
        ffp.save_logs(logs)
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
            with raises(LaunchError, match="Process is already running"):
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
            ffp.launch(TESTFF_BIN, location=srv.get_addr(), prefs_js=prefs)
            for _ in range(200):
                if not ffp.is_healthy():
                    break
                sleep(0.05)
            ffp.close()
        assert ffp.reason == Reason.WORKER
        assert len(ffp.available_logs()) == 3
        logs = tmp_path / "logs"
        ffp.save_logs(logs)
        worker_log = logs / "log_ffp_worker_log_contents.txt"
        assert worker_log.is_file()
        assert b"TOKEN_LOCATED: ASSERTION: test" in worker_log.read_bytes()


def test_ffpuppet_11(tmp_path):
    """test using an existing profile directory"""
    prf_dir = tmp_path / "ffp_test_prof"
    prf_dir.mkdir()
    with FFPuppet(use_profile=prf_dir) as ffp:
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
            with raises(AssertionError):
                ffp.launch(TESTFF_BIN, location=srv.get_addr())
            with raises(AssertionError):
                ffp.close()


def test_ffpuppet_13(mocker):
    """test launching under Xvfb"""
    mocker.patch("ffpuppet.core.Popen", autospec=True)
    mocker.patch("ffpuppet.core.ProcessTree", autospec=True)
    fake_bts = mocker.patch("ffpuppet.core.Bootstrapper", autospec=True)
    fake_bts.create.return_value.location = "http://test:123"
    fake_system = mocker.patch("ffpuppet.core.system", autospec=True)
    is_linux = system() == "Linux"
    fake_xvfb = mocker.patch(
        "ffpuppet.core.Xvfb", autospec=is_linux, create=not is_linux
    )
    # success
    fake_system.return_value = "Linux"
    with FFPuppet(headless="xvfb") as ffp:
        ffp.launch(TESTFF_BIN)
    assert fake_xvfb.call_count == 1
    assert fake_xvfb.return_value.start.call_count == 1
    fake_xvfb.reset_mock()
    # success - legacy
    fake_system.return_value = "Linux"
    with FFPuppet(use_xvfb=True):
        pass
    assert fake_xvfb.call_count == 1
    assert fake_xvfb.return_value.start.call_count == 1
    fake_xvfb.reset_mock()
    # not installed
    fake_xvfb.side_effect = NameError
    with raises(OSError, match="Please install xvfbwrapper"):
        FFPuppet(headless="xvfb")
    assert fake_xvfb.start.call_count == 0


def test_ffpuppet_14(tmp_path):
    """test passing a file and a non existing file to launch() via location"""
    with FFPuppet() as ffp:
        with raises(OSError, match="Cannot find"):
            ffp.launch(TESTFF_BIN, location="missing.file")
        ffp.close()
        prefs = tmp_path / "prefs.js"
        prefs.write_bytes(b"//fftest_exit_code_0\n")
        test_file = tmp_path / "test_file"
        test_file.write_bytes(b"test")
        # needs realpath() for OSX & normcase() for Windows
        fname = os.path.normcase(os.path.realpath(str(test_file)))
        # use relative binary path to verify it is resolved
        ffp.launch(TESTFF_BIN.relative_to(Path.cwd()), location=fname, prefs_js=prefs)
        assert ffp._bin_path.is_absolute()
        ffp.wait(timeout=10)
        ffp.close()
        logs = tmp_path / "logs"
        ffp.save_logs(logs)
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


@mark.parametrize(
    "debugger, dbg_bin, version",
    [
        (Debugger.GDB, b"gdb", b""),
        (Debugger.PERNOSCO, b"rr", b""),
        (Debugger.RR, b"rr", b""),
        (Debugger.VALGRIND, b"valgrind", b"valgrind-99.0"),
    ],
)
def test_ffpuppet_15(mocker, tmp_path, debugger, dbg_bin, version):
    """test launching with debuggers"""
    mocker.patch("ffpuppet.core.check_output", autospec=True, return_value=version)
    mocker.patch("ffpuppet.core.Popen", autospec=True)
    mocker.patch("ffpuppet.core.ProcessTree", autospec=True)
    mocker.patch("ffpuppet.core.system", autospec=True, return_value="Linux")
    fake_bts = mocker.patch("ffpuppet.core.Bootstrapper", autospec=True)
    fake_bts.create.return_value.location = "http://test:123"
    with FFPuppet(debugger=debugger) as ffp:
        assert ffp._dbg == debugger
        ffp.launch(TESTFF_BIN)
        ffp.close()
        ffp.save_logs(tmp_path / "logs")
    # verify launch command was correct
    log_data = (tmp_path / "logs" / "log_stderr.txt").read_bytes()
    assert dbg_bin in log_data
    assert b"[ffpuppet] Reason code:" in log_data


def test_ffpuppet_16(tmp_path):
    """test calling save_logs() before close()"""
    with FFPuppet() as ffp:
        with HTTPTestServer() as srv:
            ffp.launch(TESTFF_BIN, location=srv.get_addr())
            with raises(AssertionError):
                ffp.save_logs(tmp_path / "logs")


def test_ffpuppet_17(tmp_path):
    """test detecting invalid prefs file"""
    prefs = tmp_path / "prefs.js"
    prefs.write_bytes(b"//fftest_invalid_js\n")
    with FFPuppet() as ffp:
        with HTTPTestServer() as srv:
            with raises(LaunchError, match="'.+?' is invalid"):
                ffp.launch(TESTFF_BIN, location=srv.get_addr(), prefs_js=prefs)


def test_ffpuppet_18():
    """test log_length()"""
    with FFPuppet() as ffp:
        assert ffp.log_length("INVALID") is None
        assert ffp.log_length("stderr") is None
        ffp.launch(TESTFF_BIN)
        ll = ffp.log_length("stderr")
        assert ll is not None
        assert ll > 0
        ffp.close()
        ll = ffp.log_length("stderr")
        assert ll is not None
        assert ll > 0
        ffp.clean_up()
        # verify clean_up() removed the logs
        assert ffp.log_length("stderr") is None


def test_ffpuppet_19():
    """test running multiple instances in parallel"""
    # use test pool size of 10
    with HTTPTestServer() as srv:
        ffp_instances = list(FFPuppet() for _ in range(10))
        try:
            for ffp in ffp_instances:
                # NOTE: launching truly in parallel can DoS the test webserver
                ffp.launch(TESTFF_BIN, location=srv.get_addr())
                assert ffp.is_running()
                assert ffp.launches == 1
        finally:
            for ffp in ffp_instances:
                ffp.clean_up()


def test_ffpuppet_20(tmp_path):
    """test hitting log size limit"""
    prefs = tmp_path / "prefs.js"
    prefs.write_bytes(b"//fftest_big_log\n")
    with FFPuppet() as ffp:
        limit = 0x100000  # 1MB
        ffp.launch(TESTFF_BIN, prefs_js=prefs, log_limit=limit)
        for _ in range(100):
            if not ffp.is_healthy():
                break
            sleep(0.1)
        ffp.close()
        assert ffp.reason == Reason.WORKER
        logs = tmp_path / "logs"
        ffp.save_logs(logs)
        logfiles = tuple(logs.iterdir())
        assert len(logfiles) == 3
        assert sum(x.stat().st_size for x in logfiles) > limit
        assert (
            b"LOG_SIZE_LIMIT_EXCEEDED"
            in (logs / "log_ffp_worker_log_size.txt").read_bytes()
        )


def test_ffpuppet_21(tmp_path):
    """test collecting and cleaning up ASan logs"""
    test_logs = []
    with FFPuppet() as ffp:
        ffp.launch(TESTFF_BIN)
        assert ffp._logs.path is not None
        for i in range(4):
            test_logs.append(Path(f"{ffp._logs.path / ffp._logs.PREFIX_SAN}.{i}"))
        # ignore benign ASan warning
        with test_logs[0].open("w") as log_fp:
            log_fp.write("==123==WARNING: Symbolizer buffer too small")
        assert ffp.is_healthy()
        # small log with nothing interesting
        with test_logs[1].open("w") as log_fp:
            log_fp.write("SHORT LOG\n")
            log_fp.write("filler line")
        # crash on another thread
        with test_logs[2].open("w") as log_fp:
            log_fp.write("GOOD LOG\n")
            log_fp.write(
                "==70811==ERROR: AddressSanitizer:"
                " SEGV on unknown address 0x00000BADF00D"
                " (pc 0x7f4c0bb54c67 bp 0x7f4c07bea380 sp 0x7f4c07bea360 T0)\n"
            )  # must be 2nd line
            for _ in range(4):  # pad out to 6 lines
                log_fp.write("filler line\n")
        # child log that should be ignored (created when parent crashes)
        with test_logs[3].open("w") as log_fp:
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
        # close fake browser process before calling close to avoid hang
        ffp._proc_tree.terminate()
        ffp.close()
        assert ffp.reason == Reason.ALERT
        logs = tmp_path / "logs"
        ffp.save_logs(logs)
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
    assert not any(f.is_file() for f in test_logs)


@mark.parametrize("mdsw_available", [True, False])
def test_ffpuppet_22(mocker, tmp_path, mdsw_available):
    """test multiple minidumps"""

    def _fake_create_log(src, filename, _timeout: int = 90):
        dst = tmp_path / "md_parser_working_path"
        dst.mkdir(exist_ok=True)
        (dst / filename).write_text(src.read_text())
        return dst / filename

    md_parser = mocker.patch("ffpuppet.core.MinidumpParser")
    md_parser.mdsw_available.return_value = mdsw_available
    md_parser.return_value.__enter__.return_value.create_log.side_effect = (
        _fake_create_log
    )
    profile = tmp_path / "profile"
    profile.mkdir()
    (profile / "minidumps").mkdir()
    with FFPuppet(use_profile=profile) as ffp:
        ffp.launch(TESTFF_BIN)
        ffp._bin_path = ffp.profile.path
        assert ffp._bin_path is not None
        # create "test.dmp" files
        md_path = ffp.profile.path / "minidumps"
        (md_path / "test1.dmp").write_text("1a\n1b")
        (md_path / "test2.dmp").write_text("2a\n2b")
        (md_path / "test3.dmp").write_text("3a\n3b")
        assert not ffp.is_healthy()
        # close fake browser process before calling close to avoid hang
        ffp._proc_tree.terminate()
        ffp.close()
        logs = tmp_path / "logs"
        ffp.save_logs(logs)
        assert md_parser.mdsw_available.call_count == 1
        if mdsw_available:
            assert md_parser.call_count == 1
            assert any(logs.glob("log_minidump_00.txt"))
            assert any(logs.glob("log_minidump_01.txt"))
            assert any(logs.glob("log_minidump_02.txt"))
        else:
            assert md_parser.call_count == 0


def test_ffpuppet_23(tmp_path):
    """test rmtree error handler"""
    # normal profile creation
    # - just create a puppet, write a readonly file in its profile, then call close()
    with FFPuppet() as ffp:
        ffp.launch(TESTFF_BIN)
        assert ffp.profile is not None
        ro_file = ffp.profile.path / "read-only-test.txt"
        ro_file.touch()
        ro_file.chmod(S_IREAD)
        ffp.close()
        assert not ro_file.is_file()
        ffp.clean_up()
    # use template profile that contains a readonly file
    profile = tmp_path / "profile"
    profile.mkdir()
    ro_file = profile / "read-only.txt"
    ro_file.touch()
    ro_file.chmod(S_IREAD)
    with FFPuppet(use_profile=profile) as ffp:
        ffp.launch(TESTFF_BIN)
        assert ffp.profile is not None
        prof_path = ffp.profile.path
        assert prof_path.is_dir()
        ffp.close()
        assert not prof_path.is_dir()


def test_ffpuppet_24(tmp_path):
    """test using a readonly prefs.js and extension"""
    prefs = tmp_path / "prefs.js"
    prefs.touch()
    prefs.chmod(S_IREAD)
    ext = tmp_path / "ext.xpi"
    ext.touch()
    ext.chmod(S_IREAD)
    with FFPuppet() as ffp:
        ffp.launch(TESTFF_BIN, extension=[ext], prefs_js=prefs)
        prof_path = ffp.profile.path
        ffp.close()
        assert prof_path is not None
        assert not prof_path.is_dir()


def test_ffpuppet_25(mocker, tmp_path):
    """test _crashreports()"""
    mocker.patch(
        "ffpuppet.core.check_output", autospec=True, return_value=b"valgrind-99.0"
    )

    class StubbedLaunch(FFPuppet):
        # pylint: disable=arguments-differ
        def launch(self):
            self.profile = Profile(working_path=tmp_path)
            (self.profile.path / "minidumps").mkdir()

        def close(self, force_close=False):
            assert self.profile is not None
            self.profile.remove()
            self.profile = None

    is_linux = system() == "Linux"
    # only check Valgrind logs on Linux
    debugger = Debugger.VALGRIND if is_linux else Debugger.NONE
    with StubbedLaunch(debugger=debugger) as ffp:
        assert ffp._dbg == debugger
        ffp.launch()
        assert not any(ffp._crashreports())
        # benign sanitizer warnings
        assert ffp._logs.path is not None
        ign_log = ffp._logs.path / f"{ffp._logs.PREFIX_SAN}.1"
        ign_log.write_text(
            "==123==WARNING: Symbolizer buffer too small\n\n"
            "==123==WARNING: Symbolizer buffer too small\n\n"
            "==123==WARNING: AddressSanitizer failed to allocate 0xFFFFFF bytes\n"
            "==123==AddressSanitizer: soft rss limit exhausted (5000Mb vs 5026Mb)\n"
        )
        assert any(ffp._crashreports(skip_benign=False))
        # valid sanitizer log
        san_log = ffp._logs.path / f"{ffp._logs.PREFIX_SAN}.2"
        san_log.write_text("test\n")
        # valid Valgrind log - with error
        vg1_log = ffp._logs.path / f"{ffp._logs.PREFIX_VALGRIND}.1"
        vg1_log.write_text("test\n")
        # valid Valgrind log - without error
        (ffp._logs.path / f"{ffp._logs.PREFIX_VALGRIND}.2").touch()
        # nothing interesting
        (ffp._logs.path / "junk.log").write_text("test\n")
        # valid minidump
        assert ffp.profile is not None
        (ffp.profile.path / "minidumps" / "test.dmp").write_text("test\n")
        # nothing interesting
        (ffp.profile.path / "minidumps" / "test.junk").write_text("\n")
        assert not ffp._logs.watching
        assert len(list(ffp._crashreports())) == (3 if is_linux else 2)
        assert ffp._logs.watching
        assert len(list(ffp._crashreports(skip_md=True))) == (2 if is_linux else 1)
        if system() != "Windows":
            # fail to open (for read) and scan sanitizer file
            # not tested on Windows because chmod() does not work
            ffp._logs.watching.clear()
            ign_log.chmod(S_IWRITE)
            assert len(list(ffp._crashreports())) == (4 if is_linux else 3)
            assert not ffp._logs.watching


def test_ffpuppet_26(mocker, tmp_path):
    """test build_launch_cmd()"""
    with FFPuppet() as ffp:
        cmd = ffp.build_launch_cmd("bin_path", ["test"])
        assert len(cmd) == 3
        assert cmd[0] == "bin_path"
        assert cmd[-1] == "test"
        assert "-headless" not in cmd
        # headless
        ffp._headless = "default"
        cmd = ffp.build_launch_cmd("bin_path", ["test"])
        assert len(cmd) == 4
        assert cmd[0] == "bin_path"
        assert cmd[-1] == "test"
        assert "-headless" in cmd
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
        assert "--chaos" not in cmd
        assert "--disable-cpuid-features-ext" in cmd
        # RR
        ffp._dbg = Debugger.RR
        mocker.patch.dict(os.environ, {"RR_CHAOS": "1"})
        cmd = ffp.build_launch_cmd("bin_path")
        assert len(cmd) > 2
        assert cmd[0] == "rr"
        assert "--chaos" in cmd
        assert "--disable-cpuid-features-ext" not in cmd
        # Valgrind
        ffp._dbg = Debugger.VALGRIND
        mocker.patch.dict(os.environ, {"VALGRIND_SUP_PATH": "blah"})
        with raises(OSError):
            ffp.build_launch_cmd("bin_path")
        supp = tmp_path / "suppressions.txt"
        supp.touch()
        mocker.patch.dict(os.environ, {"VALGRIND_SUP_PATH": str(supp)})
        cmd = ffp.build_launch_cmd("bin_path")
        assert len(cmd) > 2
        assert cmd[0] == "valgrind"


def test_ffpuppet_27():
    """test cpu_usage()"""
    with FFPuppet() as ffp:
        assert not any(ffp.cpu_usage())
        with HTTPTestServer() as srv:
            ffp.launch(TESTFF_BIN, location=srv.get_addr())
            usage = next(ffp.cpu_usage())
            assert usage
            assert usage[1] >= 0
        ffp.close()
        assert ffp.wait(timeout=10)


def test_ffpuppet_28(mocker):
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
    with raises(OSError, match="Please install GDB"):
        FFPuppet._dbg_sanity_check(Debugger.GDB)
    fake_chkout.reset_mock()
    fake_chkout.side_effect = None
    # gdb - unsupported OS
    fake_system.return_value = "Windows"
    with raises(OSError, match="GDB is only supported on Linux"):
        FFPuppet._dbg_sanity_check(Debugger.GDB)
    # rr - success
    fake_system.return_value = "Linux"
    FFPuppet._dbg_sanity_check(Debugger.RR)
    assert fake_chkout.call_count == 1
    fake_chkout.reset_mock()
    # rr - not installed
    fake_chkout.side_effect = OSError
    with raises(OSError, match="Please install rr"):
        FFPuppet._dbg_sanity_check(Debugger.RR)
    fake_chkout.reset_mock()
    fake_chkout.side_effect = None
    # rr - unsupported OS
    fake_system.return_value = "Windows"
    with raises(OSError, match="rr is only supported on Linux"):
        FFPuppet._dbg_sanity_check(Debugger.RR)
    # valgrind - success
    fake_system.return_value = "Linux"
    fake_chkout.return_value = f"valgrind-{FFPuppet.VALGRIND_MIN_VERSION:.2f}".encode()
    FFPuppet._dbg_sanity_check(Debugger.VALGRIND)
    assert fake_chkout.call_count == 1
    fake_chkout.reset_mock()
    # valgrind - old version
    fake_system.return_value = "Linux"
    fake_chkout.return_value = b"valgrind-0.1"
    with raises(OSError, match=r"Valgrind >= \d+\.\d+ is required"):
        FFPuppet._dbg_sanity_check(Debugger.VALGRIND)
    assert fake_chkout.call_count == 1
    fake_chkout.reset_mock()
    # valgrind - not installed
    fake_chkout.side_effect = OSError
    with raises(OSError, match="Please install Valgrind"):
        FFPuppet._dbg_sanity_check(Debugger.VALGRIND)
    fake_chkout.reset_mock()
    fake_chkout.side_effect = None
    # valgrind - unsupported OS
    fake_system.return_value = "Windows"
    with raises(OSError, match="Valgrind is only supported on Linux"):
        FFPuppet._dbg_sanity_check(Debugger.VALGRIND)


def test_ffpuppet_29(mocker, tmp_path):
    """test FFPuppet.close() setting reason"""

    class StubbedProc(FFPuppet):
        # pylint: disable=arguments-differ
        def launch(self):
            self.reason = None
            self._bin_path = tmp_path
            self._logs.reset()
            self._logs.add_log("stderr")
            self._proc_tree = mocker.Mock(spec_set=ProcessTree)
            self._proc_tree.wait_procs.return_value = 1
            profile = tmp_path / "profile"
            profile.mkdir(exist_ok=True)
            self.profile = Profile(working_path=profile)

    fake_wait_files = mocker.patch("ffpuppet.core.wait_on_files", autospec=True)
    # process exited - no crash
    mocker.patch.object(StubbedProc, "_crashreports", return_value=())
    with StubbedProc() as ffp:
        ffp.launch()
        ffp._proc_tree.wait.return_value = 0
        ffp._proc_tree.is_running.return_value = False
        assert not ffp.is_healthy()
        ffp.close()
        assert ffp._proc_tree is None
        assert ffp._logs.closed
        assert ffp.reason == Reason.EXITED
    # process exited - exit code - crash
    with StubbedProc() as ffp:
        ffp.launch()
        ffp._proc_tree.is_running.return_value = False
        ffp._proc_tree.wait.return_value = -11
        assert not ffp.is_healthy()
        ffp.close()
        assert ffp._proc_tree is None
        assert ffp._logs.closed
        assert ffp.reason == Reason.ALERT
    # process running - no crash reports
    with StubbedProc() as ffp:
        ffp.launch()
        ffp._proc_tree.is_running.return_value = True
        ffp._proc_tree.wait.return_value = None
        assert ffp.is_healthy()
        ffp.close()
        assert ffp._proc_tree is None
        assert ffp._logs.closed
        assert ffp.reason == Reason.CLOSED
    # process running - with crash reports, hang waiting to close
    (tmp_path / "fake_report1").touch()
    mocker.patch.object(
        StubbedProc, "_crashreports", return_value=(tmp_path / "fake_report1",)
    )
    with StubbedProc() as ffp:
        ffp.launch()
        fake_wait_files.return_value = False
        assert not ffp.is_healthy()
        ffp.close()
        assert ffp._proc_tree is None
        assert ffp._logs.closed
        assert ffp.reason == Reason.ALERT
    # process running - with crash reports, multiple logs
    (tmp_path / "fake_report2").touch()
    mocker.patch.object(
        StubbedProc,
        "_crashreports",
        side_effect=(
            (tmp_path / "fake_report1",),
            (tmp_path / "fake_report1", tmp_path / "fake_report2"),
            (tmp_path / "fake_report1", tmp_path / "fake_report2"),
        ),
    )
    with StubbedProc() as ffp:
        ffp.launch()
        fake_wait_files.return_value = True
        ffp.close()
        assert ffp._proc_tree is None
        assert ffp._logs.closed
        assert ffp.reason == Reason.ALERT


def test_ffpuppet_30():
    """test ignoring benign sanitizer logs"""
    with FFPuppet() as ffp:
        ffp.launch(TESTFF_BIN)
        assert ffp._logs.path is not None
        san_log = f"{ffp._logs.path / ffp._logs.PREFIX_SAN}.1"
        assert not ffp._logs.watching
        # ignore benign ASan warning
        with open(san_log, "w") as log_fp:
            log_fp.write("==123==WARNING: Symbolizer buffer too small")
        assert ffp.is_healthy()
        assert san_log in ffp._logs.watching
        ffp.close()
        assert ffp.reason == Reason.CLOSED


@mark.parametrize(
    "bin_exists, expect_exc",
    [
        # failed to execute binary
        (True, BrowserExecutionError),
        # missing binary
        (False, FileNotFoundError),
    ],
)
def test_ffpuppet_31(mocker, tmp_path, bin_exists, expect_exc):
    """test Popen failure during launch"""
    bin_fake = tmp_path / "fake_bin"
    if bin_exists:
        bin_fake.touch()
    exc = FileNotFoundError()
    exc.filename = bin_fake
    mocker.patch("ffpuppet.core.Popen", autospec=True, side_effect=exc)
    fake_bts = mocker.patch("ffpuppet.core.Bootstrapper", autospec=True)
    fake_bts.create.return_value.location = ""
    with FFPuppet() as ffp:
        with raises(expect_exc):
            ffp.launch(TESTFF_BIN)
        assert not ffp.is_healthy()
        assert ffp.launches == 0


@mark.skipif(system() != "Windows", reason="Only supported on Windows")
def test_ffpuppet_32(mocker):
    """test FFPuppet.launch() config_job_object code path"""
    mocker.patch("ffpuppet.core.ProcessTree", autospec=True)
    fake_bts = mocker.patch("ffpuppet.core.Bootstrapper", autospec=True)
    fake_bts.create.return_value.location = ""
    fake_popen = mocker.patch("ffpuppet.core.Popen", autospec=True)
    fake_popen.return_value._handle = 123
    fake_popen.return_value.pid = 789
    config_job_object = mocker.patch("ffpuppet.core.config_job_object", autospec=True)
    resume_suspended = mocker.patch(
        "ffpuppet.core.resume_suspended_process", autospec=True
    )
    with FFPuppet() as ffp:
        ffp.launch(TESTFF_BIN, memory_limit=456)
    assert config_job_object.call_count == 1
    assert config_job_object.mock_calls[0] == mocker.call(123, 456)
    assert resume_suspended.call_count == 1
    assert resume_suspended.mock_calls[0] == mocker.call(789)
