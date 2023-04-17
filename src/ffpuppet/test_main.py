# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet main.py tests"""

from pytest import mark, raises

from .core import Reason
from .exceptions import BrowserExecutionError
from .main import dump_to_console, main, parse_args
from .profile import Profile


@mark.parametrize(
    "reason, launch, is_healthy, extra_args",
    [
        # browser exit
        (Reason.EXITED, None, (False,), ["-d", "--save-all"]),
        # browser exit - more flags
        (Reason.EXITED, None, (False,), ["-a", "token", "--log-level", "DEBUG"]),
        # cannot launch browser binary
        (Reason.CLOSED, (BrowserExecutionError(),), None, []),
        # browser crash
        (Reason.ALERT, None, (False,), []),
        # user exit
        (Reason.CLOSED, None, (True, KeyboardInterrupt()), []),
        # exception
        (None, None, (False,), []),
    ],
)
def test_main_01(mocker, tmp_path, reason, launch, is_healthy, extra_args):
    """test main()"""
    mocker.patch("ffpuppet.main.sleep", autospec=True)
    fake_ffp = mocker.patch("ffpuppet.main.FFPuppet", autospec=True)
    fake_ffp.return_value.get_pid.return_value = 12345
    fake_ffp.return_value.is_healthy.side_effect = is_healthy
    fake_ffp.return_value.launch.side_effect = launch
    fake_ffp.return_value.profile = mocker.Mock(spec_set=Profile, path=tmp_path)
    fake_ffp.return_value.reason = reason
    out_logs = tmp_path / "logs"
    out_logs.mkdir()
    prefs = tmp_path / "prefs.js"
    prefs.touch()
    fake_bin = tmp_path / "fake.bin"
    fake_bin.touch()
    args = [str(fake_bin), "-l", str(out_logs), "-p", str(prefs)]
    main(args + extra_args)
    if "-a" in extra_args:
        assert fake_ffp.return_value.add_abort_token.call_count == 1
    else:
        assert fake_ffp.return_value.add_abort_token.call_count == 0
    assert fake_ffp.return_value.close.call_count == 1
    if "--save-all" in extra_args or Reason.ALERT:
        assert fake_ffp.return_value.save_logs.call_count == 1
    else:
        assert fake_ffp.return_value.save_logs.call_count == 0
    assert fake_ffp.return_value.clean_up.call_count == 1


def test_parse_args_01(mocker, tmp_path):
    """test parse_args()"""
    certutil_avail = mocker.patch("ffpuppet.main.certutil_available", autospec=True)
    with raises(SystemExit):
        parse_args(["-h"])
    # invalid/missing binary
    with raises(SystemExit):
        parse_args(["fake_bin"])
    fake_bin = tmp_path / "fake.bin"
    fake_bin.touch()
    # invalid log-limit
    with raises(SystemExit):
        parse_args([str(fake_bin), "--log-limit", "-1"])
    # invalid memory limit
    with raises(SystemExit):
        parse_args([str(fake_bin), "--memory", "-1"])
    # missing prefs
    with raises(SystemExit):
        parse_args([str(fake_bin), "-p", str(tmp_path / "missing")])
    # missing extension
    with raises(SystemExit):
        parse_args([str(fake_bin), "-e", str(tmp_path / "missing")])
    # missing certificate
    certutil_avail.return_value = True
    with raises(SystemExit):
        parse_args([str(fake_bin), "--cert", str(tmp_path / "missing")])
    # missing certutil
    certutil_avail.return_value = False
    with raises(SystemExit):
        parse_args([str(fake_bin), "--cert", str(fake_bin)])
    # multiple debuggers
    with raises(SystemExit):
        parse_args([str(fake_bin), "--gdb", "--valgrind"])
    # invalid log path
    (tmp_path / "junk.log").touch()
    with raises(SystemExit):
        parse_args([str(fake_bin), "--logs", "/missing/path/"])
    # success
    assert parse_args([str(fake_bin)])


def test_parse_args_02(mocker, tmp_path):
    """test parse_args() - headless"""
    fake_system = mocker.patch("ffpuppet.main.system", autospec=True)
    fake_bin = tmp_path / "fake.bin"
    fake_bin.touch()
    # no headless
    assert parse_args([str(fake_bin)]).headless is None
    # headless (default)
    assert parse_args([str(fake_bin), "--headless"]).headless == "default"
    # headless via Xvfb
    fake_system.return_value = "Linux"
    assert parse_args([str(fake_bin), "--headless", "xvfb"]).headless == "xvfb"
    # --xvfb flag
    assert parse_args([str(fake_bin), "--xvfb"]).headless == "xvfb"
    # headless Xvfb unsupported
    fake_system.return_value = "Windows"
    with raises(SystemExit):
        parse_args([str(fake_bin), "--headless", "xvfb"])


def test_dump_to_console_01(tmp_path):
    """test dump_to_console()"""
    # call with no logs
    assert not dump_to_console(tmp_path)
    # call with dummy logs
    (tmp_path / "log_stderr.txt").write_bytes(b"dummy-stderr")
    (tmp_path / "log_stdout.txt").write_bytes(b"dummy-stdout")
    output = dump_to_console(tmp_path)
    assert "Dumping 'log_stderr.txt'" in output
    assert "dummy-stderr" in output
    assert "Dumping 'log_stdout.txt'" in output
    assert "dummy-stdout" in output
    # truncate log
    with (tmp_path / "log_stdout.txt").open("wb") as log_fp:
        log_fp.write(b"dummy-stdout")
        for _ in range(1024):
            log_fp.write(b"test")
    output = dump_to_console(tmp_path, log_quota=100)
    assert "Dumping 'log_stderr.txt'" in output
    assert "dummy-stderr" in output
    assert "Dumping 'log_stdout.txt'" in output
    assert "dummy-stdout" not in output
