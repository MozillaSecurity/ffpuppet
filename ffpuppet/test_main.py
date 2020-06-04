# coding=utf-8
"""ffpuppet main.py tests"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import pytest

from .main import dump_to_console, main, parse_args


def test_main_01(mocker, tmp_path):
    """test main() with FFPuppet exit"""
    fake_ffp = mocker.patch("ffpuppet.main.FFPuppet", autospec=True)
    fake_ffp.return_value.get_pid.return_value = 12345
    fake_ffp.return_value.is_healthy.return_value = False
    fake_ffp.return_value.profile = str(tmp_path)
    fake_ffp.return_value.reason = "EXITED"
    out_logs = tmp_path / "logs"
    out_logs.mkdir()
    prefs = tmp_path / "prefs.js"
    prefs.touch()
    fake_bin = (tmp_path / "fake.bin")
    fake_bin.touch()
    main([str(fake_bin), "-d", "-l", str(out_logs), "-p", str(prefs), "--save-all"])
    assert fake_ffp.return_value.add_abort_token.call_count == 0
    assert fake_ffp.return_value.get_pid.call_count == 1
    assert fake_ffp.return_value.is_healthy.call_count == 1
    assert fake_ffp.return_value.close.call_count == 1
    assert fake_ffp.return_value.save_logs.call_count == 1
    assert fake_ffp.return_value.clean_up.call_count == 1

def test_main_02(mocker, tmp_path):
    """test main() with user exit"""
    fake_ffp = mocker.patch("ffpuppet.main.FFPuppet", autospec=True)
    fake_ffp.return_value.get_pid.return_value = 12345
    fake_ffp.return_value.profile = str(tmp_path)
    fake_ffp.return_value.reason = "CLOSED"
    fake_sleep = mocker.patch("ffpuppet.main.time.sleep", autospec=True)
    fake_sleep.side_effect = KeyboardInterrupt
    fake_bin = (tmp_path / "fake.bin")
    fake_bin.touch()
    main([str(fake_bin), "-l", str(tmp_path), "-a", "token", "--log-level", "DEBUG"])
    assert fake_ffp.return_value.add_abort_token.call_count == 1
    assert fake_ffp.return_value.get_pid.call_count == 1
    assert fake_ffp.return_value.is_healthy.call_count == 1
    assert fake_ffp.return_value.close.call_count == 1
    assert fake_ffp.return_value.save_logs.call_count == 1
    assert fake_ffp.return_value.clean_up.call_count == 1

def test_parse_args_01(tmp_path):
    """test parse_args()"""
    with pytest.raises(SystemExit):
        parse_args(["-h"])
    # invalid/missing binary
    with pytest.raises(SystemExit):
        parse_args(["fake_bin"])
    fake_bin = (tmp_path / "fake.bin")
    fake_bin.touch()
    # invalid log-limit
    with pytest.raises(SystemExit):
        parse_args([str(fake_bin), "--log-limit", "-1"])
    # invalid memory limit
    with pytest.raises(SystemExit):
        parse_args([str(fake_bin), "--memory", "-1"])
    # missing prefs
    with pytest.raises(SystemExit):
        parse_args([str(fake_bin), "-p", str(tmp_path / "missing")])
    # missing extension
    with pytest.raises(SystemExit):
        parse_args([str(fake_bin), "-e", str(tmp_path / "missing")])
    # multiple debuggers
    with pytest.raises(SystemExit):
        parse_args([str(fake_bin), "--gdb", "--valgrind"])
    # invalid log path
    (tmp_path / "junk.log").touch()
    with pytest.raises(SystemExit):
        parse_args([str(fake_bin), "--logs", "/missing/path/"])
    # invalid log level
    with pytest.raises(SystemExit):
        parse_args([str(fake_bin), "--log-level", "bad"])
    # success
    assert parse_args([str(fake_bin)])

def test_dump_to_console_01(tmp_path):
    """test dump_to_console()"""
    # call with no logs
    assert not dump_to_console(str(tmp_path))
    # call with dummy logs
    (tmp_path / "log_stderr.txt").write_bytes(b"dummy-stderr")
    (tmp_path / "log_stdout.txt").write_bytes(b"dummy-stdout")
    output = dump_to_console(str(tmp_path))
    assert "Dumping 'log_stderr.txt'" in output
    assert "dummy-stderr" in output
    assert "Dumping 'log_stdout.txt'" in output
    assert "dummy-stdout" in output
    # truncate log
    with (tmp_path / "log_stdout.txt").open("wb") as log_fp:
        log_fp.write(b"dummy-stdout")
        for _ in range(1024):
            log_fp.write(b"test")
    output = dump_to_console(str(tmp_path), log_quota=100)
    assert "Dumping 'log_stderr.txt'" in output
    assert "dummy-stderr" in output
    assert "Dumping 'log_stdout.txt'" in output
    assert "dummy-stdout" not in output
