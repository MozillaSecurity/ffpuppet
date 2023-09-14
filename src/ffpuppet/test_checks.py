# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""checks.py tests"""

from os import getpid
from re import compile as re_compile

from psutil import Process

from .checks import CheckLogContents, CheckLogSize, CheckMemoryUsage


def test_check_01(mocker, tmp_path):
    """test CheckLogContents()"""
    test_log = tmp_path / "test.log"
    # input contains token
    test_log.write_bytes(b"\xF0\x9F\x91\x8Dblah\nfoo\ntest\n123")
    checker = CheckLogContents([str(test_log)], [re_compile("test")])
    assert checker.check()
    with test_log.open("wb") as lfp:
        checker.dump_log(lfp)
        assert lfp.tell()
    # input does not contains token
    checker = CheckLogContents([str(test_log)], [re_compile("no_token")])
    assert not checker.check()
    # check a 2nd time
    assert not checker.check()
    with test_log.open("wb") as lfp:
        checker.dump_log(lfp)
        assert not lfp.tell()
    # log does not exist
    checker = CheckLogContents(["missing_log"], [re_compile("no_token")])
    assert not checker.check()
    with test_log.open("wb") as lfp:
        checker.dump_log(lfp)
        assert not lfp.tell()
    # input exceeds chunk_size
    with test_log.open("w") as lfp_txt:
        lfp_txt.write("A" * (CheckLogContents.buf_limit - 2))
        lfp_txt.write("test123")
        lfp_txt.write("A" * 20)
    checker = CheckLogContents([str(test_log)], [re_compile("test123")])
    mocker.patch(
        "ffpuppet.checks.CheckLogContents.chunk_size", CheckLogContents.buf_limit
    )
    assert not checker.check()
    assert checker.check()
    with test_log.open("wb") as lfp:
        checker.dump_log(lfp)
        assert lfp.tell()


def test_check_02(tmp_path):
    """test CheckLogSize()"""
    stde = tmp_path / "stderr"
    stde.write_text("test\n")
    stdo = tmp_path / "stdout"
    stdo.write_text("test\n")
    # exceed limit
    checker = CheckLogSize(1, str(stde), str(stdo))
    assert checker.check()
    with (tmp_path / "log").open("wb") as lfp:
        checker.dump_log(lfp)
        assert lfp.tell()
    # don't exceed limit
    checker = CheckLogSize(12, str(stde), str(stdo))
    assert not checker.check()
    with (tmp_path / "log").open("wb") as lfp:
        checker.dump_log(lfp)
        assert not lfp.tell()


def test_check_03(tmp_path):
    """test CheckMemoryUsage()"""

    def get_procs():
        yield Process(getpid())

    checker = CheckMemoryUsage(getpid(), 300 * 1024 * 1024, get_procs)
    # don't exceed limit
    assert not checker.check()
    with (tmp_path / "log").open("wb") as lfp:
        checker.dump_log(lfp)
        assert not lfp.tell()
    checker = CheckMemoryUsage(getpid(), 10, get_procs)
    # exceed limit
    assert checker.check()
    with (tmp_path / "log").open("wb") as lfp:
        checker.dump_log(lfp)
        assert lfp.tell()
