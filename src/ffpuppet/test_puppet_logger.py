# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet puppet logger tests"""
# pylint: disable=protected-access

import os
from tempfile import SpooledTemporaryFile
from time import sleep

from pytest import raises

from .helpers import onerror
from .puppet_logger import PuppetLogger


def test_puppet_logger_01(tmp_path):
    """test simple PuppetLogger()"""
    plog = PuppetLogger(base_path=str(tmp_path))
    assert not plog.closed
    assert not plog._logs
    assert plog.path is not None
    assert plog.path.is_dir()
    assert plog._base is not None
    assert any(os.scandir(plog._base))
    plog.close()
    assert any(os.scandir(plog._base))
    assert plog.closed
    with raises(AssertionError):
        plog.add_log("test")
    assert plog.log_length("missing") is None


def test_puppet_logger_02(tmp_path):
    """test PuppetLogger.add_log() and PuppetLogger.available_logs()"""
    with PuppetLogger(base_path=str(tmp_path)) as plog:
        assert not plog._logs
        assert not plog.available_logs()
        assert not any(plog.files)
        plog.add_log("test_new")  # non-existing log
        assert "test_new" in plog.available_logs()
        plog_fp_test_new = plog.get_fp("test_new")
        assert plog_fp_test_new is not None
        assert os.path.isfile(plog_fp_test_new.name)
        with (tmp_path / "test_existing.txt").open("w+b") as in_fp:
            in_fp.write(b"blah")
            plog.add_log("test_existing", logfp=in_fp)
        assert len(plog.available_logs()) == 2
        assert len(tuple(plog.files)) == 2
        plog_fp_test_existing = plog.get_fp("test_existing")
        assert plog_fp_test_existing is not None
        assert os.path.isfile(plog_fp_test_existing.name)
        assert plog.log_length("test_new") == 0
        assert plog.log_length("test_existing") == 4


def test_puppet_logger_03(tmp_path):
    """test PuppetLogger.clean_up()"""
    with PuppetLogger(base_path=str(tmp_path)) as plog:
        assert not plog.closed
        assert not plog._logs
        assert plog.path is not None
        assert plog.path.is_dir()
        assert plog._base is not None
        assert any(os.scandir(plog._base))
        plog.add_log("test_new")
        plog.clean_up()
        assert plog.closed
        assert not any(os.scandir(plog._base))
        assert plog.path is None
        assert plog.closed
        assert not plog._logs


def test_puppet_logger_04(tmp_path):
    """test PuppetLogger.reset()"""
    with PuppetLogger(base_path=str(tmp_path)) as plog:
        plog.add_log("test_new")
        plog.clean_up()
        plog.reset()
        assert not plog.closed
        assert not plog._logs
        assert plog.path is not None
        assert plog.path.is_dir()
        assert plog._base is not None
        assert len(os.listdir(plog._base)) == 1


def test_puppet_logger_05(tmp_path):
    """test PuppetLogger.clone_log()"""
    with PuppetLogger(base_path=str(tmp_path)) as plog:
        plog.add_log("test_empty")
        plog.add_log("test_extra")
        plog_fp_test_extra = plog.get_fp("test_extra")
        assert plog_fp_test_extra is not None
        plog_fp_test_extra.write(b"stuff")
        plog_fp_test_extra.flush()
        # test clone
        plog.add_log("test_new")
        pl_fp = plog.get_fp("test_new")
        assert pl_fp is not None
        pl_fp.write(b"test1")
        cloned = plog.clone_log("test_new")
        assert cloned is not None
        assert cloned.is_file()
        assert cloned.read_bytes() == b"test1"
        cloned.unlink()
        # test target exists
        target = tmp_path / "target.txt"
        target.touch()
        pl_fp.write(b"test2")
        pl_fp.flush()
        cloned = plog.clone_log("test_new", target_file=str(target))
        assert cloned is not None
        assert cloned.is_file()
        assert cloned.read_bytes() == b"test1test2"
        cloned.unlink()
        # test target does not exist with offset
        assert not target.is_file()
        pl_fp.write(b"test3")
        pl_fp.flush()
        cloned = plog.clone_log("test_new", target_file=str(target), offset=4)
        assert cloned is not None
        assert cloned.is_file()
        assert cloned.read_bytes() == b"1test2test3"
        assert plog.log_length("test_new") == 15
        cloned.unlink()
        # test non existent log
        assert plog.clone_log("no_log") is None
        # test empty log
        assert plog.log_length("test_empty") == 0
        cloned = plog.clone_log("test_empty")
        assert cloned is not None
        assert cloned.is_file()
        assert not cloned.stat().st_size
        cloned.unlink()


def test_puppet_logger_06(tmp_path):
    """test PuppetLogger.save_logs()"""
    with PuppetLogger(base_path=str(tmp_path)) as plog:
        plog.close()
        # save when there are no logs
        dest = tmp_path / "dest"
        plog.save_logs(dest)
        assert not any(dest.iterdir())
        plog.reset()
        dest.rmdir()
        # add small log
        plog.add_log("test_1")
        plog_fp_test_1 = plog.get_fp("test_1")
        assert plog_fp_test_1 is not None
        plog_fp_test_1.write(b"test1\ntest1\n")
        # add binary data in log
        plog.add_log("test_2")
        plog_fp_test_2 = plog.get_fp("test_2")
        assert plog_fp_test_2 is not None
        plog_fp_test_2.write(b"\x00TEST\xFF\xEF")
        # add empty log
        plog.add_log("test_empty")
        # add larger log (not a power of 2 to help catch buffer issues)
        plog.add_log("test_3")
        data = b"A" * 1234
        plog_fp_test_3 = plog.get_fp("test_3")
        assert plog_fp_test_3 is not None
        for _ in range(500):
            plog_fp_test_3.write(data)
        # delay to check if creation time was copied when save_logs is called
        sleep(0.1)
        plog.close()
        dest.mkdir()
        plog.save_logs(dest)
        # check saved file count
        assert len(plog.available_logs()) == 4
        assert len(tuple(dest.iterdir())) == 4
        # verify all data was copied
        assert os.stat(plog_fp_test_1.name).st_size == 12
        assert os.stat(plog_fp_test_2.name).st_size == 7
        assert os.stat(plog_fp_test_3.name).st_size == 500 * 1234


def test_puppet_logger_07(mocker, tmp_path):
    """test PuppetLogger.save_logs() rr trace directory"""
    fake_ck = mocker.patch("ffpuppet.puppet_logger.check_output", autospec=True)
    with PuppetLogger(base_path=str(tmp_path)) as plog:
        assert plog.path is not None
        (plog.path / plog.PATH_RR / "latest-trace").mkdir(parents=True)
        plog.close()
        # test call to rr failing
        fake_ck.side_effect = OSError
        plog.save_logs(tmp_path / "dest1", rr_pack=True)
        assert fake_ck.call_count == 1
        assert not plog._rr_packed
        # test call to rr passing
        fake_ck.side_effect = None
        plog.save_logs(tmp_path / "dest2", rr_pack=True)
        assert fake_ck.call_count == 2
        assert plog._rr_packed
        # test 'taskcluster-build-task' copied
        bin_path = tmp_path / "bin_path"
        bin_path.mkdir()
        (bin_path / "taskcluster-build-task").write_text("task-info\n")
        plog.save_logs(tmp_path / "dest3", bin_path=bin_path)
        assert (
            tmp_path
            / "dest3"
            / "rr-traces"
            / "latest-trace"
            / "files.mozilla"
            / "taskcluster-build-task"
        ).is_file()
        assert fake_ck.call_count == 2
        assert plog._rr_packed


def test_puppet_logger_08(tmp_path):
    """test PuppetLogger.add_log() with file not on disk"""
    with PuppetLogger(base_path=str(tmp_path)) as plog:
        with SpooledTemporaryFile(max_size=2048) as log_fp:
            plog.add_log("test", logfp=log_fp)
            with raises(OSError, match="log file None does not exist"):
                plog.get_fp("test")


def test_puppet_logger_09(mocker, tmp_path):
    """test PuppetLogger.clean_up() with in-use file or inaccessible directory"""
    fake_rmtree = mocker.patch("ffpuppet.puppet_logger.rmtree", autospec=True)
    with PuppetLogger(base_path=str(tmp_path)) as plog:
        plog.add_log("test")
        path = plog.path
        # test with ignore_errors=False
        fake_rmtree.side_effect = OSError("test")
        with raises(OSError):
            plog.clean_up()
        assert fake_rmtree.call_count == 2
        fake_rmtree.assert_called_with(path, ignore_errors=False, onerror=onerror)
        assert plog.path is not None
        fake_rmtree.reset_mock()
        # test with ignore_errors=True
        fake_rmtree.side_effect = None
        plog.clean_up(ignore_errors=True)
        assert fake_rmtree.call_count == 1
        fake_rmtree.assert_called_with(path, ignore_errors=True, onerror=onerror)
        assert plog.path is None


def test_puppet_logger_10(tmp_path):
    """test PuppetLogger.add_path()"""
    with PuppetLogger(base_path=str(tmp_path)) as plog:
        path = plog.add_path("test")
        assert path.is_dir()
        (path / "simple.txt").write_text("test")
        plog.close()
        dest = tmp_path / "dest"
        plog.save_logs(dest)
        assert (dest / "test").is_dir()
        assert (dest / "test" / "simple.txt").is_file()
