# coding=utf-8
"""ffpuppet puppet logger tests"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access

import json
import os
import tempfile
import time

import pytest

from .puppet_logger import PuppetLogger, onerror


def test_puppet_logger_01(tmp_path):
    """test simple PuppetLogger()"""
    plog = PuppetLogger(base_path=str(tmp_path))
    assert not plog.closed
    assert not plog._logs
    assert plog.working_path is not None
    assert os.path.isdir(plog.working_path)
    assert plog._base is not None
    assert any(os.scandir(plog._base))
    plog.close()
    assert any(os.scandir(plog._base))
    assert plog.closed
    with pytest.raises(AssertionError):
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
        assert os.path.isfile(plog.get_fp("test_new").name)
        with (tmp_path / "test_existing.txt").open("w+b") as in_fp:
            in_fp.write(b"blah")
            plog.add_log("test_existing", logfp=in_fp)
        assert len(plog.available_logs()) == 2
        assert len(tuple(plog.files)) == 2
        assert os.path.isfile(plog.get_fp("test_existing").name)
        assert plog.log_length("test_new") == 0
        assert plog.log_length("test_existing") == 4


def test_puppet_logger_03(tmp_path):
    """test PuppetLogger.clean_up()"""
    with PuppetLogger(base_path=str(tmp_path)) as plog:
        assert not plog.closed
        assert not plog._logs
        assert plog.working_path is not None
        assert os.path.isdir(plog.working_path)
        assert plog._base is not None
        assert any(os.scandir(plog._base))
        plog.add_log("test_new")
        plog.clean_up()
        assert plog.closed
        assert not any(os.scandir(plog._base))
        assert plog.working_path is None
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
        assert os.path.isdir(plog.working_path)
        assert plog._base is not None
        assert len(os.listdir(plog._base)) == 1


def test_puppet_logger_05(tmp_path):
    """test PuppetLogger.clone_log()"""
    with PuppetLogger(base_path=str(tmp_path)) as plog:
        plog.add_log("test_empty")
        plog.add_log("test_extra")
        plog.get_fp("test_extra").write(b"stuff")
        plog.get_fp("test_extra").flush()
        # test clone
        plog.add_log("test_new")
        pl_fp = plog.get_fp("test_new")
        pl_fp.write(b"test1")
        cloned = plog.clone_log("test_new")
        assert os.path.isfile(cloned)
        with open(cloned, "rb") as log_fp:
            assert log_fp.read() == b"test1"
        os.remove(cloned)
        # test target exists
        target = tmp_path / "target.txt"
        target.touch()
        pl_fp.write(b"test2")
        pl_fp.flush()
        cloned = plog.clone_log("test_new", target_file=str(target))
        assert os.path.isfile(cloned)
        with open(cloned, "rb") as log_fp:
            assert log_fp.read() == b"test1test2"
        os.remove(cloned)
        # test target does not exist with offset
        assert not target.is_file()
        pl_fp.write(b"test3")
        pl_fp.flush()
        cloned = plog.clone_log("test_new", target_file=str(target), offset=4)
        assert os.path.isfile(cloned)
        with open(cloned, "rb") as log_fp:
            assert log_fp.read() == b"1test2test3"
        assert plog.log_length("test_new") == 15
        os.remove(cloned)
        # test non existent log
        assert plog.clone_log("no_log") is None
        # test empty log
        assert plog.log_length("test_empty") == 0
        cloned = plog.clone_log("test_empty")
        assert os.path.isfile(cloned)
        assert not os.stat(cloned).st_size
        os.remove(cloned)


def test_puppet_logger_06(tmp_path):
    """test PuppetLogger.save_logs()"""
    with PuppetLogger(base_path=str(tmp_path)) as plog:
        plog.close()
        # save when there are no logs
        dest = tmp_path / "dest"
        plog.save_logs(str(dest))
        assert not any(dest.iterdir())
        plog.reset()
        dest.rmdir()
        # add small log
        plog.add_log("test_1")
        plog.get_fp("test_1").write(b"test1\ntest1\n")
        # add binary data in log
        plog.add_log("test_2")
        plog.get_fp("test_2").write(b"\x00TEST\xFF\xEF")
        # add empty log
        plog.add_log("test_empty")
        # add larger log (not a power of 2 to help catch buffer issues)
        plog.add_log("test_3")
        data = b"A" * 1234
        for _ in range(500):
            plog.get_fp("test_3").write(data)
        meta_test = tmp_path / "test_meta.txt"
        with meta_test.open("w+b") as meta_fp:
            meta_fp.write(b"blah")
            plog.add_log("test_meta", logfp=meta_fp)
        # delay to check if creation time was copied when save_logs is called
        time.sleep(0.1)
        plog.close()
        dest.mkdir()
        plog.save_logs(str(dest), meta=True)
        # grab meta data and remove test file
        meta_ctime = meta_test.stat().st_ctime
        meta_test.unlink()
        # check saved file count
        assert len(plog.available_logs()) == 5
        assert len(tuple(dest.iterdir())) == 6
        # verify meta data was copied
        meta_file = dest / PuppetLogger.META_FILE
        assert meta_file.is_file()
        meta_map = json.loads(meta_file.read_text())
        assert len(meta_map) == 5
        assert meta_ctime == meta_map["log_test_meta.txt"]["st_ctime"]
        # verify all data was copied
        assert os.stat(plog.get_fp("test_1").name).st_size == 12
        assert os.stat(plog.get_fp("test_2").name).st_size == 7
        assert os.stat(plog.get_fp("test_3").name).st_size == 500 * 1234


def test_puppet_logger_07(mocker, tmp_path):
    """test PuppetLogger.save_logs() rr trace directory"""
    fake_ck = mocker.patch("ffpuppet.puppet_logger.check_output", autospec=True)
    with PuppetLogger(base_path=str(tmp_path)) as plog:
        os.makedirs(os.path.join(plog.working_path, plog.PATH_RR, "latest-trace"))
        plog.close()
        # test call to rr failing
        fake_ck.side_effect = OSError
        plog.save_logs(str(tmp_path / "dest1"), rr_pack=True)
        assert fake_ck.call_count == 1
        assert not plog._rr_packed
        # test call to rr passing
        fake_ck.side_effect = None
        plog.save_logs(str(tmp_path / "dest2"), rr_pack=True)
        assert fake_ck.call_count == 2
        assert plog._rr_packed
        # test 'taskcluster-build-task' copied
        bin_path = tmp_path / "bin_path"
        bin_path.mkdir()
        (bin_path / "taskcluster-build-task").write_text("task-info\n")
        plog.save_logs(str(tmp_path / "dest3"), bin_path=str(bin_path))
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
        with tempfile.SpooledTemporaryFile(max_size=2048) as log_fp:
            plog.add_log("test", logfp=log_fp)
            with pytest.raises(IOError, match="log file None does not exist"):
                plog.get_fp("test")


def test_puppet_logger_09(mocker, tmp_path):
    """test PuppetLogger.clean_up() with in-use file or inaccessible directory"""
    fake_rmtree = mocker.patch("ffpuppet.puppet_logger.rmtree", autospec=True)
    with PuppetLogger(base_path=str(tmp_path)) as plog:
        plog.add_log("test")
        working_path = plog.working_path
        # test with ignore_errors=False
        fake_rmtree.side_effect = OSError
        with pytest.raises(OSError):
            plog.clean_up()
        assert fake_rmtree.call_count == 2
        fake_rmtree.assert_called_with(
            working_path, ignore_errors=False, onerror=onerror
        )
        assert plog.working_path is not None
        fake_rmtree.reset_mock()
        # test with ignore_errors=True
        fake_rmtree.side_effect = None
        plog.clean_up(ignore_errors=True)
        assert fake_rmtree.call_count == 1
        fake_rmtree.assert_called_with(
            working_path, ignore_errors=True, onerror=onerror
        )
        assert plog.working_path is None


def test_puppet_logger_10(tmp_path):
    """test PuppetLogger.add_path()"""
    with PuppetLogger(base_path=str(tmp_path)) as plog:
        path = plog.add_path("test")
        assert os.path.isdir(path)
        with open(os.path.join(path, "simple.txt"), "w") as o_fp:
            o_fp.write("test")
        plog.close()
        dest = tmp_path / "dest"
        plog.save_logs(str(dest))
        assert (dest / "test").is_dir()
        assert (dest / "test" / "simple.txt").is_file()
