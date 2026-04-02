# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""process_tree.py tests"""

from collections import namedtuple
from itertools import chain, count, repeat
from pathlib import Path
from subprocess import Popen
from time import sleep
from unittest import mock

from psutil import STATUS_ZOMBIE, AccessDenied, NoSuchProcess, Process, TimeoutExpired
from pytest import mark, raises

from .exceptions import TerminateError
from .process_tree import (
    ProcessTree,
    _filter_zombies,
    _last_modified,
    _safe_wait_procs,
    _writing_coverage,
)

TREE = Path(__file__).parent / "resources" / "tree.py"


@mark.parametrize(
    "enable_launcher, launcher_is_parent",
    [
        # no launcher
        (False, False),
        # use launcher
        (True, False),
        # launcher disabled (browser.launcherProcess.enabled=false)
        (True, True),
    ],
)
def test_process_tree_01(tmp_path, enable_launcher, launcher_is_parent):
    """test ProcessTree() with actual processes"""
    content_procs = 3
    flag = tmp_path / "running"
    # don't use sys.executable it is not always correct (incompatible with tox)
    cmd = [Process().exe(), str(TREE), str(content_procs), str(flag)]

    # parent + content + launcher
    expected_procs = 1 + content_procs
    if enable_launcher:
        if launcher_is_parent:
            cmd.append("--launcher-is-parent")
        else:
            expected_procs += 1
        cmd.append("-no-deelevate")
    else:
        # make sure the test is not broken
        assert not launcher_is_parent, "launcher_is_parent requires launcher!"

    # pylint: disable=consider-using-with
    proc = Popen(cmd)
    tree = ProcessTree(proc.pid)
    try:
        # wait (30 seconds) for tree to launch all processes
        for _ in range(300):
            if flag.exists():
                break
            assert proc.poll() is None
            sleep(0.1)
        else:
            raise AssertionError(f"Process tree ({expected_procs}) failed to launch")
        tree.detect_launcher()
        if enable_launcher and not launcher_is_parent:
            assert tree.launcher is not None
            assert tree.launcher.pid == proc.pid
        else:
            assert tree.launcher is None
            assert tree.parent.pid == proc.pid
        assert ProcessTree._poll(tree.parent) is None
        assert tree.is_running()
        assert len(tree.processes()) == expected_procs
        assert tree.wait_procs() == expected_procs
        usage = tuple(tree.cpu_usage())
        assert len(usage) == expected_procs
        tree.terminate()
    finally:
        # this should cause everything to close gracefully if it is still running
        flag.unlink(missing_ok=True)
        if tree and tree.parent.is_running():
            tree.parent.terminate()
        if proc.poll() is None:
            proc.terminate()
        proc.wait(timeout=30)
    assert not tree.is_running()
    assert not tree.processes()
    assert tree.wait() is not None
    assert tree.wait_procs() == 0


@mark.parametrize(
    "side_effect, expected_result",
    [
        # process exited
        ((0,), 0),
        # process exited - exit code not available
        ((None,), 0),
        # can't find process
        (NoSuchProcess(1), 0),
        # process is running
        (TimeoutExpired(1), None),
    ],
)
def test_process_tree_02(mocker, side_effect, expected_result):
    """test ProcessTree._poll()"""
    proc = mocker.Mock(spec_set=Process)
    proc.wait.side_effect = side_effect
    # pylint: disable=protected-access
    assert ProcessTree._poll(proc) == expected_result


def test_process_tree_03(mocker):
    """test ProcessTree.terminate()"""
    mocker.patch("ffpuppet.process_tree.Process", autospec=True)
    wait_procs = mocker.patch("ffpuppet.process_tree.wait_procs", autospec=True)

    # no processes to terminate
    mocker.patch.object(ProcessTree, "processes", side_effect=([],))
    tree = ProcessTree(1234)
    tree.parent = mocker.Mock(spec_set=Process)
    tree.terminate()
    assert tree.processes.call_count == 1  # pylint: disable=no-member
    assert tree.parent.wait.call_count == 0
    assert tree.parent.terminate.call_count == 0

    # this should be the "normal" code path
    # flow: processes() -> terminate parent -> wait_procs -> processes() -> empty
    proc = mocker.Mock(spec_set=Process, pid=1337)
    wait_procs.return_value = ([proc], [])
    proc.wait.side_effect = (TimeoutExpired(1), None)
    mocker.patch.object(ProcessTree, "processes", side_effect=([proc], []))
    tree = ProcessTree(1234)
    tree.parent = proc
    tree.terminate()
    assert tree.processes.call_count == 2  # pylint: disable=no-member
    assert tree.parent.wait.call_count == 2
    assert tree.parent.terminate.call_count == 1
    assert wait_procs.call_count == 1
    wait_procs.reset_mock()

    # this is the stubborn code path that should not happen
    # flow: processes() -> terminate parent -> wait_procs -> processes() -> [proc]
    #   -> terminate -> wait_procs -> processes() -> [proc] -> kill -> wait_procs
    #   -> processes() -> [proc] -> raise
    proc = mocker.Mock(spec_set=Process, pid=1337)
    proc.status.return_value = "running"
    wait_procs.return_value = ([], [proc])
    proc.wait.side_effect = (TimeoutExpired(1), None)
    mocker.patch.object(
        ProcessTree, "processes", side_effect=([proc], [proc], [proc], [proc])
    )
    tree = ProcessTree(1234)
    tree.parent = proc
    with raises(TerminateError, match="Failed to terminate processes"):
        tree.terminate()
    assert tree.processes.call_count == 4  # pylint: disable=no-member
    assert tree.parent.terminate.call_count == 2
    assert tree.parent.kill.call_count == 1
    assert wait_procs.call_count == 3


def test_process_tree_04(mocker):
    """test ProcessTree.cpu_usage()"""
    mocker.patch("ffpuppet.process_tree.Process", autospec=True)
    proc = mocker.Mock(spec_set=Process, pid=1234)
    proc.cpu_percent.return_value = 2.3
    mocker.patch.object(ProcessTree, "processes", side_effect=([proc],))
    tree = ProcessTree(1234)
    stats = tuple(tree.cpu_usage())
    assert stats
    assert stats[0][0] == 1234
    assert stats[0][1] == 2.3


@mark.parametrize(
    "procs, last_mod, writing, is_running, success",
    [
        # no processes
        (False, repeat(0), False, True, True),
        # data written successfully
        (True, chain([0], repeat(2)), False, True, True),
        # data not updated
        (True, repeat(0), False, True, False),
        # data write timeout
        (True, chain([0], repeat(2)), True, True, False),
        # process exits
        (True, repeat(0), False, False, True),
    ],
)
def test_process_tree_05(mocker, procs, last_mod, writing, is_running, success):
    """test ProcessTree.dump_coverage()"""
    mocker.patch("ffpuppet.process_tree.Process", autospec=True)
    mocker.patch("ffpuppet.process_tree.COVERAGE_SIGNAL", return_value="foo")
    mocker.patch("ffpuppet.process_tree.getenv", return_value="foo")
    mocker.patch("ffpuppet.process_tree.perf_counter", side_effect=count(step=0.25))
    mocker.patch("ffpuppet.process_tree.sleep", autospec=True)
    mocker.patch("ffpuppet.process_tree._last_modified", side_effect=last_mod)
    mocker.patch("ffpuppet.process_tree._writing_coverage", return_value=writing)

    proc_list = [] if not procs else [mocker.Mock(spec_set=Process)]
    mocker.patch.object(ProcessTree, "is_running", return_value=is_running)
    mocker.patch.object(ProcessTree, "processes", return_value=proc_list)
    tree = ProcessTree(1234)
    assert tree.dump_coverage() == success


def test_process_tree_06(mocker):
    """test ProcessTree._full_system_scan()"""
    mocker.patch("ffpuppet.process_tree.Process", autospec=True)
    parent_pid = 1234

    # no matching processes
    unrelated = mocker.Mock(spec_set=Process, pid=100)
    unrelated.cmdline.return_value = ["some_app", "--flag"]
    mocker.patch("ffpuppet.process_tree.process_iter", return_value=[unrelated])
    tree = ProcessTree(parent_pid)
    tree.parent = mocker.Mock(spec_set=Process, pid=parent_pid)
    # pylint: disable=protected-access
    assert not list(tree._full_system_scan())

    # matching content process
    content = mocker.Mock(spec_set=Process, pid=200)
    content.cmdline.return_value = [
        "firefox",
        "-contentproc",
        "-parentPid",
        str(parent_pid),
    ]
    mocker.patch("ffpuppet.process_tree.process_iter", return_value=[content])
    result = list(tree._full_system_scan())
    assert len(result) == 1

    # mixed: one match, one wrong parent pid, one unrelated
    wrong_parent = mocker.Mock(spec_set=Process, pid=300)
    wrong_parent.cmdline.return_value = [
        "firefox",
        "-contentproc",
        "-parentPid",
        "9999",
    ]
    mocker.patch(
        "ffpuppet.process_tree.process_iter",
        return_value=[unrelated, content, wrong_parent],
    )
    result = list(tree._full_system_scan())
    assert len(result) == 1


@mark.parametrize(
    "cmdline, expected",
    [
        # content process with parentPid
        (["firefox", "-contentproc", "-parentPid", "1234"], 1234),
        # no -contentproc flag
        (["firefox", "--flag"], None),
        # -contentproc but no -parentPid
        (["firefox", "-contentproc"], None),
        # non-integer parentPid
        (["firefox", "-contentproc", "-parentPid", "abc"], None),
        # empty cmdline
        ([], None),
    ],
)
def test_browser_parent_pid_01(mocker, cmdline, expected):
    """test ProcessTree._browser_parent_pid()"""
    proc = mocker.Mock(spec_set=Process)
    proc.cmdline.return_value = cmdline
    assert ProcessTree._browser_parent_pid(proc) == expected


def test_browser_parent_pid_02(mocker):
    """test ProcessTree._browser_parent_pid() with AccessDenied"""
    proc = mocker.Mock(spec_set=Process)
    proc.cmdline.side_effect = AccessDenied(1)
    assert ProcessTree._browser_parent_pid(proc) is None


def test_detect_launcher_01(mocker):
    """test ProcessTree.detect_launcher()"""
    fake_process = mocker.patch("ffpuppet.process_tree.Process", autospec=True)

    # no children - launcher stays None
    tree = ProcessTree(100)
    tree.parent = mocker.Mock(spec_set=Process, pid=100)
    tree.parent.children.return_value = []
    tree.detect_launcher()
    assert tree.launcher is None
    assert tree.parent.pid == 100

    # child parentPid matches self.parent.pid - no launcher
    child = mocker.Mock(spec_set=Process, pid=200)
    child.cmdline.return_value = [
        "firefox",
        "-contentproc",
        "-parentPid",
        "100",
    ]
    tree = ProcessTree(100)
    tree.parent = mocker.Mock(spec_set=Process, pid=100)
    tree.parent.children.return_value = [child]
    # Process(100) must return something with pid=100 to match self.parent.pid
    fake_process.side_effect = lambda pid: mocker.Mock(spec_set=Process, pid=pid)
    tree.detect_launcher()
    assert tree.launcher is None
    assert tree.parent.pid == 100

    # child parentPid differs - launcher detected
    child = mocker.Mock(spec_set=Process, pid=200)
    child.cmdline.return_value = [
        "firefox",
        "-contentproc",
        "-parentPid",
        "150",
    ]
    tree = ProcessTree(100)
    original_parent = mocker.Mock(spec_set=Process, pid=100)
    tree.parent = original_parent
    tree.parent.children.return_value = [child]
    tree.detect_launcher()
    assert tree.launcher is original_parent
    assert tree.parent.pid == 150

    # already has launcher - no-op
    tree = ProcessTree(100)
    tree.parent = mocker.Mock(spec_set=Process, pid=150)
    tree.launcher = mocker.Mock(spec_set=Process, pid=100)
    tree.parent.children.return_value = []
    tree.detect_launcher()
    assert tree.launcher.pid == 100
    assert tree.parent.pid == 150


def test_processes_01(mocker):
    """test ProcessTree.processes()"""
    mocker.patch("ffpuppet.process_tree.Process", autospec=True)
    child = mocker.Mock(spec_set=Process, pid=300)

    # parent alive, no launcher
    tree = ProcessTree(100)
    tree.parent = mocker.Mock(spec_set=Process, pid=100)
    mocker.patch.object(
        ProcessTree, "_poll", side_effect=lambda p: None if p.pid in (100,) else 0
    )
    mocker.patch.object(ProcessTree, "_recursive_process_scan", return_value=[child])
    procs = tree.processes()
    assert len(procs) == 2
    assert procs[0].pid == 100
    assert procs[1].pid == 300

    # parent alive, with launcher alive
    tree = ProcessTree(100)
    tree.parent = mocker.Mock(spec_set=Process, pid=150)
    tree.launcher = mocker.Mock(spec_set=Process, pid=100)
    mocker.patch.object(
        ProcessTree, "_poll", side_effect=lambda p: None if p.pid in (100, 150) else 0
    )
    mocker.patch.object(ProcessTree, "_recursive_process_scan", return_value=[child])
    procs = tree.processes()
    assert len(procs) == 3
    assert procs[0].pid == 100
    assert procs[1].pid == 150
    assert procs[2].pid == 300

    # parent dead - falls back to _full_system_scan
    tree = ProcessTree(100)
    tree.parent = mocker.Mock(spec_set=Process, pid=100)
    mocker.patch.object(ProcessTree, "_poll", return_value=0)
    mocker.patch.object(ProcessTree, "_full_system_scan", return_value=[child])
    procs = tree.processes()
    assert len(procs) == 1
    assert procs[0].pid == 300

    # _recursive_process_scan returns None - falls back to _full_system_scan
    tree = ProcessTree(100)
    tree.parent = mocker.Mock(spec_set=Process, pid=100)
    mocker.patch.object(
        ProcessTree, "_poll", side_effect=lambda p: None if p.pid == 100 else 0
    )
    mocker.patch.object(ProcessTree, "_recursive_process_scan", return_value=None)
    mocker.patch.object(ProcessTree, "_full_system_scan", return_value=[child])
    procs = tree.processes()
    assert len(procs) == 2
    assert procs[0].pid == 100
    assert procs[1].pid == 300


def test_last_modified_01(tmp_path):
    """test _last_modified()"""
    # scan missing path
    assert _last_modified(tmp_path / "missing") is None
    # scan empty path
    assert _last_modified(tmp_path) is None
    # scan path without gcda files
    (tmp_path / "somefile.txt").touch()
    assert _last_modified(tmp_path) is None
    # scan nested path with gcda files
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "file.gcda").touch()
    assert _last_modified(tmp_path) > 0


def test_writing_coverage_01(mocker):
    """test _writing_coverage()"""
    openfile = namedtuple("openfile", ["path", "fd"])
    # empty list
    assert not _writing_coverage([])
    # no open files
    proc = mocker.Mock(spec_set=Process, pid=1337)
    proc.open_files.return_value = ()
    assert not _writing_coverage([proc])
    assert proc.open_files.call_count == 1
    # open test
    proc.reset_mock()
    proc.open_files.return_value = (openfile("file.txt", None),)
    assert not _writing_coverage([proc])
    assert proc.open_files.call_count == 1
    # open gcda
    proc.reset_mock()
    proc.open_files.return_value = (openfile("file.gcda", None),)
    assert _writing_coverage([proc])
    assert proc.open_files.call_count == 1


@mark.parametrize(
    "wait_side_effect, procs, alive_count, gone_count",
    [
        # no processes - passthrough
        ((([], []),), [], 0, 0),
        # AccessDenied - no procs
        (AccessDenied(), [], 0, 0),
        # AccessDenied - alive (is_running check)
        (
            AccessDenied(),
            [mock.Mock(spec_set=Process, is_running=mock.Mock(return_value=True))],
            1,
            0,
        ),
        # AccessDenied - gone (is_running check)
        (
            AccessDenied(),
            [mock.Mock(spec_set=Process, is_running=mock.Mock(return_value=False))],
            0,
            1,
        ),
        # AccessDenied - alive
        (
            AccessDenied(),
            [
                mock.Mock(
                    spec_set=Process, is_running=mock.Mock(side_effect=AccessDenied())
                )
            ],
            1,
            0,
        ),
        # AccessDenied - gone
        (
            AccessDenied(),
            [
                mock.Mock(
                    spec_set=Process,
                    is_running=mock.Mock(side_effect=NoSuchProcess(pid=1)),
                )
            ],
            0,
            1,
        ),
    ],
)
def test_safe_wait_procs_01(mocker, wait_side_effect, procs, alive_count, gone_count):
    """test _safe_wait_procs()"""
    mocker.patch("ffpuppet.process_tree.perf_counter", side_effect=count(step=0.25))
    mocker.patch("ffpuppet.process_tree.sleep", autospec=True)
    mocker.patch("ffpuppet.process_tree.wait_procs", side_effect=wait_side_effect)

    result = _safe_wait_procs(procs, timeout=1)
    assert len(result[0]) == gone_count
    assert len(result[1]) == alive_count


def test_filter_zombies_01(mocker):
    """test _filter_zombies()"""
    zombie = mocker.Mock(spec_set=Process, pid=123)
    zombie.status.return_value = STATUS_ZOMBIE
    procs = tuple(_filter_zombies([zombie, mocker.Mock(spec_set=Process)]))
    assert len(procs) == 1
    assert not any(x for x in procs if x.status() == STATUS_ZOMBIE)
