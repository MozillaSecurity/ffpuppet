# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""process_tree.py tests"""

from collections import namedtuple
from itertools import chain, count, repeat
from pathlib import Path
from subprocess import Popen
from time import perf_counter, sleep
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


def _wait_for(condition, msg, timeout=30.0):
    """wait for a condition to become true or raise AssertionError"""
    deadline = perf_counter() + timeout
    while perf_counter() < deadline:
        if condition():
            return
        sleep(0.1)
    raise AssertionError(msg)


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
        # the scanner thread should find the processes without any help
        _wait_for(
            lambda: len(tree._procs) == expected_procs,
            f"scanner did not find {expected_procs} process(es)",
        )
        procs = tree.processes()
        assert len(procs) == expected_procs
        # only the content processes have a detectable process type
        assert sum(ProcessTree._lookup_proc_type(x) == "tab" for x in procs) == (
            content_procs
        )
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
    # the type of each process that was running should still be available
    types = tree.process_types()
    assert len(types) == expected_procs
    assert sum(x == "tab" for x in types.values()) == content_procs
    assert types[tree.parent.pid] == "parent"
    if tree.launcher is not None:
        assert types[tree.launcher.pid] == "launcher"


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
    tree = ProcessTree(1234, scan_interval=0)
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
    tree = ProcessTree(1234, scan_interval=0)
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
    tree = ProcessTree(1234, scan_interval=0)
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
    tree = ProcessTree(1234, scan_interval=0)
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
    tree = ProcessTree(1234, scan_interval=0)
    assert tree.dump_coverage() == success


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


@mark.parametrize(
    "cmdline, expected",
    [
        # content (tab) process
        (["firefox", "-contentproc", "-parentPid", "1234", "4321", "tab"], "tab"),
        # gpu process
        (["firefox", "-contentproc", "-parentPid", "1234", "4321", "gpu"], "gpu"),
        # utility process
        (["firefox", "-contentproc", "-sandboxingKind", "1", "utility"], "utility"),
        # fork server process
        (["firefox", "-contentproc", "forkserver"], "forkserver"),
        # unknown process type
        (["firefox", "-contentproc", "-parentPid", "1234", "new-type"], "unknown"),
        # process type is not the last argument
        (["firefox", "-contentproc", "tab", "-parentPid", "1234"], "unknown"),
        # process type without -contentproc flag
        (["firefox", "tab"], "unknown"),
        # parent process
        (["firefox", "-no-remote"], "unknown"),
        # empty cmdline
        ([], "unknown"),
    ],
)
def test_lookup_proc_type_01(mocker, cmdline, expected):
    """test ProcessTree._lookup_proc_type()"""
    proc = mocker.Mock(spec_set=Process)
    proc.cmdline.return_value = cmdline
    assert ProcessTree._lookup_proc_type(proc) == expected


@mark.parametrize("side_effect", [AccessDenied(1), NoSuchProcess(1)])
def test_lookup_proc_type_02(mocker, side_effect):
    """test ProcessTree._lookup_proc_type() with inaccessible process"""
    proc = mocker.Mock(spec_set=Process)
    proc.cmdline.side_effect = side_effect
    assert ProcessTree._lookup_proc_type(proc) == "unknown"


def test_detect_launcher_01(mocker):
    """test ProcessTree.detect_launcher()"""
    fake_process = mocker.patch("ffpuppet.process_tree.Process", autospec=True)

    # no children - launcher stays None
    tree = ProcessTree(100, scan_interval=0)
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
    tree = ProcessTree(100, scan_interval=0)
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
    tree = ProcessTree(100, scan_interval=0)
    original_parent = mocker.Mock(spec_set=Process, pid=100)
    tree.parent = original_parent
    tree.parent.children.return_value = [child]
    tree.detect_launcher()
    assert tree.launcher is original_parent
    assert tree.parent.pid == 150

    # already has launcher - no-op
    tree = ProcessTree(100, scan_interval=0)
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
    child.cmdline.return_value = ["firefox", "-contentproc", "-parentPid", "100", "tab"]

    # parent alive, no launcher
    tree = ProcessTree(100, scan_interval=0)
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
    tree = ProcessTree(100, scan_interval=0)
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

    # parent dead - lingering processes are found with a full system scan
    tree = ProcessTree(100, scan_interval=0)
    tree.parent = mocker.Mock(spec_set=Process, pid=100)
    mocker.patch.object(ProcessTree, "_poll", return_value=0)
    mocker.patch.object(ProcessTree, "_full_system_scan", return_value=[child])
    procs = tree.processes()
    assert len(procs) == 1
    assert procs[0].pid == 300

    # _recursive_process_scan finds nothing - only the parent is found
    tree = ProcessTree(100, scan_interval=0)
    tree.parent = mocker.Mock(spec_set=Process, pid=100)
    mocker.patch.object(
        ProcessTree, "_poll", side_effect=lambda p: None if p.pid == 100 else 0
    )
    mocker.patch.object(ProcessTree, "_recursive_process_scan", return_value=[])
    procs = tree.processes()
    assert len(procs) == 1
    assert procs[0].pid == 100


def test_processes_02(mocker):
    """test ProcessTree.processes() with a recycled pid"""
    mocker.patch("ffpuppet.process_tree.Process", autospec=True)
    mocker.patch.object(
        ProcessTree, "_poll", side_effect=lambda p: None if p.pid == 100 else 0
    )
    tree = ProcessTree(100, scan_interval=0)
    tree.parent = mocker.Mock(spec_set=Process, pid=100)

    # scan with a content process
    original = mocker.Mock(spec_set=Process, pid=300)
    original.cmdline.return_value = ["firefox", "-contentproc", "-childID", "1", "tab"]
    mocker.patch.object(ProcessTree, "_recursive_process_scan", return_value=[original])
    assert original in tree.processes()
    assert tree._types[300] == "tab"

    # original process exits and the pid is reused by a new process
    original.is_running.return_value = False
    recycled = mocker.Mock(spec_set=Process, pid=300)
    recycled.cmdline.return_value = ["firefox", "-contentproc", "-childID", "2", "gpu"]
    mocker.patch.object(ProcessTree, "_recursive_process_scan", return_value=[recycled])
    procs = tree.processes()
    assert original not in procs
    assert recycled in procs
    assert tree._types[300] == "gpu"


def test_processes_03(mocker):
    """test ProcessTree.processes() removing processes that are no longer running"""
    mocker.patch("ffpuppet.process_tree.Process", autospec=True)
    mocker.patch.object(
        ProcessTree, "_poll", side_effect=lambda p: None if p.pid == 100 else 0
    )
    scan = mocker.patch.object(ProcessTree, "_recursive_process_scan")

    def _tree_with_content_proc():
        """create a tree with a cached content process that the next scan won't find"""
        tree = ProcessTree(100, scan_interval=0)
        tree.parent = mocker.Mock(spec_set=Process, pid=100)
        proc = mocker.Mock(spec_set=Process, pid=300)
        proc.cmdline.return_value = ["firefox", "-contentproc", "-childID", "1", "tab"]
        scan.return_value = [proc]
        assert proc in tree.processes()
        assert tree._types[300] == "tab"
        scan.return_value = []
        return tree, proc

    # process exits
    tree, content = _tree_with_content_proc()
    content.is_running.return_value = False
    assert tree.processes() == [tree.parent]
    assert 300 not in tree._procs
    # the process type is kept
    assert tree._types[300] == "tab"

    # process is gone
    tree, content = _tree_with_content_proc()
    content.is_running.side_effect = NoSuchProcess(300)
    assert tree.processes() == [tree.parent]
    assert 300 not in tree._procs
    assert tree._types[300] == "tab"

    # process cannot be checked, it must be kept
    tree, content = _tree_with_content_proc()
    content.is_running.side_effect = AccessDenied(300)
    assert tree.processes() == [tree.parent]
    assert 300 in tree._procs
    assert tree._types[300] == "tab"


def test_processes_04(mocker):
    """test ProcessTree.processes() looking up an unknown process type again"""
    mocker.patch("ffpuppet.process_tree.Process", autospec=True)
    mocker.patch.object(
        ProcessTree, "_poll", side_effect=lambda p: None if p.pid == 100 else 0
    )
    tree = ProcessTree(100, scan_interval=0)
    tree.parent = mocker.Mock(spec_set=Process, pid=100)

    # the command line is not available yet
    content = mocker.Mock(spec_set=Process, pid=300)
    content.cmdline.side_effect = AccessDenied(300)
    mocker.patch.object(ProcessTree, "_recursive_process_scan", return_value=[content])
    assert content in tree.processes()
    assert tree._types[300] == "unknown"

    # the command line is available on the next scan
    content.cmdline.side_effect = None
    content.cmdline.return_value = ["firefox", "-contentproc", "-childID", "1", "tab"]
    assert content in tree.processes()
    assert tree._types[300] == "tab"


def test_process_types_01(mocker):
    """test ProcessTree.process_types()"""
    mocker.patch("ffpuppet.process_tree.Process", autospec=True)
    tree = ProcessTree(100, scan_interval=0)
    tree._types = {100: "parent", 200: "gpu", 300: "tab"}
    types = tree.process_types()
    assert types == {100: "parent", 200: "gpu", 300: "tab"}
    # the mapping must be a copy
    types.clear()
    assert tree._types


def test_full_system_scan_01(mocker):
    """test ProcessTree._full_system_scan()"""
    mocker.patch("ffpuppet.process_tree.Process", autospec=True)
    parent_pid = 1234

    # no matching processes
    unrelated = mocker.Mock(spec_set=Process, pid=100)
    unrelated.cmdline.return_value = ["some_app", "--flag"]
    mocker.patch("ffpuppet.process_tree.process_iter", return_value=[unrelated])
    tree = ProcessTree(parent_pid, scan_interval=0)
    tree.parent = mocker.Mock(spec_set=Process, pid=parent_pid)
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
    assert len(list(tree._full_system_scan())) == 1

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
    assert len(list(tree._full_system_scan())) == 1


def test_recursive_process_scan_01(mocker):
    """test ProcessTree._recursive_process_scan() with an inaccessible parent"""
    mocker.patch("ffpuppet.process_tree.Process", autospec=True)
    tree = ProcessTree(100, scan_interval=0)
    tree.parent = mocker.Mock(spec_set=Process, pid=100)
    tree.parent.children.side_effect = AccessDenied(100)
    assert not tree._recursive_process_scan()


def test_scanner_01(mocker):
    """test ProcessTree scanner thread updating the cache"""
    fake_process = mocker.patch("ffpuppet.process_tree.Process", autospec=True)
    fake_process.side_effect = lambda pid: mocker.Mock(spec_set=Process, pid=pid)
    mocker.patch.object(
        ProcessTree, "_poll", side_effect=lambda p: None if p.pid == 100 else 0
    )
    content = mocker.Mock(spec_set=Process, pid=300)
    content.cmdline.return_value = ["firefox", "-contentproc", "-childID", "1", "tab"]
    mocker.patch.object(ProcessTree, "_recursive_process_scan", return_value=[content])
    tree = ProcessTree(100, scan_interval=0.01)
    try:
        # the cache is updated without calling processes()
        _wait_for(lambda: 300 in tree._procs, "scanner did not update the cache")
        assert tree._types[300] == "tab"
    finally:
        tree.stop_scanner()
    assert tree._scan_thread is None
    # calling this again should do nothing
    tree.stop_scanner()


def test_scanner_02(mocker):
    """test ProcessTree scanner thread stopping when the parent is not running"""
    mocker.patch("ffpuppet.process_tree.Process", autospec=True)
    mocker.patch.object(ProcessTree, "_poll", return_value=0)
    tree = ProcessTree(100, scan_interval=0.01)
    try:
        _wait_for(lambda: not tree._scan_thread.is_alive(), "scanner did not stop")
        assert not tree._procs
    finally:
        tree.stop_scanner()


def test_scanner_03(mocker):
    """test ProcessTree with the scanner thread disabled"""
    mocker.patch("ffpuppet.process_tree.Process", autospec=True)
    tree = ProcessTree(100, scan_interval=0)
    assert tree._scan_thread is None
    tree.stop_scanner()


def test_scanner_04(mocker):
    """test ProcessTree scanner thread with a failing scan"""
    fake_process = mocker.patch("ffpuppet.process_tree.Process", autospec=True)
    fake_process.side_effect = lambda pid: mocker.Mock(spec_set=Process, pid=pid)
    mocker.patch.object(
        ProcessTree, "_poll", side_effect=lambda p: None if p.pid == 100 else 0
    )
    mocker.patch.object(ProcessTree, "_scan", side_effect=RuntimeError("boom"))
    tree = ProcessTree(100, scan_interval=0.01)
    try:
        # the thread should exit instead of failing silently
        _wait_for(lambda: not tree._scan_thread.is_alive(), "scanner did not stop")
    finally:
        tree.stop_scanner()


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
