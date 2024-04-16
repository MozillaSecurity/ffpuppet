# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""process_tree.py tests"""

from pathlib import Path
from subprocess import Popen
from time import sleep

from psutil import NoSuchProcess, Process, TimeoutExpired
from pytest import mark, raises

from .exceptions import TerminateError
from .process_tree import ProcessTree

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
    tree = None
    try:
        # wait (30 seconds) for tree to launch all processes
        for _ in range(300):
            if flag.exists():
                break
            assert proc.poll() is None
            sleep(0.1)
        else:
            raise AssertionError(f"Process tree ({expected_procs}) failed to launch")

        tree = ProcessTree(proc)
        # pylint: disable=protected-access
        tree._launcher_check = enable_launcher
        assert tree.parent
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
    tree = ProcessTree(mocker.Mock())
    tree.parent = mocker.Mock(spec_set=Process)
    tree.terminate()
    # pylint: disable=no-member
    assert tree.processes.call_count == 1
    assert tree.parent.wait.call_count == 0
    assert tree.parent.terminate.call_count == 0

    # this should be the "normal" code path
    proc = mocker.Mock(spec_set=Process, pid=1337)
    wait_procs.return_value = ([proc], [])
    proc.wait.side_effect = (TimeoutExpired(1), None)
    mocker.patch.object(ProcessTree, "processes", side_effect=([proc],))
    tree = ProcessTree(mocker.Mock())
    tree.parent = proc
    tree.terminate()
    # pylint: disable=no-member
    assert tree.processes.call_count == 1
    assert tree.parent.wait.call_count == 2
    assert tree.parent.terminate.call_count == 1
    assert wait_procs.call_count == 1
    wait_procs.reset_mock()

    # this is the stubborn code path that should not happen
    proc = mocker.Mock(spec_set=Process, pid=1337)
    wait_procs.return_value = ([], [proc])
    proc.wait.side_effect = (TimeoutExpired(1), None)
    mocker.patch.object(ProcessTree, "processes", side_effect=([proc],))
    tree = ProcessTree(mocker.Mock())
    tree.parent = proc
    with raises(TerminateError, match="Failed to terminate processes"):
        tree.terminate()
    # pylint: disable=no-member
    assert tree.processes.call_count == 1
    assert tree.parent.wait.call_count == 2
    assert tree.parent.terminate.call_count == 2
    assert tree.parent.kill.call_count == 1
    assert wait_procs.call_count == 3


def test_process_tree_04(mocker):
    """test ProcessTree.cpu_usage()"""
    mocker.patch("ffpuppet.process_tree.Process", autospec=True)
    proc = mocker.Mock(spec_set=Process, pid=1234)
    proc.cpu_percent.return_value = 2.3
    mocker.patch.object(ProcessTree, "processes", side_effect=([proc],))
    tree = ProcessTree(mocker.Mock())
    stats = tuple(tree.cpu_usage())
    assert stats
    assert stats[0][0] == 1234
    assert stats[0][1] == 2.3
