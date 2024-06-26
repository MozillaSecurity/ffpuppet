# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet job object tests"""

from platform import system
from subprocess import PIPE, Popen
from sys import executable
from time import sleep

from pytest import skip

if system() == "Windows":
    from .core import CREATE_SUSPENDED
    from .job_object import config_job_object, resume_suspended_process
else:
    skip("skipping windows-only tests", allow_module_level=True)


def test_job_object_01():
    """test config_job_object() set limit higher than usage"""
    with Popen([executable, "-c", "input()"], stdin=PIPE, stderr=PIPE) as proc:
        # pylint: disable=no-member,protected-access,possibly-used-before-assignment
        config_job_object(proc._handle, 1024 * 1024 * 1024)
        proc.communicate(input=b"a", timeout=10)
        assert proc.wait(10) == 0


def test_job_object_02():
    """test config_job_object() enforce limit"""
    with Popen(
        [executable, "-c", "input(); a = ['A' * 1024 * 1024 for _ in range(50)]"],
        stdin=PIPE,
        stderr=PIPE,
    ) as proc:
        # pylint: disable=no-member,protected-access,possibly-used-before-assignment
        config_job_object(proc._handle, 32 * 1024 * 1024)
        _, err = proc.communicate(input=b"a", timeout=10)
        assert proc.wait(10) == 1
        assert b"MemoryError" in err


def test_thread_resume():
    """test that suspended process is created in job"""
    # the test function creates a subprocess to show that the parent process
    # is suspended on launch. if creationflags=CREATE_SUSPENDED is omitted,
    # the test should fail (no MemoryError)
    with Popen(
        [
            executable,
            "-c",
            "from subprocess import run; import sys;"
            "run([sys.executable, '-c', "
            "\"input(); a = ['A' * 1024 * 1024 for _ in range(50)]\"], check=True)",
        ],
        # pylint: disable=possibly-used-before-assignment
        creationflags=CREATE_SUSPENDED,
        stdin=PIPE,
        stderr=PIPE,
    ) as proc:
        sleep(0.1)
        # pylint: disable=no-member,protected-access,possibly-used-before-assignment
        config_job_object(proc._handle, 32 * 1024 * 1024)
        resume_suspended_process(proc.pid)
        _, err = proc.communicate(input=b"a", timeout=10)
        assert proc.wait(10) == 1
        assert b"MemoryError" in err
