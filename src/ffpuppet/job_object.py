# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Windows Job Object management"""

import ctypes
import ctypes.wintypes
import sys
from logging import getLogger
from subprocess import Handle  # type: ignore[attr-defined]

from psutil import Process

assert sys.platform == "win32"

JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x200
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x100

THREAD_SUSPEND_RESUME = 0x0002

__author__ = "Jesse Schwartzentruber"

LOG = getLogger(__name__)


class IOCounters(ctypes.Structure):
    """IOCounters"""

    _fields_ = (
        ("read_operation_count", ctypes.c_ulonglong),
        ("write_operation_count", ctypes.c_ulonglong),
        ("other_operation_count", ctypes.c_ulonglong),
        ("read_transfer_count", ctypes.c_ulonglong),
        ("write_transfer_count", ctypes.c_ulonglong),
        ("other_transfer_count", ctypes.c_ulonglong),
    )


class JobObjectBasicLimitInformation(ctypes.Structure):
    """JobObjectBasicLimitInformation"""

    _fields_ = (
        ("per_process_user_time_limit", ctypes.wintypes.LARGE_INTEGER),
        ("per_job_user_time_limit", ctypes.wintypes.LARGE_INTEGER),
        ("limit_flags", ctypes.wintypes.DWORD),
        ("minimum_working_set_size", ctypes.c_size_t),
        ("maximum_working_set_size", ctypes.c_size_t),
        ("active_process_limit", ctypes.wintypes.DWORD),
        ("affinity", ctypes.wintypes.PULONG),
        ("priority_class", ctypes.wintypes.DWORD),
        ("scheduling_class", ctypes.wintypes.DWORD),
    )


class JobObjectExtendedLimitInformation(ctypes.Structure):
    """JobObjectExtendedLimitInformation"""

    _fields_ = (
        ("basic_limit_information", JobObjectBasicLimitInformation),
        ("io_info", IOCounters),
        ("process_memory_limit", ctypes.c_size_t),
        ("job_memory_limit", ctypes.c_size_t),
        ("peak_process_memory_used", ctypes.c_size_t),
        ("peak_job_memory_used", ctypes.c_size_t),
    )


def config_job_object(handle: Handle, limit: int) -> None:
    """Configure Windows Job object.

    Args:
        handle: Process handle to assigned to the job object.
        limit: Total memory limit for the job.

    Returns:
        None
    """
    assert limit > 0
    kernel32 = ctypes.windll.kernel32
    job = Handle(kernel32.CreateJobObjectA(None, None))
    try:
        assert kernel32.AssignProcessToJobObject(job, handle)
        info = JobObjectExtendedLimitInformation()
        info.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_JOB_MEMORY
        # pylint: disable=attribute-defined-outside-init
        info.job_memory_limit = limit
        assert kernel32.SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
    finally:
        job.Close()


def resume_suspended_process(pid: int) -> None:
    """Resume a possibly suspended Windows Process.

    Args:
        pid: Process ID.

    Returns:
        None
    """
    kernel32 = ctypes.windll.kernel32
    for tinfo in Process(pid).threads():
        thnd = Handle(kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, tinfo.id))
        try:
            result = kernel32.ResumeThread(thnd)
            LOG.debug("resuming thread %d returned %d", tinfo.id, result)
            assert result >= 0, f"ResumeThread for tid={tinfo.id} returned {result}"
        finally:
            thnd.Close()
