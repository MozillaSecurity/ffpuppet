# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""Windows utility to map all open files on the system to process"""
import ctypes
import ctypes.wintypes
from pathlib import Path
from typing import Dict, Optional, Set

DUPLICATE_SAME_ACCESS = 2
FILE_TYPE_DISK = 1
FILE_TYPE_UNKNOWN = 0
MAX_PATH = 260
NO_ERROR = 0
PROCESS_DUP_HANDLE = 0x40
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
SYSTEM_EXTENDED_HANDLE_INFORMATION_CLASS = 0x40
SYSTEM_HANDLE_INFORMATION_CLASS = 0x10

__all__ = ("pids_by_file",)
__author__ = "Jesse Schwartzentruber"


def nt_status(status: int) -> int:
    """Cast a signed integer to 32-bit unsigned.

    Args:
        status: an NTSTATUS result

    Returns:
        status cast to uint32
    """
    return status & 0xFFFFFFFF


def create_winerror(function: str) -> OSError:  # pragma: no cover
    """Create a WinError exception.

    Args:
        function: Windows API function name that generated the error.

    Returns:
        OSError representing a windows error from fall to a given function.
    """
    errno = ctypes.GetLastError()  # type: ignore[attr-defined]
    desc = f"{ctypes.FormatError()} ({function})"  # type: ignore[attr-defined]
    return OSError(errno, desc, None, errno)


class SystemHandleTableEntryInfoEx(ctypes.Structure):
    """NT API Handle table entry structure"""

    _fields_ = [
        ("Object", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.wintypes.HANDLE),
        ("HandleValue", ctypes.wintypes.HANDLE),
        ("GrantedAccess", ctypes.c_ulong),
        ("CreatorBackTraceIndex", ctypes.c_ushort),
        ("ObjectTypeIndex", ctypes.c_ushort),
        ("HandleAttributes", ctypes.c_ulong),
        ("Reserved", ctypes.c_ulong),
    ]


def nt_query_system_handle_information_ex() -> ctypes.Structure:
    """List all open handles in the system.

    Args:
        None

    Returns:
        A ctypes Structure with fields:
            NumberOfHandles (int)
            Handles (list[SystemHandleTableEntryInfoEx])
    """
    buf_size = 64 * 1024
    buf = ctypes.create_string_buffer(buf_size)
    ntdll = ctypes.windll.ntdll  # type: ignore[attr-defined]
    while True:
        status = ntdll.NtQuerySystemInformation(
            SYSTEM_EXTENDED_HANDLE_INFORMATION_CLASS,
            buf,
            buf_size,
            None,
        )
        if nt_status(status) != STATUS_INFO_LENGTH_MISMATCH:
            break
        buf_size *= 2
        buf = ctypes.create_string_buffer(buf_size)
    assert status >= 0, f"NtQuerySystemInformation returned 0x{nt_status(status):08X}"
    num_handles = ctypes.c_void_p.from_buffer(buf).value

    class SystemHandleInformationEx(ctypes.Structure):
        """NT API Handle table structure"""

        _fields_ = [
            ("NumberOfHandles", ctypes.c_void_p),
            ("Reserved", ctypes.c_void_p),
            ("Handles", SystemHandleTableEntryInfoEx * (num_handles or 0)),
        ]

    return SystemHandleInformationEx.from_buffer(buf)


def pid_handle_to_filename(
    pid: int, hnd: int, raise_for_error: bool = False
) -> Optional[Path]:
    """Resolve a PID/Handle pair to a filesystem Path.

    Args:
        pid: The Process ID the Handle belongs to
        hnd: The Handle belonging to the Process
        raise_for_error: if True, raise OSError when any error occurs

    Returns:
        Path the handle represents
        or None if error occurred and `raise_for_error` is False
    """
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    buf_size = MAX_PATH * 2 + 1
    buf = ctypes.create_string_buffer(buf_size)
    process_handle = kernel32.OpenProcess(PROCESS_DUP_HANDLE, False, pid)
    close_hnd = False
    try:
        if process_handle:
            handle_out = ctypes.wintypes.HANDLE()
            if kernel32.DuplicateHandle(
                process_handle,
                hnd,
                ctypes.wintypes.HANDLE(kernel32.GetCurrentProcess()),
                ctypes.byref(handle_out),
                0,
                False,
                DUPLICATE_SAME_ACCESS,
            ):
                assert handle_out.value is not None
                hnd = int(handle_out.value)
                close_hnd = True
            else:
                if not raise_for_error:
                    kernel32.SetLastError(0)
                    return None
                raise create_winerror("DuplicateHandle")  # pragma: no cover
        else:
            if not raise_for_error:
                kernel32.SetLastError(0)
                return None
            raise create_winerror("OpenProcess")  # pragma: no cover
        ftype = kernel32.GetFileType(hnd)
        if ftype == FILE_TYPE_UNKNOWN:
            code = ctypes.GetLastError()  # type: ignore[attr-defined]
            if code != NO_ERROR:
                if not raise_for_error:
                    kernel32.SetLastError(0)
                    return None
                raise create_winerror("GetFileType")  # pragma: no cover
        if ftype != FILE_TYPE_DISK:
            if not raise_for_error:
                return None
            raise OSError("Given handle is not a file")  # pragma: no cover
        status = kernel32.GetFinalPathNameByHandleW(hnd, buf, buf_size, 0)
    finally:
        if process_handle:
            kernel32.CloseHandle(process_handle)
        if close_hnd:
            kernel32.CloseHandle(hnd)
    if not status:
        if not raise_for_error:
            kernel32.SetLastError(0)
            return None
        raise create_winerror("GetFinalPathnameByHandle")  # pragma: no cover
    return Path(ctypes.wstring_at(buf)[4:])  # always prefixed with \\?\


def pids_by_file() -> Dict[Path, Set[int]]:
    """Create a mapping of open paths to the Processes that own the open file handles.

    Args:
        None

    Returns:
        dict mapping Path (the path of the open file) to a set of PIDs which have
        that path open.
    """
    result: Dict[Path, Set[int]] = {}
    for hnd in nt_query_system_handle_information_ex().Handles:
        fname = pid_handle_to_filename(hnd.UniqueProcessId, hnd.HandleValue)
        if fname is not None:
            proc_pids = result.setdefault(fname, set())
            proc_pids.add(hnd.UniqueProcessId)
    return result


if __name__ == "__main__":  # pragma: no cover
    import sys

    def main() -> None:
        """test main"""
        printed = False
        for path, pids in sorted(pids_by_file().items()):
            print(f"{path}")
            for pid in sorted(pids):
                print(f"\t{pid}")
            printed = True
        if not printed:
            print("no open files?", file=sys.stderr)
            sys.exit(1)

    main()
