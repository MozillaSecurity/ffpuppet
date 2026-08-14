# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet crash report module"""

from __future__ import annotations

from logging import getLogger
from typing import TYPE_CHECKING

from .process_tree import UNKNOWN_PROCESS_TYPE

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from pathlib import Path

LOG = getLogger(__name__)


def _report_pid(report: Path) -> int | None:
    """Lookup the pid of the process that created a crash report. Sanitizer and
    Valgrind logs are named with the pid as the last part of the file name.

    Args:
        report: Crash report to check.

    Returns:
        Pid of the process that created the report or None if it is unavailable.
    """
    pid = report.name.rsplit(".", 1)[-1]
    return int(pid) if pid.isdigit() else None


def attribute_reports(
    reports: Iterable[Path], proc_types: Mapping[int, str]
) -> list[tuple[int, str]]:
    """Attribute crash reports to the processes that created them.

    Args:
        reports: Crash reports (sanitizer logs, Valgrind logs and minidump logs).
        proc_types: Process type by pid. See ProcessTree.process_types().

    Returns:
        Pid and process type of each process that crashed.
    """
    crashed: dict[int, str] = {}
    for report in reports:
        pid = _report_pid(report)
        if pid is None:
            LOG.debug("cannot lookup pid of crash report '%s'", report.name)
            continue
        crashed[pid] = proc_types.get(pid, UNKNOWN_PROCESS_TYPE)
    return list(crashed.items())
