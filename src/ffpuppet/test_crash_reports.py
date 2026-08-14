# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=protected-access
"""crash_reports.py tests"""

from pathlib import Path

from pytest import mark

from .crash_reports import _report_pid, attribute_reports


@mark.parametrize(
    "name, expected",
    [
        # sanitizer log
        ("ffp_asan_9001.log.1042", 1042),
        # valgrind log
        ("valgrind.9001.1042", 1042),
        # sanitizer log without a pid
        ("ffp_asan_9001.log", None),
        # minidump log
        ("minidump_00.1042", 1042),
        # minidump log without a pid
        ("minidump_00", None),
        # minidump
        ("8f2c1eb1-4d1e-4f4a-9a1e-2f0f1d1c1b1a.dmp", None),
        # no suffix
        ("logfile", None),
    ],
)
def test_report_pid_01(name, expected):
    """test _report_pid()"""
    assert _report_pid(Path(name)) == expected


def test_attribute_reports_01():
    """test attribute_reports() with no reports"""
    assert not attribute_reports((), {1042: "tab"})


def test_attribute_reports_02():
    """test attribute_reports() with a known process type"""
    reports = (Path("ffp_asan_9001.log.1042"), Path("valgrind.9001.1044"))
    assert attribute_reports(reports, {1042: "tab", 1044: "gpu"}) == [
        (1042, "tab"),
        (1044, "gpu"),
    ]


def test_attribute_reports_03():
    """test attribute_reports() with an unknown process type"""
    assert attribute_reports((Path("ffp_asan_9001.log.1042"),), {}) == [
        (1042, "unknown")
    ]


def test_attribute_reports_04():
    """test attribute_reports() with a minidump log"""
    # pid is not available
    assert not attribute_reports((Path("minidump_00"),), {1042: "tab"})
    # pid included in the log name by the minidump parser
    assert attribute_reports((Path("minidump_00.1042"),), {1042: "tab"}) == [
        (1042, "tab")
    ]


def test_attribute_reports_05():
    """test attribute_reports() with multiple reports from the same process"""
    reports = (Path("ffp_asan_9001.log.1042"), Path("minidump_00.1042"))
    assert attribute_reports(reports, {1042: "tab"}) == [(1042, "tab")]
