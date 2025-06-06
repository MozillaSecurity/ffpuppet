# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet helpers tests"""

from os import getpid
from pathlib import Path
from subprocess import CalledProcessError

from pytest import mark, raises

from .helpers import (
    CERTUTIL,
    LLVM_SYMBOLIZER,
    _configure_sanitizers,
    certutil_available,
    certutil_find,
    files_in_use,
    prepare_environment,
    wait_on_files,
    warn_open,
)
from .sanitizer_util import SanitizerOptions


def test_helpers_01(tmp_path):
    """test _configure_sanitizers()"""
    # test with empty environment
    env = _configure_sanitizers({}, tmp_path, "blah")
    assert "ASAN_OPTIONS" in env
    opts = SanitizerOptions(env["ASAN_OPTIONS"])
    assert opts.get("external_symbolizer_path") is None
    assert opts.get("detect_leaks") == "false"
    assert opts.get("log_path") == "'blah'"
    assert "LSAN_OPTIONS" in env
    assert "UBSAN_OPTIONS" in env
    # test with presets environment
    env = _configure_sanitizers(
        {
            "ASAN_OPTIONS": "detect_leaks=true",
            "LSAN_OPTIONS": "a=1",
            "UBSAN_OPTIONS": "",
        },
        tmp_path,
        "blah",
    )
    assert "ASAN_OPTIONS" in env
    opts = SanitizerOptions(env["ASAN_OPTIONS"])
    assert opts.get("detect_leaks") == "true"
    assert "LSAN_OPTIONS" in env
    assert "UBSAN_OPTIONS" in env
    opts = SanitizerOptions(env["UBSAN_OPTIONS"])
    assert opts.get("print_stacktrace") is not None
    # test suppression file
    sup = tmp_path / "test.sup"
    sup.touch()
    env = _configure_sanitizers(
        {"ASAN_OPTIONS": f"suppressions='{sup}'"}, tmp_path, "blah"
    )
    opts = SanitizerOptions(env["ASAN_OPTIONS"])
    assert opts.get("suppressions") is not None
    # test overwrite log_path
    env = _configure_sanitizers(
        {
            "ASAN_OPTIONS": "log_path='overwrite'",
            "TSAN_OPTIONS": "log_path='overwrite'",
            "UBSAN_OPTIONS": "log_path='overwrite'",
        },
        tmp_path,
        "blah",
    )
    assert "ASAN_OPTIONS" in env
    opts = SanitizerOptions(env["ASAN_OPTIONS"])
    assert opts.get("log_path") == "'blah'"
    assert "UBSAN_OPTIONS" in env
    opts = SanitizerOptions(env["UBSAN_OPTIONS"])
    assert opts.get("log_path") == "'blah'"
    # test missing suppression file
    with raises(AssertionError, match="missing suppressions file"):
        _configure_sanitizers(
            {"ASAN_OPTIONS": "suppressions=not_a_file"}, tmp_path, "blah"
        )
    # unquoted path containing ':'
    with raises(ValueError, match=r"\(strip_path_prefix\) must be quoted"):
        _configure_sanitizers(
            {"ASAN_OPTIONS": "strip_path_prefix=x:\\foo\\bar"}, tmp_path, "blah"
        )
    # multiple options
    options = (
        "opt1=1",
        "opt2=",
        "opt3=test",
        "opt4='x:\\foo'",
        'opt5="z:/bar"',
        "opt6=''",
        "opt7='/with space/'",
        "opt8='x:\\with a space\\or two'",
    )
    env = _configure_sanitizers({"ASAN_OPTIONS": ":".join(options)}, tmp_path, "blah")
    opts = SanitizerOptions(env["ASAN_OPTIONS"])
    for key, value in (x.split(sep="=", maxsplit=1) for x in options):
        assert opts.get(key) == value
    # test using packaged llvm-symbolizer
    llvm_sym_packed = tmp_path / LLVM_SYMBOLIZER
    llvm_sym_packed.touch()
    env = _configure_sanitizers({"ASAN_OPTIONS": ":".join(options)}, tmp_path, "blah")
    opts = SanitizerOptions(env["ASAN_OPTIONS"])
    assert opts.get("external_symbolizer_path").strip("'") == str(llvm_sym_packed)
    # test malformed option pair
    env = _configure_sanitizers({"ASAN_OPTIONS": "a=b=c:malformed"}, tmp_path, "blah")
    opts = SanitizerOptions(env["ASAN_OPTIONS"])
    assert opts.get("a") == "b=c"
    assert "malformed" not in str(opts)
    # test ASAN_SYMBOLIZER_PATH
    (tmp_path / "a").mkdir()
    llvm_sym_a = tmp_path / "a" / "llvm-symbolizer"
    llvm_sym_a.touch()
    env = {"ASAN_SYMBOLIZER_PATH": str(llvm_sym_a)}
    env = _configure_sanitizers(env, tmp_path, "blah")
    opts = SanitizerOptions(env["ASAN_OPTIONS"])
    assert opts.get("external_symbolizer_path").strip("'") == str(llvm_sym_a)
    # test ASAN_SYMBOLIZER_PATH override by ASAN_OPTIONS=external_symbolizer_path
    (tmp_path / "b").mkdir()
    llvm_sym_b = tmp_path / "b" / "llvm-symbolizer"
    llvm_sym_b.touch()
    env = {
        "ASAN_SYMBOLIZER_PATH": str(llvm_sym_a),
        "ASAN_OPTIONS": f"external_symbolizer_path='{llvm_sym_b}'",
    }
    env = _configure_sanitizers(env, tmp_path, "blah")
    opts = SanitizerOptions(env["ASAN_OPTIONS"])
    assert opts.get("external_symbolizer_path").strip("'") == str(llvm_sym_b)


def test_helpers_02(tmp_path):
    """test prepare_environment()"""
    env = prepare_environment(tmp_path, "blah")
    assert "ASAN_OPTIONS" in env
    assert "LSAN_OPTIONS" in env
    assert "UBSAN_OPTIONS" in env
    assert "RUST_BACKTRACE" in env
    assert "MOZ_CRASHREPORTER" in env


def test_helpers_03(mocker, tmp_path):
    """test prepare_environment() using some predefined environment variables"""
    mocker.patch.dict(
        "ffpuppet.helpers.environ",
        {
            "MOZ_SKIA_DISABLE_ASSERTS": "0",
            "TEST_EXISTING_OVERWRITE": "0",
            "TEST_EXISTING_REMOVE": "1",
            "TEST_SECRET_TO_REMOVE": "1",
        },
    )
    pre = {
        "LSAN_OPTIONS": "lopt=newopt",
        "MOZ_GDB_SLEEP": "2",  # update default
        "MOZ_SKIA_DISABLE_ASSERTS": "1",  # existing optional
        "RUST_BACKTRACE": None,  # remove default
        "TEST_FAKE": None,  # remove non existing entry
        "TEST_VAR": "123",  # add non existing entry
        "TEST_EXISTING_OVERWRITE": "1",
        "TEST_EXISTING_REMOVE": None,
    }
    env = prepare_environment(tmp_path, "blah", pre)
    assert "ASAN_OPTIONS" in env
    assert "LSAN_OPTIONS" in env
    assert "lopt=newopt" in env["LSAN_OPTIONS"].split(":")
    assert "max_leaks=1" in env["LSAN_OPTIONS"].split(":")
    assert "UBSAN_OPTIONS" in env
    assert env["TEST_VAR"] == "123"
    assert "MOZ_CRASHREPORTER" in env
    assert env["MOZ_GDB_SLEEP"] == "2"
    assert "RUST_BACKTRACE" not in env
    assert "TEST_FAKE" not in env
    assert "TEST_EXISTING_REMOVE" not in env
    assert env["MOZ_SKIA_DISABLE_ASSERTS"] == "0"
    assert env["TEST_EXISTING_OVERWRITE"] == "1"
    assert "TEST_SECRET_TO_REMOVE" not in env
    # MOZ_CRASHREPORTER should not be added if MOZ_CRASHREPORTER_DISABLE is set
    pre = {"MOZ_CRASHREPORTER_DISABLE": "1"}
    env = prepare_environment(tmp_path, "blah", pre)
    assert "MOZ_CRASHREPORTER" not in env


def test_helpers_04(mocker, tmp_path):
    """test wait_on_files()"""
    fake_sleep = mocker.patch("ffpuppet.helpers.sleep", autospec=True)
    fake_time = mocker.patch("ffpuppet.helpers.perf_counter", autospec=True)
    t_file = tmp_path / "file.bin"
    t_file.touch()
    # test with open file (timeout)
    fake_time.side_effect = (1, 1, 2)
    with (tmp_path / "open.bin").open("w") as wait_fp:
        assert not wait_on_files([Path(wait_fp.name), t_file], timeout=0.1)
    assert fake_sleep.call_count == 1
    fake_sleep.reset_mock()
    # existing but closed file
    fake_time.side_effect = (1, 1)
    assert wait_on_files([t_file])
    assert fake_sleep.call_count == 0
    # file that does not exist
    fake_time.side_effect = (1, 1)
    assert wait_on_files([Path("missing")])
    assert fake_sleep.call_count == 0
    # empty file list
    fake_time.side_effect = (1, 1)
    assert wait_on_files([])
    assert fake_sleep.call_count == 0


def test_helpers_06(tmp_path):
    """test files_in_use()"""
    t_file = tmp_path / "file.bin"
    t_file.touch()
    # test with open file
    with (tmp_path / "file").open("w") as wait_fp:
        in_use = next(files_in_use([t_file, Path(wait_fp.name)]))
        assert in_use
        assert len(in_use) == 3
        assert Path(wait_fp.name).samefile(in_use[0])
        assert in_use[1] == getpid()
        assert isinstance(in_use[2], str)
    # existing but closed file
    assert not any(files_in_use([t_file]))
    # missing file
    assert not any(files_in_use([tmp_path / "missing_file"]))
    # no files
    assert not any(files_in_use([]))


def test_helpers_07(tmp_path):
    """test warn_open()"""
    with (tmp_path / "file.bin").open("w") as _:
        warn_open(tmp_path)


@mark.parametrize(
    "raised, result",
    [
        (None, False),
        (OSError("test"), False),
        (CalledProcessError(1, "test"), False),
        (
            CalledProcessError(
                1,
                "test",
                output=b"certutil - Utility to manipulate NSS certificate databases",
            ),
            True,
        ),
    ],
)
def test_certutil_available_01(mocker, raised, result):
    """test certutil_available()"""
    mocker.patch("ffpuppet.helpers.check_output", autospec=True, side_effect=raised)
    assert certutil_available(CERTUTIL) == result


def test_certutil_find_01(tmp_path):
    """test certutil_find()"""
    # default
    assert certutil_find() == CERTUTIL
    # missing bundled certutil
    browser_bin = tmp_path / "browser"
    browser_bin.touch()
    assert certutil_find(browser_bin) == CERTUTIL
    # found bundled certutil
    certutil_bin = tmp_path / "bin" / CERTUTIL
    certutil_bin.parent.mkdir()
    certutil_bin.touch()
    assert certutil_find(browser_bin) == str(certutil_bin)
