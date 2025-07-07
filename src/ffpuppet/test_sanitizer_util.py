# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet sanitizer_util tests"""

from subprocess import CalledProcessError, TimeoutExpired

from pytest import mark, raises

from .sanitizer_util import SanitizerOptions, symbolize_log


@mark.parametrize(
    "init, add, result, overwrite",
    [
        # do nothing
        ("", {}, [""], False),
        # add single option
        ("", {"a": "1"}, ["a=1"], False),
        # add multiple options
        ("", {"b": "2", "a": "1"}, ["a=1", "b=2"], False),
        # existing
        ("a=1", {}, ["a=1"], False),
        # add to existing
        ("a=1", {"b": "2"}, ["a=1", "b=2"], False),
        # no overwrite existing
        ("a=1", {"a": "2"}, ["a=1"], False),
        # overwrite existing
        ("a=1", {"a": "2"}, ["a=2"], True),
        # parse quoted
        (
            "a='C:\\test\\':b=\"/dev/null\"",
            {},
            ["a='C:\\test\\'", 'b="/dev/null"'],
            False,
        ),
    ],
)
def test_sanitizer_options_parsing_adding(init, add, result, overwrite):
    """test SanitizerOptions() - parsing and adding"""
    opts = SanitizerOptions(init)
    for key, value in add.items():
        opts.add(key, value, overwrite=overwrite)
    # test __str__
    split_opts = SanitizerOptions.re_delim.split(str(opts))
    assert len(split_opts) == len(result)
    if opts:
        # test __len___
        assert len(opts) == len(result)
        for opt in split_opts:
            assert opt in result
        # test __iter__
        for opt, value in opts:
            assert f"{opt}={value}" in result
        # test __contains___
        for opt in result:
            assert opt.split("=")[0] in opts
    else:
        assert not result[-1]


def test_sanitizer_load_options():
    """test SanitizerOptions.load_options -"""
    opts = SanitizerOptions()
    # empty
    assert not opts
    assert len(opts) == 0
    # single options
    opts.load_options("a=1")
    assert opts
    assert len(opts) == 1
    assert opts.pop("a") == "1"
    # multiple options
    opts.load_options("a=1:b=2")
    assert len(opts) == 2
    assert opts.pop("a") == "1"
    assert opts.pop("b") == "2"
    # malformed option
    opts.load_options("foo")
    assert len(opts) == 0
    # malformed option with valid option
    opts.load_options("a=1:foo")
    assert len(opts) == 1
    assert opts.pop("a") == "1"


@mark.parametrize(
    "flag, value, msg",
    [
        # empty flag name
        ("", "test", r"Flag name cannot be empty"),
        # missing quotes with ':'
        ("test", "a:b", r"'a:b' \(test\) must be quoted"),
        # missing quotes with ' '
        ("test", "a b", r"'a b' \(test\) must be quoted"),
    ],
)
def test_sanitizer_options_invalid_add(flag, value, msg):
    """test SanitizerOptions() -"""
    with raises(ValueError, match=msg):
        SanitizerOptions().add(flag, value)


def test_sanitizer_options_get_pop():
    """test SanitizerOptions() - get() and pop()"""
    opts = SanitizerOptions()
    assert opts.get("missing") is None
    assert opts.pop("missing") is None
    opts.add("exists", "1")
    assert opts.pop("exists") == "1"
    assert opts.get("exists") is None


def test_sanitizer_options_check_path(tmp_path):
    """test SanitizerOptions() - check_path()"""
    opts = SanitizerOptions()
    # test missing key
    assert opts.check_path("file")
    # test exists
    file = tmp_path / "file.bin"
    file.touch()
    opts.add("file", f"'{file}'")
    assert opts.check_path("file")
    # test missing file
    file.unlink()
    assert not opts.check_path("file")


def test_sanitizer_options_is_quoted():
    """test SanitizerOptions.is_quoted()"""
    assert SanitizerOptions.is_quoted("'quoted'")
    assert SanitizerOptions.is_quoted('"quoted"')
    assert not SanitizerOptions.is_quoted("not'quoted")
    assert not SanitizerOptions.is_quoted("'not'quoted")
    assert not SanitizerOptions.is_quoted("not'quoted'")
    assert not SanitizerOptions.is_quoted("'test\"")
    assert not SanitizerOptions.is_quoted("'")


def test_symbolize_log(mocker, tmp_path):
    """test symbolize_log()"""
    fake_run = mocker.patch("ffpuppet.sanitizer_util.run", autospec=True)
    log = tmp_path / "foo.txt"
    log.write_text("foo")
    # default built in llvm-symbolizer
    assert symbolize_log(log)
    # specify llvm-symbolizer
    llvm_sym = tmp_path / "fake-llvm-symbolizer"
    llvm_sym.touch()
    assert symbolize_log(log, llvm_sym)
    # symbolizer tool failed
    fake_run.side_effect = CalledProcessError(1, mocker.Mock())
    assert not symbolize_log(log, llvm_sym)
    # symbolizer tool hung
    fake_run.side_effect = TimeoutExpired(1, mocker.Mock())
    assert not symbolize_log(log, llvm_sym)
