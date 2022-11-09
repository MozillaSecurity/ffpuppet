# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet sanitizer_util tests"""

from pytest import mark

from .sanitizer_util import SanitizerOptions


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
def test_sanitizer_options_01(init, add, result, overwrite):
    """test SanitizerOptions() - parsing and adding"""
    opts = SanitizerOptions(init)
    for key, value in add.items():
        opts.add(key, value, overwrite=overwrite)
    # test __str__
    assert str(opts) == str(opts.options)
    split_opts = SanitizerOptions.re_delim.split(str(opts))
    assert len(split_opts) == len(result)
    if opts:
        # test __len___
        assert len(opts) == len(result)
        for opt in split_opts:
            assert opt in result
        # test __iter__
        for opt, value in opts:
            assert "=".join((opt, value)) in result
        # test __contains___
        for opt in result:
            assert opt.split("=")[0] in opts
    else:
        assert not result[-1]


def test_sanitizer_options_02():
    """test SanitizerOptions() - get() and pop()"""
    opts = SanitizerOptions()
    assert opts.get("missing") is None
    assert opts.pop("missing") is None
    opts.add("exists", "1")
    assert opts.pop("exists") == "1"
    assert opts.get("exists") is None


def test_sanitizer_options_03(tmp_path):
    """test SanitizerOptions() - check_path()"""
    opts = SanitizerOptions()
    # test missing key
    assert opts.check_path("file")
    # test exists
    file = tmp_path / "file.bin"
    file.touch()
    opts.add("file", f"'{str(file)}'")
    assert opts.check_path("file")
    # test missing file
    file.unlink()
    assert not opts.check_path("file")


def test_sanitizer_options_04():
    """test SanitizerOptions.is_quoted()"""
    assert SanitizerOptions.is_quoted("'quoted'")
    assert SanitizerOptions.is_quoted('"quoted"')
    assert not SanitizerOptions.is_quoted("not'quoted")
    assert not SanitizerOptions.is_quoted("'not'quoted")
    assert not SanitizerOptions.is_quoted("not'quoted'")
    assert not SanitizerOptions.is_quoted("'test\"")
    assert not SanitizerOptions.is_quoted("'")
