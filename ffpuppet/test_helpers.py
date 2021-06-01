# coding=utf-8
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet helpers tests"""

import multiprocessing
import os
import shutil
import sys
import tempfile

import psutil
import pytest

from .helpers import (
    SanitizerConfig,
    append_prefs,
    check_prefs,
    configure_sanitizers,
    create_profile,
    files_in_use,
    get_processes,
    prepare_environment,
    wait_on_files,
    warn_open,
)


def test_helpers_01(tmp_path):
    """test create_profile()"""
    # try creating a profile from scratch
    # does nothing but create a directory to be populated
    (tmp_path / "dst1").mkdir()
    prof = create_profile(working_path=str(tmp_path / "dst1"))
    assert os.path.isdir(prof)
    assert not os.listdir(prof)
    # try creating a profile from a template profile
    (tmp_path / "profile").mkdir()
    invalid_js = tmp_path / "profile" / "Invalidprefs.js"
    invalid_js.write_bytes(b"blah!")
    (tmp_path / "dst2").mkdir()
    prof = create_profile(
        prefs_js=str(invalid_js),
        template=str(tmp_path / "profile"),
        working_path=str(tmp_path / "dst2"),
    )
    assert os.path.isdir(prof)
    contents = os.listdir(prof)
    assert "prefs.js" in contents
    assert "times.json" in contents
    assert "Invalidprefs.js" not in contents
    # cleanup on failure
    (tmp_path / "dst3").mkdir()
    with pytest.raises(OSError):
        create_profile(prefs_js="fake", working_path=str(tmp_path / "dst3"))
    assert not any((tmp_path / "dst3").iterdir())


def test_helpers_02(tmp_path):
    """test check_prefs()"""
    dummy_prefs = tmp_path / "dummy.js"
    dummy_prefs.write_text(
        "// comment line\n"
        "# comment line\n"
        " \n\n"
        'user_pref("a.a", 0);\n'
        'user_pref("a.b", "test");\n'
        'user_pref("a.c", true);\n'
    )
    custom_prefs = tmp_path / "custom.js"
    custom_prefs.write_text(
        "// comment line\n"
        "# comment line\n"
        "/* comment block.\n"
        "*\n"
        " \n\n"
        'user_pref("a.a", 0); // test comment\n'
        'user_pref("a.c", true);\n'
    )
    assert check_prefs(str(dummy_prefs), str(custom_prefs))
    # test detecting missing prefs
    custom_prefs.write_text('user_pref("a.a", 0);\nuser_pref("b.a", false);\n')
    assert not check_prefs(str(dummy_prefs), str(custom_prefs))


def test_helpers_03(mocker, tmp_path):
    """test create_profile() extension support"""
    mocker.patch(
        "ffpuppet.helpers.mkdtemp", autospec=True, return_value=str(tmp_path / "dst")
    )
    # create a profile with a non-existent ext
    (tmp_path / "dst").mkdir()
    with pytest.raises(RuntimeError, match="Unknown extension: 'fake_ext'"):
        create_profile(extension="fake_ext")
    assert not (tmp_path / "dst").is_dir()
    # create a profile with an xpi ext
    (tmp_path / "dst").mkdir()
    xpi = tmp_path / "xpi-ext.xpi"
    xpi.touch()
    prof = create_profile(extension=str(xpi))
    assert "extensions" in os.listdir(prof)
    assert "xpi-ext.xpi" in os.listdir(os.path.join(prof, "extensions"))
    shutil.rmtree(str(tmp_path / "dst"))
    # create a profile with an unknown ext
    (tmp_path / "dst").mkdir()
    dummy_ext = tmp_path / "dummy_ext"
    dummy_ext.mkdir()
    with pytest.raises(
        RuntimeError, match=r"Failed to find extension id in manifest: '.+?dummy_ext'"
    ):
        create_profile(extension=str(dummy_ext))
    assert not (tmp_path / "dst").is_dir()
    # create a profile with a bad legacy ext
    (tmp_path / "dst").mkdir()
    bad_legacy = tmp_path / "bad_legacy"
    bad_legacy.mkdir()
    (bad_legacy / "install.rdf").touch()
    with pytest.raises(
        RuntimeError, match=r"Failed to find extension id in manifest: '.+?bad_legacy'"
    ):
        create_profile(extension=str(bad_legacy))
    assert not (tmp_path / "dst").is_dir()
    # create a profile with a good legacy ext
    (tmp_path / "dst").mkdir()
    good_legacy = tmp_path / "good_legacy"
    good_legacy.mkdir()
    (good_legacy / "install.rdf").write_text(
        '<?xml version="1.0"?>'
        '<RDF xmlns="http://www.w3.org/1999/02/22-rdf-syntax-ns#"\n'
        '     xmlns:em="http://www.mozilla.org/2004/em-rdf#">\n'
        '  <Description about="urn:mozilla:install-manifest">\n'
        "    <em:id>good-ext-id</em:id>\n"
        "  </Description>\n"
        "</RDF>"
    )
    (good_legacy / "example.js").touch()
    prof = create_profile(extension=str(good_legacy))
    assert "extensions" in os.listdir(prof)
    assert "good-ext-id" in os.listdir(os.path.join(prof, "extensions"))
    assert set(os.listdir(os.path.join(prof, "extensions", "good-ext-id"))) == {
        "install.rdf",
        "example.js",
    }
    shutil.rmtree(str(tmp_path / "dst"))
    # create a profile with a bad webext
    (tmp_path / "dst").mkdir()
    bad_webext = tmp_path / "bad_webext"
    bad_webext.mkdir()
    (bad_webext / "manifest.json").touch()
    with pytest.raises(
        RuntimeError, match=r"Failed to find extension id in manifest: '.+?bad_webext'"
    ):
        create_profile(extension=str(bad_webext))
    assert not (tmp_path / "dst").is_dir()
    # create a profile with a good webext
    (tmp_path / "dst").mkdir()
    good_webext = tmp_path / "good_webext"
    good_webext.mkdir()
    (good_webext / "manifest.json").write_bytes(
        b"""{"applications": {"gecko": {"id": "good-webext-id"}}}"""
    )
    (good_webext / "example.js").touch()
    prof = create_profile(extension=str(good_webext))
    assert "extensions" in os.listdir(prof)
    ext_path = os.path.join(prof, "extensions")
    assert "good-webext-id" in os.listdir(ext_path)
    assert set(os.listdir(os.path.join(ext_path, "good-webext-id"))) == {
        "manifest.json",
        "example.js",
    }
    shutil.rmtree(str(tmp_path / "dst"))
    # create a profile with multiple extensions
    (tmp_path / "dst").mkdir()
    prof = create_profile(extension=[str(good_webext), str(good_legacy)])
    assert "extensions" in os.listdir(prof)
    ext_path = os.path.join(prof, "extensions")
    assert set(os.listdir(ext_path)) == {"good-ext-id", "good-webext-id"}
    assert set(os.listdir(os.path.join(ext_path, "good-webext-id"))) == {
        "manifest.json",
        "example.js",
    }
    assert set(os.listdir(os.path.join(ext_path, "good-ext-id"))) == {
        "install.rdf",
        "example.js",
    }


def test_helpers_04(tmp_path):
    """test configure_sanitizers()"""

    def parse(opt_str):
        opts = dict()
        for entry in SanitizerConfig.re_delim.split(opt_str):
            try:
                key, value = entry.split("=", maxsplit=1)
            except ValueError:
                pass
            opts[key] = value
        return opts

    # test with empty environment
    env = {}
    configure_sanitizers(env, str(tmp_path), "blah")
    assert "ASAN_OPTIONS" in env
    asan_opts = parse(env["ASAN_OPTIONS"])
    assert "external_symbolizer_path" not in asan_opts
    assert "detect_leaks" in asan_opts
    assert asan_opts["detect_leaks"] == "false"
    assert asan_opts["log_path"] == "'blah'"
    assert "LSAN_OPTIONS" in env
    assert "UBSAN_OPTIONS" in env
    # test with presets environment
    env = {
        "ASAN_OPTIONS": "detect_leaks=true",
        "LSAN_OPTIONS": "a=1",
        "UBSAN_OPTIONS": "",
    }
    configure_sanitizers(env, str(tmp_path), "blah")
    assert "ASAN_OPTIONS" in env
    asan_opts = parse(env["ASAN_OPTIONS"])
    assert "detect_leaks" in asan_opts
    assert asan_opts["detect_leaks"] == "true"
    assert "LSAN_OPTIONS" in env
    assert "UBSAN_OPTIONS" in env
    ubsan_opts = parse(env["UBSAN_OPTIONS"])
    assert "print_stacktrace" in ubsan_opts
    # test suppression file
    sup = tmp_path / "test.sup"
    sup.touch()
    env = {"ASAN_OPTIONS": "suppressions='%s'" % str(sup)}
    configure_sanitizers(env, str(tmp_path), "blah")
    asan_opts = parse(env["ASAN_OPTIONS"])
    assert "suppressions" in asan_opts
    # test overwrite log_path
    env = {
        "ASAN_OPTIONS": "log_path='overwrite'",
        "TSAN_OPTIONS": "log_path='overwrite'",
        "UBSAN_OPTIONS": "log_path='overwrite'",
    }
    configure_sanitizers(env, str(tmp_path), "blah")
    assert "ASAN_OPTIONS" in env
    asan_opts = parse(env["ASAN_OPTIONS"])
    assert asan_opts["log_path"] == "'blah'"
    assert "UBSAN_OPTIONS" in env
    ubsan_opts = parse(env["UBSAN_OPTIONS"])
    assert ubsan_opts["log_path"] == "'blah'"
    # test missing suppression file
    env = {"ASAN_OPTIONS": "suppressions=not_a_file"}
    with pytest.raises(IOError, match=r"not_a_file' \(suppressions\) does not exist"):
        configure_sanitizers(env, str(tmp_path), "blah")
    # unquoted path containing ':'
    env = {"ASAN_OPTIONS": "strip_path_prefix=x:\\foo\\bar"}
    with pytest.raises(AssertionError, match=r"\(strip_path_prefix\) must be quoted"):
        configure_sanitizers(env, str(tmp_path), "blah")
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
    env = {"ASAN_OPTIONS": ":".join(options)}
    configure_sanitizers(env, str(tmp_path), "blah")
    asan_opts = parse(env["ASAN_OPTIONS"])
    for key, value in (x.split(sep="=", maxsplit=1) for x in options):
        assert asan_opts[key] == value
    # test using packaged llvm-symbolizer
    if sys.platform.startswith("win"):
        llvm_sym_bin = tmp_path / "llvm-symbolizer.exe"
    else:
        llvm_sym_bin = tmp_path / "llvm-symbolizer"
    llvm_sym_bin.touch()
    configure_sanitizers(env, str(tmp_path), "blah")
    asan_opts = parse(env["ASAN_OPTIONS"])
    assert "external_symbolizer_path" in asan_opts
    assert asan_opts["external_symbolizer_path"].strip("'") == str(llvm_sym_bin)
    # test unbalanced quotes
    env = {"ASAN_OPTIONS": "test='a"}
    with pytest.raises(AssertionError, match=r"unbalanced quotes on"):
        configure_sanitizers(env, str(tmp_path), "blah")
    # test malformed option pair
    env = {"ASAN_OPTIONS": "a=b=c:x"}
    configure_sanitizers(env, str(tmp_path), "blah")
    asan_opts = parse(env["ASAN_OPTIONS"])
    assert asan_opts["a"] == "b=c"
    assert "x" not in asan_opts


def test_helpers_05():
    """test prepare_environment()"""
    env = prepare_environment("", "blah")
    assert "ASAN_OPTIONS" in env
    assert "LSAN_OPTIONS" in env
    assert "UBSAN_OPTIONS" in env
    assert "RUST_BACKTRACE" in env
    assert "MOZ_CRASHREPORTER" in env


def test_helpers_06():
    """test prepare_environment() using some predefined environment variables"""
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
    try:
        os.environ["MOZ_SKIA_DISABLE_ASSERTS"] = "0"
        os.environ["TEST_EXISTING_OVERWRITE"] = "0"
        os.environ["TEST_EXISTING_REMOVE"] = "1"
        env = prepare_environment("", "blah", pre)
    finally:
        os.environ.pop("MOZ_SKIA_DISABLE_ASSERTS")
        os.environ.pop("TEST_EXISTING_OVERWRITE")
        os.environ.pop("TEST_EXISTING_REMOVE")
    assert "ASAN_OPTIONS" in env
    assert "LSAN_OPTIONS" in env
    assert "lopt=newopt" in env["LSAN_OPTIONS"].split(":")
    assert "max_leaks=1" in env["LSAN_OPTIONS"].split(":")
    assert "UBSAN_OPTIONS" in env
    assert "TEST_VAR" in env
    assert env["TEST_VAR"] == "123"
    assert "MOZ_CRASHREPORTER" in env
    assert "MOZ_GDB_SLEEP" in env
    assert env["MOZ_GDB_SLEEP"] == "2"
    assert "RUST_BACKTRACE" not in env
    assert "TEST_FAKE" not in env
    assert "TEST_EXISTING_REMOVE" not in env
    assert env["MOZ_SKIA_DISABLE_ASSERTS"] == "0"
    assert env["TEST_EXISTING_OVERWRITE"] == "1"
    # MOZ_CRASHREPORTER should not be added if MOZ_CRASHREPORTER_DISABLE is set
    pre = {"MOZ_CRASHREPORTER_DISABLE": "1"}
    env = prepare_environment("", "blah", pre)
    assert "MOZ_CRASHREPORTER" not in env


def test_helpers_07(tmp_path):
    """test wait_on_files()"""
    t_file = tmp_path / "file.bin"
    t_file.touch()
    # test with open file
    procs = get_processes(os.getpid(), recursive=False)
    with tempfile.NamedTemporaryFile() as wait_fp:
        assert not wait_on_files(procs, (wait_fp.name, str(t_file)), timeout=0.1)
    # existing but closed file
    procs = get_processes(os.getpid(), recursive=False)
    assert wait_on_files(procs, [str(t_file)], timeout=0.1)
    # file that does not exist
    procs = get_processes(os.getpid(), recursive=False)
    assert wait_on_files(procs, ["no_file"], timeout=0.1)
    # empty file list
    assert wait_on_files([], [])


# this needs to be here in order to work correctly on Windows
def _dummy_process(is_alive, is_done):
    is_alive.set()
    sys.stdout.write("I'm process %d\n" % os.getpid())
    is_done.wait(30)


def test_helpers_08():
    """test get_processes()"""
    assert len(get_processes(os.getpid(), recursive=False)) == 1
    assert not get_processes(0xFFFFFF)
    is_alive = multiprocessing.Event()
    is_done = multiprocessing.Event()
    proc = multiprocessing.Process(target=_dummy_process, args=(is_alive, is_done))
    proc.start()
    try:
        is_alive.wait(30)
        assert len(get_processes(os.getpid())) > 1
    finally:
        is_done.set()
    proc.join()


def test_helpers_09(tmp_path):
    """test append_prefs()"""
    prefs = tmp_path / "prefs.js"
    prefs.write_bytes(b"user_pref('pre.existing', 1);")
    append_prefs(str(tmp_path), {"test.enabled": "true", "foo": "'a1b2c3'"})
    prefs.is_file()
    data = prefs.read_text().splitlines()
    assert len(data) == 3
    assert "user_pref('pre.existing', 1);" in data
    assert "user_pref('test.enabled', true);" in data
    assert "user_pref('foo', 'a1b2c3');" in data


def test_helpers_10(tmp_path):
    """test files_in_use()"""
    t_file = tmp_path / "file.bin"
    t_file.touch()
    procs = [psutil.Process(os.getpid())]
    # test with open file
    with tempfile.NamedTemporaryFile() as wait_fp:
        check = [os.path.abspath(wait_fp.name), os.path.abspath(str(t_file))]
        assert any(files_in_use(check, os.path.abspath, procs))
    # existing but closed file
    check = [os.path.abspath(str(t_file))]
    assert not any(files_in_use(check, os.path.abspath, procs))


def test_helpers_11(tmp_path):
    """test warn_open()"""
    (tmp_path / "file.bin").touch()
    with tempfile.NamedTemporaryFile(dir=str(tmp_path)) as _:
        warn_open(str(tmp_path))
