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

import pytest

from .helpers import append_prefs, create_profile, check_prefs, configure_sanitizers, \
    get_processes, prepare_environment, SanitizerConfig, wait_on_files


def test_helpers_01(tmp_path):
    """test create_profile()"""
    with pytest.raises(IOError, match="Cannot find template profile: 'fake_dir'"):
        create_profile(template="fake_dir")
    with pytest.raises(IOError, match="prefs.js file does not exist: 'fake_prefs'"):
        create_profile(prefs_js="fake_prefs")
    # try creating a profile from scratch, does nothing but create a directory to be populated
    prof = create_profile()
    assert os.path.isdir(prof)
    try:
        assert not os.listdir(prof)
    finally:
        shutil.rmtree(prof, ignore_errors=True)
    # create dummy profile
    profile = (tmp_path / "profile")
    profile.mkdir()
    invalid_js = (profile / "Invalidprefs.js")
    invalid_js.write_bytes(b"blah!")
    # try creating a profile from a template
    prof = create_profile(prefs_js=str(invalid_js), template=str(profile), tmpdir=str(tmp_path))
    assert os.path.isdir(prof)
    contents = os.listdir(prof)
    assert "prefs.js" in contents
    assert "times.json" in contents
    assert "Invalidprefs.js" not in contents

def test_helpers_02(tmp_path):
    """test check_prefs()"""
    dummy_prefs = (tmp_path / "dummy.js")
    dummy_prefs.touch()
    with pytest.raises(IOError):
        check_prefs(str(dummy_prefs), "/missing/file")
    with pytest.raises(IOError):
        check_prefs("/missing/file", str(dummy_prefs))
    with dummy_prefs.open("wb") as prefs_fp:
        prefs_fp.write(b"// comment line\n")
        prefs_fp.write(b"# comment line\n")
        prefs_fp.write(b" \n\n")
        prefs_fp.write(b"user_pref(\"a.a\", 0);\n")
        prefs_fp.write(b"user_pref(\"a.b\", \"test\");\n")
        prefs_fp.write(b"user_pref(\"a.c\", true);\n")
    custom_prefs = (tmp_path / "custom.js")
    with custom_prefs.open("wb") as prefs_fp:
        prefs_fp.write(b"// comment line\n")
        prefs_fp.write(b"# comment line\n")
        prefs_fp.write(b"/* comment block.\n")
        prefs_fp.write(b"*\n")
        prefs_fp.write(b" \n\n")
        prefs_fp.write(b"user_pref(\"a.a\", 0); // test comment\n")
        prefs_fp.write(b"user_pref(\"a.c\", true);\n")
    assert check_prefs(str(dummy_prefs), str(custom_prefs))
    # test detecting missing prefs
    with custom_prefs.open("wb") as prefs_fp:
        prefs_fp.write(b"user_pref(\"a.a\", 0);\n")
        prefs_fp.write(b"user_pref(\"b.a\", false);\n")
    assert not check_prefs(str(dummy_prefs), str(custom_prefs))

def test_helpers_03(tmp_path):
    """test create_profile() extension support"""
    # create a profile with a non-existent ext
    with pytest.raises(RuntimeError, match="Unknown extension: 'fake_ext'"):
        create_profile(extension="fake_ext", tmpdir=str(tmp_path))
    # create a profile with an xpi ext
    xpi = (tmp_path / "xpi-ext.xpi")
    xpi.touch()
    prof = create_profile(extension=str(xpi), tmpdir=str(tmp_path))
    assert "extensions" in os.listdir(prof)
    assert "xpi-ext.xpi" in os.listdir(os.path.join(prof, "extensions"))
    # create a profile with an unknown ext
    dummy_ext = (tmp_path / "dummy_ext")
    dummy_ext.mkdir()
    with pytest.raises(RuntimeError, match=r"Failed to find extension id in manifest: '.+?dummy_ext'"):
        create_profile(extension=str(dummy_ext), tmpdir=str(tmp_path))
    # create a profile with a bad legacy ext
    bad_legacy = (tmp_path / "bad_legacy")
    bad_legacy.mkdir()
    (bad_legacy / "install.rdf").touch()
    with pytest.raises(RuntimeError, match=r"Failed to find extension id in manifest: '.+?bad_legacy'"):
        create_profile(extension=str(bad_legacy), tmpdir=str(tmp_path))
    # create a profile with a good legacy ext
    good_legacy = (tmp_path / "good_legacy")
    good_legacy.mkdir()
    with (good_legacy / "install.rdf").open("wb") as manifest:
        manifest.write(b"""<?xml version="1.0"?>
                           <RDF xmlns="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
                                xmlns:em="http://www.mozilla.org/2004/em-rdf#">
                             <Description about="urn:mozilla:install-manifest">
                               <em:id>good-ext-id</em:id>
                             </Description>
                           </RDF>""")
    (good_legacy / "example.js").touch()
    prof = create_profile(extension=str(good_legacy), tmpdir=str(tmp_path))
    assert "extensions" in os.listdir(prof)
    assert "good-ext-id" in os.listdir(os.path.join(prof, "extensions"))
    assert set(os.listdir(os.path.join(prof, "extensions", "good-ext-id"))) == {"install.rdf", "example.js"}
    # create a profile with a bad webext
    bad_webext = (tmp_path / "bad_webext")
    bad_webext.mkdir()
    (bad_webext / "manifest.json").touch()
    with pytest.raises(RuntimeError, match=r"Failed to find extension id in manifest: '.+?bad_webext'"):
        create_profile(extension=str(bad_webext), tmpdir=str(tmp_path))
    # create a profile with a good webext
    good_webext = (tmp_path / "good_webext")
    good_webext.mkdir()
    (good_webext / "manifest.json").write_bytes(b"""{"applications": {"gecko": {"id": "good-webext-id"}}}""")
    (good_webext / "example.js").touch()
    prof = create_profile(extension=str(good_webext), tmpdir=str(tmp_path))
    assert "extensions" in os.listdir(prof)
    ext_path = os.path.join(prof, "extensions")
    assert "good-webext-id" in os.listdir(ext_path)
    assert set(os.listdir(os.path.join(ext_path, "good-webext-id"))) == {"manifest.json", "example.js"}
    # create a profile with multiple extensions
    prof = create_profile(extension=[str(good_webext), str(good_legacy)], tmpdir=str(tmp_path))
    assert "extensions" in os.listdir(prof)
    ext_path = os.path.join(prof, "extensions")
    assert set(os.listdir(ext_path)) == {"good-ext-id", "good-webext-id"}
    assert set(os.listdir(os.path.join(ext_path, "good-webext-id"))) == {"manifest.json", "example.js"}
    assert set(os.listdir(os.path.join(ext_path, "good-ext-id"))) == {"install.rdf", "example.js"}

def test_helpers_04(tmp_path):
    """test configure_sanitizers()"""
    def parse(opt_str):
        opts = dict()
        for entry in SanitizerConfig.re_delim.split(opt_str):
            key, value = entry.split("=")
            opts[key] = value
        return opts
    is_windows = sys.platform.startswith("win")
    # create dummy llvm-symbolizer
    if is_windows:
        (tmp_path / "llvm-symbolizer.exe").touch()
    else:
        (tmp_path / "llvm-symbolizer").touch()
    # test with empty environment
    env = {}
    configure_sanitizers(env, str(tmp_path), "blah")
    assert "ASAN_OPTIONS" in env
    asan_opts = parse(env["ASAN_OPTIONS"])
    assert "detect_leaks" in asan_opts
    assert asan_opts["detect_leaks"] == "false"
    assert asan_opts["log_path"] == "'blah'"
    assert "LSAN_OPTIONS" in env
    assert "UBSAN_OPTIONS" in env
    if is_windows:
        assert "ASAN_SYMBOLIZER_PATH" not in env
    else:
        assert "llvm-symbolizer" in env["ASAN_SYMBOLIZER_PATH"]
    # test with presets environment
    env = {"ASAN_OPTIONS":"detect_leaks=true", "LSAN_OPTIONS":"a=1=2", "UBSAN_OPTIONS":""}
    configure_sanitizers(env, str(tmp_path), "blah")
    assert "ASAN_OPTIONS" in env
    asan_opts = parse(env["ASAN_OPTIONS"])
    assert "detect_leaks" in asan_opts
    assert asan_opts["detect_leaks"] == "true"
    assert "LSAN_OPTIONS" in env
    assert "UBSAN_OPTIONS" in env
    ubsan_opts = parse(env["UBSAN_OPTIONS"])
    assert "print_stacktrace" in ubsan_opts
    # test previously set ASAN_SYMBOLIZER_PATH
    env = {"ASAN_SYMBOLIZER_PATH":"blah"}
    configure_sanitizers(env, "target_dir", "blah")
    assert "ASAN_SYMBOLIZER_PATH" in env
    assert env["ASAN_SYMBOLIZER_PATH"] in "blah"
    # test suppression file
    sup = tmp_path / "test.sup"
    sup.touch()
    env = {"ASAN_OPTIONS":"suppressions='%s'" % str(sup)}
    configure_sanitizers(env, str(tmp_path), "blah")
    asan_opts = parse(env["ASAN_OPTIONS"])
    assert "suppressions" in asan_opts
    # test overwrite log_path
    env = {"ASAN_OPTIONS":"log_path='overwrite'", "UBSAN_OPTIONS":"log_path='overwrite'"}
    configure_sanitizers(env, str(tmp_path), "blah")
    assert "ASAN_OPTIONS" in env
    asan_opts = parse(env["ASAN_OPTIONS"])
    assert asan_opts["log_path"] == "'blah'"
    assert "UBSAN_OPTIONS" in env
    ubsan_opts = parse(env["UBSAN_OPTIONS"])
    assert ubsan_opts["log_path"] == "'blah'"
    # test missing suppression file
    env = {"ASAN_OPTIONS":"suppressions=no_a_file"}
    with pytest.raises(IOError, match=r"Suppressions file '.+?' does not exist"):
        configure_sanitizers(env, str(tmp_path), "blah")
    # unquoted path containing ':'
    env = {"ASAN_OPTIONS":"strip_path_prefix=x:\\foo\\bar"}
    with pytest.raises(AssertionError):
        configure_sanitizers(env, tmp_path, "blah")
    # multiple options
    env = {"ASAN_OPTIONS":"opt1=1:opt2=:opt3=test:opt4='x:\\foo':opt5=\"z:/bar\":opt6=''"}
    configure_sanitizers(env, str(tmp_path), "blah")
    asan_opts = parse(env["ASAN_OPTIONS"])
    assert asan_opts["opt1"] == "1"
    assert asan_opts["opt2"] == ""
    assert asan_opts["opt3"] == "test"
    assert asan_opts["opt4"] == "'x:\\foo'"
    assert asan_opts["opt5"] == "\"z:/bar\""
    assert asan_opts["opt6"] == "''"

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
        "MOZ_GDB_SLEEP":"2",  # update default
        "MOZ_SKIA_DISABLE_ASSERTS": "1",  # existing optional
        "RUST_BACKTRACE":None,  # remove default
        "TEST_FAKE":None,  # remove non existing entry
        "TEST_VAR":"123",  # add non existing entry
        "TEST_EXISTING_OVERWRITE":"1",
        "TEST_EXISTING_REMOVE":None}
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
    t_file = (tmp_path / "file.bin")
    t_file.touch()
    with tempfile.NamedTemporaryFile() as wait_fp:
        assert not wait_on_files((wait_fp.name, str(t_file)), timeout=0.1)
    # existing but closed file
    assert wait_on_files([str(t_file)], timeout=0.1)
    # file that does not exist
    assert wait_on_files(["no_file"], timeout=0.1)
    # empty file list
    assert wait_on_files([])

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
    prefs = (tmp_path / "prefs.js")
    prefs.write_bytes(b"user_pref('pre.existing', 1);")
    append_prefs(str(tmp_path), {"test.enabled": "true", "foo": "'a1b2c3'"})
    prefs.is_file()
    data = prefs.read_text().splitlines()
    assert len(data) == 3
    assert "user_pref('pre.existing', 1);" in data
    assert "user_pref('test.enabled', true);" in data
    assert "user_pref('foo', 'a1b2c3');" in data
