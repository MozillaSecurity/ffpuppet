# type: ignore
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet profile tests"""

from shutil import rmtree
from subprocess import CalledProcessError

from pytest import mark, raises

from .profile import Profile


def test_profile_01(tmp_path):
    """test basic Profile"""
    with Profile(working_path=str(tmp_path)) as profile:
        assert profile
        assert str(profile)
        assert profile.path.parent == tmp_path
        assert not (profile.path / "times.json").is_file()
        assert profile.invalid_prefs is None
        (profile.path / "Invalidprefs.js").touch()
        assert profile.invalid_prefs is not None
        profile.remove()
        assert profile.path is None


def test_profile_02(tmp_path):
    """test Profile with template"""
    template = tmp_path / "template"
    template.mkdir()
    (template / "a.txt").touch()
    (template / "Invalidprefs.js").touch()
    working = tmp_path / "working"
    working.mkdir()
    with Profile(template=template, working_path=str(working)) as profile:
        assert profile
        assert profile.path.parent == working
        assert (profile.path / "a.txt").is_file()
        assert not (profile.path / "Invalidprefs.js").is_file()


@mark.parametrize(
    "existing, additional",
    [
        ({}, {}),
        ({"pre.existing": "1"}, {}),
        ({"pre.existing": "1"}, {"foo": "'a1b1c1'", "test.enabled": "true"}),
        ({}, {"foo": "'a1b1c1'", "test.enabled": "true"}),
    ],
)
def test_profile_03(tmp_path, existing, additional):
    """test Profile with prefs.js"""
    prefs = None
    if existing:
        prefs = tmp_path / "prefs.js"
        for name, value in existing.items():
            prefs.write_text(f"user_pref('{name}', {value});\n")
    working = tmp_path / "working"
    working.mkdir()
    with Profile(prefs_file=prefs, working_path=str(working)) as profile:
        assert profile
        assert profile.path.parent == working
        profile.add_prefs(additional)
        if additional or existing:
            assert (profile.path / "prefs.js").is_file()
            assert (profile.path / "times.json").is_file()
            data = (profile.path / "prefs.js").read_text()
            for name, value in existing.items():
                assert f"user_pref('{name}', {value});\n" in data
            for name, value in additional.items():
                assert f"user_pref('{name}', {value});\n" in data
            lines = [x for x in data.splitlines() if x.startswith("user_pref(")]
            assert len(lines) == len(existing) + len(additional)


def test_profile_04(mocker, tmp_path):
    """test create_profile() extension support"""
    mocker.patch(
        "ffpuppet.profile.mkdtemp", autospec=True, return_value=str(tmp_path / "dst")
    )
    # create a profile with a non-existent ext
    (tmp_path / "dst").mkdir()
    with raises(RuntimeError, match=r"Unknown extension: '.+?fake_ext'"):
        Profile(extensions=[tmp_path / "fake_ext"])
    assert not (tmp_path / "dst").is_dir()
    # create a profile with an xpi ext
    (tmp_path / "dst").mkdir()
    xpi = tmp_path / "xpi-ext.xpi"
    xpi.touch()
    with Profile(extensions=[xpi]) as prof:
        assert any(prof.path.glob("extensions"))
        assert (prof.path / "extensions" / "xpi-ext.xpi").is_file()
        rmtree(tmp_path / "dst")
    # create a profile with an unknown ext
    (tmp_path / "dst").mkdir()
    dummy_ext = tmp_path / "dummy_ext"
    dummy_ext.mkdir()
    with raises(
        RuntimeError, match=r"Failed to find extension id in manifest: '.+?dummy_ext'"
    ):
        Profile(extensions=[dummy_ext])
    assert not (tmp_path / "dst").is_dir()
    # create a profile with a bad legacy ext
    (tmp_path / "dst").mkdir()
    bad_legacy = tmp_path / "bad_legacy"
    bad_legacy.mkdir()
    (bad_legacy / "install.rdf").touch()
    with raises(
        RuntimeError, match=r"Failed to find extension id in manifest: '.+?bad_legacy'"
    ):
        Profile(extensions=[bad_legacy])
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
    with Profile(extensions=[good_legacy]) as prof:
        assert any(prof.path.glob("extensions"))
        ext_path = prof.path / "extensions" / "good-ext-id"
        assert (ext_path / "install.rdf").is_file()
        assert (ext_path / "example.js").is_file()
        rmtree(tmp_path / "dst")
    # create a profile with a bad webext
    (tmp_path / "dst").mkdir()
    bad_webext = tmp_path / "bad_webext"
    bad_webext.mkdir()
    (bad_webext / "manifest.json").touch()
    with raises(
        RuntimeError, match=r"Failed to find extension id in manifest: '.+?bad_webext'"
    ):
        Profile(extensions=[bad_webext])
    assert not (tmp_path / "dst").is_dir()
    # create a profile with a good webext
    (tmp_path / "dst").mkdir()
    good_webext = tmp_path / "good_webext"
    good_webext.mkdir()
    (good_webext / "manifest.json").write_bytes(
        b"""{"applications": {"gecko": {"id": "good-webext-id"}}}"""
    )
    (good_webext / "example.js").touch()
    with Profile(extensions=[good_webext]) as prof:
        assert any(prof.path.glob("extensions"))
        ext_path = prof.path / "extensions" / "good-webext-id"
        assert ext_path.is_dir()
        assert (ext_path / "manifest.json").is_file()
        assert (ext_path / "example.js").is_file()
        rmtree(tmp_path / "dst")
    # create a profile with multiple extensions
    (tmp_path / "dst").mkdir()
    with Profile(extensions=[good_webext, good_legacy]) as prof:
        assert any(prof.path.glob("extensions"))
        ext_path = prof.path / "extensions"
        assert ext_path.is_dir()
        ext_path = prof.path / "extensions" / "good-webext-id"
        assert ext_path.is_dir()
        assert (ext_path / "manifest.json").is_file()
        assert (ext_path / "example.js").is_file()
        ext_path = prof.path / "extensions" / "good-ext-id"
        assert ext_path.is_dir()
        assert (ext_path / "install.rdf").is_file()
        assert (ext_path / "example.js").is_file()


def test_profile_05(tmp_path):
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
    assert Profile.check_prefs(dummy_prefs, custom_prefs)
    # test detecting missing prefs
    custom_prefs.write_text('user_pref("a.a", 0);\nuser_pref("b.a", false);\n')
    assert not Profile.check_prefs(dummy_prefs, custom_prefs)


def test_profile_06(mocker, tmp_path):
    """test Profile.remove() failure"""
    mocker.patch("ffpuppet.profile.rmtree", autospec=True, side_effect=OSError("test"))
    with Profile(working_path=str(tmp_path)) as profile:
        profile.remove(ignore_errors=True)
    with Profile(working_path=str(tmp_path)) as profile:
        with raises(OSError, match="test"):
            profile.remove(ignore_errors=False)


def test_profile_07(mocker, tmp_path):
    """test Profile with certs"""
    mocker.patch("ffpuppet.profile.certutil_available", autospec=True)
    fake_check = mocker.patch("ffpuppet.profile.check_output", autospec=True)
    working = tmp_path / "working"
    working.mkdir()
    cert = tmp_path / "cert"
    cert.touch()
    with Profile(cert_files=[cert], working_path=str(working)):
        assert fake_check.call_count == 2


def test_profile_08(mocker, tmp_path):
    """test Profile missing certutil"""
    mocker.patch(
        "ffpuppet.profile.check_output", autospec=True, side_effect=OSError("test")
    )
    cert = tmp_path / "cert"
    cert.touch()
    with raises(OSError, match="certutil not found"):
        Profile(cert_files=[cert], working_path=str(tmp_path))


def test_profile_09(mocker, tmp_path):
    """test Profile._install_cert() certutil error"""
    mocker.patch("ffpuppet.profile.certutil_available", autospec=True)
    mocker.patch(
        "ffpuppet.profile.check_output",
        autospec=True,
        side_effect=CalledProcessError(1, "test", output=b"error msg"),
    )
    cert = tmp_path / "cert"
    cert.touch()
    with raises(RuntimeError, match="certutil error"):
        Profile(cert_files=[cert], working_path=str(tmp_path))
