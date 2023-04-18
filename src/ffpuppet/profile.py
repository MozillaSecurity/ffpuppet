# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet profile manager"""

from json import load as json_load
from logging import getLogger
from pathlib import Path
from shutil import copyfile, copytree, rmtree
from subprocess import STDOUT, CalledProcessError, check_output
from tempfile import mkdtemp
from time import time
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree

from .helpers import certutil_available, certutil_find, onerror

LOG = getLogger(__name__)

__author__ = "Tyson Smith"
__all__ = ("Profile",)


class Profile:
    """
    Browser profile management object.
    """

    __slots__ = ("path",)

    def __init__(
        self,
        browser_bin: Optional[Path] = None,
        cert_files: Optional[List[Path]] = None,
        extensions: Optional[List[Path]] = None,
        prefs_file: Optional[Path] = None,
        template: Optional[Path] = None,
        working_path: Optional[str] = None,
    ) -> None:
        if cert_files and not certutil_available(certutil_find(browser_bin)):
            raise OSError("NSS certutil not found")

        self.path: Optional[Path] = Path(mkdtemp(dir=working_path, prefix="ffprofile_"))
        try:
            if template is not None:
                self._copy_template(template)
            if prefs_file is not None:
                self._copy_prefs_file(prefs_file)
            if extensions is not None:
                self._copy_extensions(extensions)
            if cert_files:
                for cert in cert_files:
                    self._install_cert(cert, certutil_find(browser_bin))
        except Exception:
            rmtree(self.path, onerror=onerror)
            raise

    def __enter__(self) -> "Profile":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.remove()

    def __str__(self) -> str:
        return str(self.path)

    def _add_times_json(self) -> None:
        assert self.path
        # times.json only needs to be created when using a custom prefs.js
        times_json = self.path / "times.json"
        if not times_json.is_file():
            times_json.write_text(f'{{"created":{int(time()) * 1000}}}')

    def _copy_extensions(self, extensions: List[Path]) -> None:
        assert self.path
        ext_path = self.path / "extensions"
        ext_path.mkdir(exist_ok=True)
        for ext in extensions:
            if ext.is_file() and ext.name.endswith(".xpi"):
                copyfile(ext, ext_path / ext.name)
            elif ext.is_dir():
                # read manifest to see what the folder should be named
                ext_name = None
                if (ext / "manifest.json").is_file():
                    try:
                        with (ext / "manifest.json").open("r") as manifest:
                            manifest_loaded_json = json_load(manifest)
                        ext_name = manifest_loaded_json["applications"]["gecko"]["id"]
                    except (OSError, KeyError, ValueError) as exc:
                        LOG.debug("Failed to parse manifest.json: %s", exc)
                elif (ext / "install.rdf").is_file():
                    try:
                        xmlns = {
                            "x": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                            "em": "http://www.mozilla.org/2004/em-rdf#",
                        }
                        tree = ElementTree.parse(str(ext / "install.rdf"))
                        assert tree.getroot().tag == f"{{{xmlns['x']}}}RDF"
                        ids = tree.findall("./x:Description/em:id", namespaces=xmlns)
                        assert len(ids) == 1
                        ext_name = ids[0].text
                    except (AssertionError, OSError, ElementTree.ParseError) as exc:
                        LOG.debug("Failed to parse install.rdf: %s", exc)
                if ext_name is None:
                    raise RuntimeError(
                        f"Failed to find extension id in manifest: '{ext}'"
                    )
                copytree(ext, self.path / "extensions" / ext_name)
            else:
                raise RuntimeError(f"Unknown extension: '{ext}'")

    def _copy_prefs_file(self, prefs_file: Path) -> None:
        assert self.path
        LOG.debug("using prefs.js: %r", prefs_file)
        copyfile(prefs_file, self.path / "prefs.js")
        self._add_times_json()

    def _copy_template(self, template: Path) -> None:
        assert self.path
        LOG.debug("using profile template: %s", template)
        rmtree(self.path)
        copytree(template, self.path)
        invalid_prefs = self.path / "Invalidprefs.js"
        # if Invalidprefs.js was copied from the template profile remove it
        if invalid_prefs.is_file():
            invalid_prefs.unlink()

    def _install_cert(self, cert_file: Path, certutil: str) -> None:
        assert self.path
        LOG.debug("installing certificate '%s' with %r", cert_file, certutil)
        try:
            # create certificate database if needed
            if not (self.path / "cert9.db").exists():
                check_output(
                    [
                        certutil,
                        "-N",
                        "-d",
                        str(self.path),
                        "--empty-password",
                    ],
                    stderr=STDOUT,
                    timeout=10,
                )
            check_output(
                [
                    certutil,
                    "-A",
                    "-d",
                    str(self.path),
                    "-t",
                    "CT,,",
                    "-n",
                    "test cert",
                    "-i",
                    str(cert_file),
                ],
                stderr=STDOUT,
                timeout=10,
            )
        except CalledProcessError as exc:
            LOG.error(exc.output.decode().strip())
            raise RuntimeError("certutil error") from None

    def add_prefs(self, prefs: Dict[str, str]) -> None:
        """Write or append preferences from prefs to prefs.js file in profile_path.

        Args:
            prefs: preferences to add.

        Returns:
            None
        """
        assert self.path
        if not (self.path / "prefs.js").is_file():
            self._add_times_json()
        with (self.path / "prefs.js").open("a") as prefs_fp:
            # make sure there is a newline before appending to prefs.js
            prefs_fp.write("\n")
            for name, value in prefs.items():
                prefs_fp.write(f"user_pref('{name}', {value});\n")

    @staticmethod
    def check_prefs(prof_prefs: Path, input_prefs: Path) -> bool:
        """Check that the given prefs.js file in use by the browser contains all
        the requested preferences.
        NOTE: There will be false positives if input_prefs does not adhere to the
        formatting that is used in prefs.js file generated by the browser.

        Args:
            prof_prefs: Profile prefs.js file.
            input_prefs: Prefs.js file that contains prefs that should be merged into
                         the prefs.js file generated by the browser.

        Returns:
            True if all expected preferences are found otherwise False.
        """
        with prof_prefs.open() as p_fp, input_prefs.open() as i_fp:
            p_prefs = {p.split(",")[0] for p in p_fp if p.startswith("user_pref(")}
            i_prefs = {p.split(",")[0] for p in i_fp if p.startswith("user_pref(")}
        missing_prefs = i_prefs - p_prefs
        for missing in missing_prefs:
            LOG.debug("pref not set %r", missing)
        return not missing_prefs

    @property
    def invalid_prefs(self) -> Optional[Path]:
        """Path to Invalidprefs.js if it exists.

        Args:
            None

        Returns:
            Invalidprefs.js or None if it does not exist.

        """
        if self.path and (self.path / "Invalidprefs.js").is_file():
            return self.path / "Invalidprefs.js"
        return None

    def remove(self, ignore_errors: bool = True) -> None:
        """Remove the profile from the filesystem.

        Args:
            ignore_errors: Do not raise exception if error is encountered.

        Returns:
            None
        """
        if self.path:
            LOG.debug("removing profile")
            try:
                rmtree(self.path, onerror=onerror)
            except OSError:
                LOG.error("Failed to remove profile '%s'", self.path)
                # skip raising here instead of passing ignore_errors to rmtree
                # this way onerror is always called if there is an error
                if not ignore_errors:
                    raise
            finally:
                self.path = None
