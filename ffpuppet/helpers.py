# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet helper utilities"""

from json import load as json_load
from logging import getLogger
from os import W_OK, access, chmod, environ, mkdir, remove
from os.path import abspath, basename, isdir, isfile
from os.path import join as pathjoin
from pathlib import Path
from platform import system
from shutil import copyfile, copytree, rmtree
from stat import S_IWUSR
from tempfile import mkdtemp
from time import sleep, time
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple, Union
from xml.etree import ElementTree

from psutil import AccessDenied, NoSuchProcess, Process, process_iter

from .sanitizer_util import SanitizerOptions

LOG = getLogger(__name__)

__author__ = "Tyson Smith"
__all__ = (
    "check_prefs",
    "create_profile",
    "files_in_use",
    "get_processes",
    "onerror",
    "prepare_environment",
    "wait_on_files",
    "warn_open",
)


def append_prefs(profile_path: str, prefs: Dict[str, str]) -> None:
    """Write or append preferences from prefs to prefs.js file in profile_path.

    Args:
        profile_path: Directory containing prefs.js file to write to.
        prefs: preferences to add.

    Returns:
        None
    """
    assert isinstance(prefs, dict)
    with open(pathjoin(profile_path, "prefs.js"), "a") as prefs_fp:
        # make sure there is a newline before appending to prefs.js
        prefs_fp.write("\n")
        for name, value in prefs.items():
            prefs_fp.write(f"user_pref('{name}', {value});\n")


def check_prefs(prof_prefs: str, input_prefs: str) -> bool:
    """Check that the given prefs.js file in use by the browser contains all
    the requested preferences.
    NOTE: There will be false positives if input_prefs does not adhere to the
    formatting that is used in prefs.js file generated by the browser.

    Args:
        prof_prefs: Path to profile prefs.js file.
        input_prefs: Path to prefs.js file that contains prefs that
                           should be merged into the prefs.js file generated by
                           the browser.

    Returns:
        True if all expected preferences are found otherwise False.
    """
    with open(prof_prefs) as p_fp, open(input_prefs) as i_fp:
        p_prefs = {pref.split(",")[0] for pref in p_fp if pref.startswith("user_pref(")}
        i_prefs = {pref.split(",")[0] for pref in i_fp if pref.startswith("user_pref(")}
    missing_prefs = i_prefs - p_prefs
    for missing in missing_prefs:
        LOG.debug("pref not set %r", missing)
    return not missing_prefs


def _configure_sanitizers(
    orig_env: Dict[str, str], target_dir: str, log_path: str
) -> Dict[str, str]:
    """Copy environment and update default values in *SAN_OPTIONS entries.
    These values are only updated if they are not provided, with the exception of
    'log_path'. 'log_path' is used by FFPuppet to detect results.

    Args:
        env: Current environment.
        target_dir: Directory containing browser binary.
        log_path: Location to write sanitizer logs to.

    Returns:
        Environment with *SAN_OPTIONS defaults set.
    """
    env: Dict[str, str] = dict(orig_env)
    # https://github.com/google/sanitizers/wiki/SanitizerCommonFlags
    common_flags = [
        ("abort_on_error", "false"),
        ("allocator_may_return_null", "true"),
        ("disable_coredump", "true"),
        ("exitcode", "77"),  # use unique exitcode to help identify missed reports
        ("handle_abort", "true"),  # if true, abort_on_error=false to prevent hangs
        ("handle_sigbus", "true"),  # set to be safe
        ("handle_sigfpe", "true"),  # set to be safe
        ("handle_sigill", "true"),  # set to be safe
        # requires background thread so only works on Linux for now...
        # https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/
        # sanitizer_common/sanitizer_common_libcdep.cpp#L116
        ("soft_rss_limit_mb", "10000"),
        ("symbolize", "true"),
    ]
    # set llvm-symbolizer path
    # *SAN_OPTIONS=external_symbolizer_path takes priority if it is defined in env
    llvm_sym = env.get("ASAN_SYMBOLIZER_PATH")
    if not llvm_sym:
        # use packaged llvm-symbolizer
        if system().startswith("Windows"):
            llvm_sym = pathjoin(target_dir, "llvm-symbolizer.exe")
        else:
            llvm_sym = pathjoin(target_dir, "llvm-symbolizer")
    if isfile(llvm_sym):
        # add *SAN_OPTIONS=external_symbolizer_path
        common_flags.append(("external_symbolizer_path", f"'{llvm_sym}'"))
    else:
        # assume system llvm-symbolizer will be used
        LOG.debug("llvm-symbolizer not found (%s)", llvm_sym)

    # setup Address Sanitizer options ONLY if not set manually in environment
    # https://github.com/google/sanitizers/wiki/AddressSanitizerFlags
    asan_config = SanitizerOptions(env.get("ASAN_OPTIONS"))
    assert asan_config.check_path("suppressions"), "missing suppressions file"
    for flag in common_flags:
        asan_config.add(*flag)
    # different defaults per OS
    # asan_config.add("alloc_dealloc_mismatch", "false")
    asan_config.add("check_initialization_order", "true")
    # https://bugzil.la/1057551
    # asan_config.add("detect_stack_use_after_return", "true")
    # asan_config.add("detect_stack_use_after_scope", "true")
    asan_config.add("detect_invalid_pointer_pairs", "1")
    asan_config.add("detect_leaks", "false")
    # log_path is required for FFPuppet logging to function properly
    if "log_path" in asan_config:
        LOG.warning(
            "ASAN_OPTIONS=log_path is used internally and cannot be set externally"
        )
    asan_config.add("log_path", f"'{log_path}'", overwrite=True)
    asan_config.add("sleep_before_dying", "0")
    asan_config.add("strict_init_order", "true")
    # breaks old builds (esr52)
    asan_config.add("strict_string_checks", "true")
    env["ASAN_OPTIONS"] = asan_config.options

    # setup Leak Sanitizer options ONLY if not set manually in environment
    # https://github.com/google/sanitizers/wiki/AddressSanitizerLeakSanitizer
    lsan_config = SanitizerOptions(env.get("LSAN_OPTIONS"))
    assert lsan_config.check_path("suppressions"), "missing suppressions file"
    lsan_config.add("max_leaks", "1")
    lsan_config.add("print_suppressions", "false")
    # helpful with rr/Pernosco sessions
    lsan_config.add("report_objects", "1")
    env["LSAN_OPTIONS"] = lsan_config.options

    # setup Thread Sanitizer options ONLY if not set manually in environment
    tsan_config = SanitizerOptions(env.get("TSAN_OPTIONS"))
    assert tsan_config.check_path("suppressions"), "missing suppressions file"
    tsan_config.add("halt_on_error", "1")
    if "log_path" in tsan_config:
        LOG.warning(
            "TSAN_OPTIONS=log_path is used internally and cannot be set externally"
        )
    tsan_config.add("log_path", f"'{log_path}'", overwrite=True)
    env["TSAN_OPTIONS"] = tsan_config.options

    # setup Undefined Behavior Sanitizer options ONLY if not set manually in environment
    ubsan_config = SanitizerOptions(env.get("UBSAN_OPTIONS"))
    assert ubsan_config.check_path("suppressions"), "missing suppressions file"
    for flag in common_flags:
        ubsan_config.add(*flag)
    if "log_path" in ubsan_config:
        LOG.warning(
            "UBSAN_OPTIONS=log_path is used internally and cannot be set externally"
        )
    ubsan_config.add("log_path", f"'{log_path}'", overwrite=True)
    ubsan_config.add("print_stacktrace", "1")
    ubsan_config.add("report_error_type", "1")
    env["UBSAN_OPTIONS"] = ubsan_config.options

    return env


def create_profile(
    extension: Optional[Union[List[str], str]] = None,
    prefs_js: Optional[str] = None,
    template: Optional[str] = None,
    working_path: Optional[str] = None,
) -> str:
    """Create a profile to be used with Firefox.

    Args:
        extension: Path to an extension to be installed.
        prefs_js: Path to the prefs.js file to install in the profile.
        template: Path to an existing profile directory to use.
        working_path: Used as base directory for temporary files.

    Returns:
        Path to directory to be used as a profile.
    """
    profile = mkdtemp(dir=working_path, prefix="ffprofile_")
    try:
        if template is not None:
            LOG.debug("using profile template: %r", template)
            rmtree(profile)
            copytree(template, profile)
            invalid_prefs = pathjoin(profile, "Invalidprefs.js")
            # if Invalidprefs.js was copied from the template profile remove it
            if isfile(invalid_prefs):
                remove(invalid_prefs)
        if prefs_js is not None:
            LOG.debug("using prefs.js: %r", prefs_js)
            copyfile(prefs_js, pathjoin(profile, "prefs.js"))
            # times.json only needs to be created when using a custom prefs.js
            times_json = pathjoin(profile, "times.json")
            if not isfile(times_json):
                with open(times_json, "w") as times_fp:
                    times_fp.write(f'{{"created":{int(time()) * 1000}}}')
    except OSError:
        rmtree(profile)
        raise

    # extension support
    try:
        if extension is None:
            extensions = []
        elif isinstance(extension, (list, tuple)):
            extensions = extension
        else:
            extensions = [extension]
        if extensions and not isdir(pathjoin(profile, "extensions")):
            mkdir(pathjoin(profile, "extensions"))
        for ext in extensions:
            if isfile(ext) and ext.endswith(".xpi"):
                copyfile(ext, pathjoin(profile, "extensions", basename(ext)))
            elif isdir(ext):
                # read manifest to see what the folder should be named
                ext_name = None
                if isfile(pathjoin(ext, "manifest.json")):
                    try:
                        with open(pathjoin(ext, "manifest.json")) as manifest:
                            manifest_loaded_json = json_load(manifest)
                        ext_name = manifest_loaded_json["applications"]["gecko"]["id"]
                    except (OSError, KeyError, ValueError) as exc:
                        LOG.debug("Failed to parse manifest.json: %s", exc)
                elif isfile(pathjoin(ext, "install.rdf")):
                    try:
                        xmlns = {
                            "x": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                            "em": "http://www.mozilla.org/2004/em-rdf#",
                        }
                        tree = ElementTree.parse(pathjoin(ext, "install.rdf"))
                        assert tree.getroot().tag == f"{{{xmlns['x']}}}RDF"
                        ids = tree.findall("./x:Description/em:id", namespaces=xmlns)
                        assert len(ids) == 1
                        ext_name = ids[0].text
                    except (AssertionError, OSError, ElementTree.ParseError) as exc:
                        LOG.debug("Failed to parse install.rdf: %s", exc)
                if ext_name is None:
                    raise RuntimeError(
                        f"Failed to find extension id in manifest: {ext!r}"
                    )
                copytree(abspath(ext), pathjoin(profile, "extensions", ext_name))
            else:
                raise RuntimeError(f"Unknown extension: {ext!r}")
    except Exception:
        # cleanup on failure
        rmtree(profile, True)
        raise
    return profile


def files_in_use(
    files: Iterable[Path], procs: Iterable[Process]
) -> Iterator[Tuple[Path, int, str]]:
    """Check if any of the given files are open by any of the given processes.

    Args:
        files: Files to check.
        procs: Processes to scan for open files.

    Yields:
        Path of file, process ID and process name.
    """
    assert isinstance(files, (set, tuple, list))
    if files:
        for proc in procs:
            try:
                # WARNING: Process.open_files() has issues on Windows!
                # https://psutil.readthedocs.io/en/latest/#psutil.Process.open_files
                for open_file in (Path(x.path) for x in proc.open_files()):
                    for check_file in files:
                        try:
                            if check_file.samefile(open_file):
                                yield open_file, proc.pid, proc.name()
                        except OSError:
                            # samefile() can raise if either file cannot be accessed
                            # this is triggered on Windows if a file is missing
                            pass
            except (AccessDenied, NoSuchProcess):  # pragma: no cover
                pass


def get_processes(pid: int, recursive: bool = True) -> List[Process]:
    """From a given PID create a psutil.Process object and lookup all of its
    children.

    Args:
        pid: PID of the process to lookup.
        recursive: Include the children (and so on) of the Process
                          that was created.

    Returns:
        A list of psutil.Process objects. The first object will always
        be the Process that corresponds to PID.
    """
    try:
        procs = [Process(pid)]
    except (AccessDenied, NoSuchProcess):
        return list()
    if not recursive:
        return procs
    try:
        procs += procs[0].children(recursive=True)
    except (AccessDenied, NoSuchProcess):  # pragma: no cover
        pass
    return procs


def onerror(
    func: Callable[[str], Any], path: str, _exc_info: Any
) -> None:  # pragma: no cover
    """
    Error handler for `shutil.rmtree`.

    If the error is due to an access error (read only file)
    it attempts to add write permission and then retries.

    If the error is for another reason it re-raises the error.

    Copyright Michael Foord 2004
    Released subject to the BSD License
    ref: http://www.voidspace.org.uk/python/recipebook.shtml#utils

    Usage : `shutil.rmtree(path, onerror=onerror)`
    """
    if not access(path, W_OK):
        # Is the error an access error?
        chmod(path, S_IWUSR)
        func(path)
    else:
        # this should only ever be called from an exception context
        raise  # pylint: disable=misplaced-bare-raise


def prepare_environment(
    target_dir: str,
    sanitizer_log: str,
    env_mod: Optional[Dict[str, Optional[str]]] = None,
) -> Dict[str, str]:
    """Create environment that can be used when launching the browser.

    Args:
        target_dir: Path to the directory containing the Firefox binary.
        sanitizer_log: Location to write sanitizer logs. Log prefix set
                             with ASAN_OPTIONS=log_path=<sanitizer_log>.
        env_mod (dict): Environment modifier. Add, remove and update entries
                        in the prepared environment. Add and update by setting
                        value (str) and remove by setting entry value to None.

    Returns:
        Environment to use when launching browser.
    """
    base: Dict[str, Optional[str]] = dict()
    env: Dict[str, str] = dict(environ)

    # https://developer.gimp.org/api/2.0/glib/glib-running.html#G_SLICE
    base["G_SLICE"] = "always-malloc"
    base["MOZ_AUTOMATION"] = "1"
    base["MOZ_CC_RUN_DURING_SHUTDOWN"] = "1"
    # https://firefox-source-docs.mozilla.org/toolkit/crashreporter/crashreporter/ ...
    # index.html#environment-variables-affecting-crash-reporting
    base["MOZ_CRASHREPORTER"] = "1"
    base["MOZ_CRASHREPORTER_NO_DELETE_DUMP"] = "1"
    base["MOZ_CRASHREPORTER_NO_REPORT"] = "1"
    base["MOZ_DISABLE_CONTENT_SANDBOX"] = "1"
    base["MOZ_DISABLE_GMP_SANDBOX"] = "1"
    base["MOZ_DISABLE_GPU_SANDBOX"] = "1"
    base["MOZ_DISABLE_NPAPI_SANDBOX"] = "1"
    base["MOZ_DISABLE_PDFIUM_SANDBOX"] = "1"
    base["MOZ_DISABLE_RDD_SANDBOX"] = "1"
    base["MOZ_DISABLE_SOCKET_PROCESS_SANDBOX"] = "1"
    base["MOZ_DISABLE_UTILITY_SANDBOX"] = "1"
    base["MOZ_DISABLE_VR_SANDBOX"] = "1"
    base["MOZ_GDB_SLEEP"] = "0"
    # https://bugzilla.mozilla.org/show_bug.cgi?id=1305151
    # skia assertions are easily hit and mostly due to precision, disable them.
    base["MOZ_SKIA_DISABLE_ASSERTS"] = "1"
    base["RUST_BACKTRACE"] = "full"
    # https://developer.mozilla.org/en-US/docs/Mozilla/Debugging/XPCOM_DEBUG_BREAK
    base["XPCOM_DEBUG_BREAK"] = "warn"
    base["XRE_NO_WINDOWS_CRASH_DIALOG"] = "1"
    # apply environment modifications
    if env_mod is not None:
        assert isinstance(env_mod, dict)
        base.update(env_mod)
    # environment variables to skip if previously set in environ
    optional = (
        "_RR_TRACE_DIR",
        "MOZ_CRASHREPORTER",
        "MOZ_CRASHREPORTER_NO_DELETE_DUMP",
        "MOZ_CRASHREPORTER_NO_REPORT",
        "MOZ_CRASHREPORTER_SHUTDOWN",
        "MOZ_SKIA_DISABLE_ASSERTS",
        "RUST_BACKTRACE",
        "XPCOM_DEBUG_BREAK",
    )
    # merge presets and modifications
    for env_name, env_value in base.items():
        if env_value is None:
            if env_name in env:
                LOG.debug("removing env var %r", env_name)
                del env[env_name]
            continue
        if env_name in optional and env_name in env:
            LOG.debug("skipping optional env var %r", env_name)
            continue
        env[env_name] = env_value

    if env.get("MOZ_CRASHREPORTER_DISABLE") == "1":
        env.pop("MOZ_CRASHREPORTER", None)
        env.pop("MOZ_CRASHREPORTER_NO_DELETE_DUMP", None)
        env.pop("MOZ_CRASHREPORTER_NO_REPORT", None)
        env.pop("MOZ_CRASHREPORTER_SHUTDOWN", None)

    return _configure_sanitizers(env, target_dir, sanitizer_log)


def wait_on_files(
    procs: Iterable[Process],
    wait_files: Iterable[Path],
    poll_rate: float = 0.5,
    timeout: float = 60,
) -> bool:
    """Wait for files in wait_files to no longer be use by any process.

    Args:
        procs: Processes to scan for open files.
        wait_files: Files that must no longer be open by a process.
        poll_rate: Amount of time in seconds to wait between checks.
        timeout: Amount of time in seconds to poll.

    Returns:
        True if all files were closed within given time otherwise False.
    """
    assert poll_rate >= 0
    assert timeout >= 0
    poll_rate = min(poll_rate, timeout)
    deadline = time() + timeout
    while any(files_in_use(wait_files, procs)):
        if deadline <= time():
            LOG.debug("wait_on_files timeout (%ds)", timeout)
            break
        sleep(poll_rate)
    else:
        return True
    for entry in files_in_use(wait_files, procs):
        LOG.debug("%r open by %r (%d)", str(entry[0]), entry[2], entry[1])
    return False


def warn_open(path: str) -> None:
    """Output a message via `LOG.warning` for each file found to be open by a Process.
    On Windows open files cannot be removed. Hopefully this can be used to help identify
    the processes using the files and the underlying issue.

    Args:
        path: Path to scan for initial files.

    Returns:
        None
    """
    for entry in files_in_use(list(Path(path).iterdir()), process_iter()):
        LOG.warning("%r open by %r (%d)", str(entry[0]), entry[2], entry[1])
