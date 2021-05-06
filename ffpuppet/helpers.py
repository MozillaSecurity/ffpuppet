# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet helper utilities"""

from json import load as json_load
from logging import getLogger
from os import W_OK, access, chmod, environ, mkdir, remove, scandir
from os.path import abspath, basename, expanduser, isdir, isfile
from os.path import join as pathjoin
from os.path import normcase, realpath
from platform import system
from re import compile as re_compile
from shutil import copyfile, copytree, rmtree
from stat import S_IWUSR
from tempfile import mkdtemp
from time import sleep, time
from xml.etree import ElementTree

from psutil import AccessDenied, NoSuchProcess, Process, process_iter

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


class SanitizerConfig:  # pylint: disable=missing-docstring
    re_delim = re_compile(r":(?![\\|/])")

    __slots__ = ("_options",)

    def __init__(self):
        self._options = dict()

    def __contains__(self, item):
        return item in self._options

    def add(self, flag, value, overwrite=False):
        """Add sanitizer flag.

        Args:
            flag (str): Flags to set.
            value (str): Value to use.
            overwrite (bool): Overwrite existing value.

        Returns:
            str: Colon separated list of options.
        """
        if flag not in self._options or overwrite:
            self._options[flag] = value

    @staticmethod
    def is_quoted(token):
        """Check if token is quoted.

        Args:
            token (str): Value to check.

        Returns:
            bool: True if token is quoted otherwise False.
        """
        if token.startswith("'") and token.endswith("'"):
            return True
        if token.startswith('"') and token.endswith('"'):
            return True
        return False

    def load_options(self, options):
        """Load flags from *SAN_OPTIONS in env.

        Args:
            options (str): Colon separated list of `flag=value` pairs.

        Returns:
            None
        """
        if not options:
            return
        assert " " not in options, "*SAN_OPTIONS should not contain spaces"
        for option in self.re_delim.split(options):
            try:
                opt_name, opt_value = option.split("=")
                if ":" in opt_value:
                    assert self.is_quoted(opt_value), (
                        "%s value must be quoted" % opt_name
                    )
                # add a sanity check for suppression files
                if opt_name == "suppressions":
                    sup_file = abspath(expanduser(opt_value.strip("'\"")))
                    if not isfile(sup_file):
                        raise IOError("Suppressions file %r does not exist" % sup_file)
                    opt_value = "'%s'" % sup_file
                self._options[opt_name] = opt_value
            except ValueError:
                LOG.warning("Malformed option %r", option)

    @property
    def options(self):
        """Join all flag and value pairs for use with *SAN_OPTIONS.

        Args:
            None

        Returns:
            str: Colon separated list of options.
        """
        return ":".join("=".join(kv) for kv in self._options.items())


def append_prefs(profile_path, prefs):
    """Write or append preferences from prefs to prefs.js file in profile_path.

    Args:
        profile_path (str): Directory containing prefs.js file to write to.
        prefs (dict): preferences to add.

    Returns:
        None
    """
    assert isinstance(prefs, dict)
    with open(pathjoin(profile_path, "prefs.js"), "a") as prefs_fp:
        # make sure there is a newline before appending to prefs.js
        prefs_fp.write("\n")
        for name, value in prefs.items():
            prefs_fp.write("user_pref('%s', %s);\n" % (name, value))


def check_prefs(prof_prefs, input_prefs):
    """Check that the given prefs.js file in use by the browser contains all
    the requested preferences.
    NOTE: There will be false positives if input_prefs does not adhere to the
    formatting that is used in prefs.js file generated by the browser.

    Args:
        prof_prefs (str): Path to profile prefs.js file.
        input_prefs (str): Path to prefs.js file that contains prefs that
                           should be merged into the prefs.js file generated by
                           the browser.

    Returns:
        bool: True if all expected preferences are found otherwise False.
    """
    with open(prof_prefs, "r") as p_fp, open(input_prefs, "r") as i_fp:
        p_prefs = {pref.split(",")[0] for pref in p_fp if pref.startswith("user_pref(")}
        i_prefs = {pref.split(",")[0] for pref in i_fp if pref.startswith("user_pref(")}
    missing_prefs = i_prefs - p_prefs
    for missing in missing_prefs:
        LOG.debug("pref not set %r", missing)
    return not missing_prefs


def configure_sanitizers(env, target_dir, log_path):
    """Update *SAN_OPTIONS entries in env.

    Args:
        target_dir (str): Location to find llvm-symbolizer.
        log_path (str): Location to write sanitizer logs to.

    Returns:
        None
    """
    # https://github.com/google/sanitizers/wiki/SanitizerCommonFlags
    common_flags = (
        ("abort_on_error", "false"),
        ("allocator_may_return_null", "true"),
        ("disable_coredump", "true"),
        ("exitcode", "77"),  # use unique exitcode to help identify missed reports
        ("handle_abort", "true"),  # if true, abort_on_error=false to prevent hangs
        ("handle_sigbus", "true"),  # set to be safe
        ("handle_sigfpe", "true"),  # set to be safe
        ("handle_sigill", "true"),  # set to be safe
        # ("max_allocation_size_mb", "256"),
        ("symbolize", "true"),
    )

    # setup Address Sanitizer options if not set manually
    # https://github.com/google/sanitizers/wiki/AddressSanitizerFlags
    asan_config = SanitizerConfig()
    asan_config.load_options(env.get("ASAN_OPTIONS"))
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
    asan_config.add("log_path", "'%s'" % log_path, overwrite=True)
    # attempt to save some memory during deep stack allocations
    asan_config.add("malloc_context_size", "20")
    asan_config.add("sleep_before_dying", "0")
    asan_config.add("strict_init_order", "true")
    # breaks old builds (esr52)
    asan_config.add("strict_string_checks", "true")
    env["ASAN_OPTIONS"] = asan_config.options

    # setup Leak Sanitizer options if not set manually
    # https://github.com/google/sanitizers/wiki/AddressSanitizerLeakSanitizer
    lsan_config = SanitizerConfig()
    lsan_config.load_options(env.get("LSAN_OPTIONS"))
    lsan_config.add("max_leaks", "1")
    lsan_config.add("print_suppressions", "false")
    env["LSAN_OPTIONS"] = lsan_config.options

    # setup Thread Sanitizer options if not set manually
    tsan_config = SanitizerConfig()
    tsan_config.load_options(env.get("TSAN_OPTIONS"))
    tsan_config.add("halt_on_error", "1")
    if "log_path" in tsan_config:
        LOG.warning(
            "TSAN_OPTIONS=log_path is used internally and cannot be set externally"
        )
    tsan_config.add("log_path", "'%s'" % log_path, overwrite=True)
    env["TSAN_OPTIONS"] = tsan_config.options

    # setup Undefined Behavior Sanitizer options if not set manually
    ubsan_config = SanitizerConfig()
    ubsan_config.load_options(env.get("UBSAN_OPTIONS"))
    for flag in common_flags:
        ubsan_config.add(*flag)
    if "log_path" in ubsan_config:
        LOG.warning(
            "UBSAN_OPTIONS=log_path is used internally and cannot be set externally"
        )
    ubsan_config.add("log_path", "'%s'" % log_path, overwrite=True)
    ubsan_config.add("print_stacktrace", "1")
    env["UBSAN_OPTIONS"] = ubsan_config.options

    if "ASAN_SYMBOLIZER_PATH" not in env:
        # ASAN_SYMBOLIZER_PATH only needs to be set on platforms other than Windows
        if not system().lower().startswith("windows"):
            symbolizer_bin = pathjoin(target_dir, "llvm-symbolizer")
            if isfile(symbolizer_bin):
                env["ASAN_SYMBOLIZER_PATH"] = symbolizer_bin
        elif not pathjoin(target_dir, "llvm-symbolizer.exe"):
            LOG.warning("llvm-symbolizer.exe should be next to the target binary")
    elif "ASAN_SYMBOLIZER_PATH" in env and not isfile(env["ASAN_SYMBOLIZER_PATH"]):
        LOG.warning("Invalid ASAN_SYMBOLIZER_PATH (%s)", env["ASAN_SYMBOLIZER_PATH"])


def create_profile(extension=None, prefs_js=None, template=None):
    """Create a profile to be used with Firefox.

    Args:
        extension (str): Path to an extension to be installed.
        prefs_js (str): Path to the prefs.js file to install in the profile.
        template (str): Path to an existing profile directory to use.

    Returns:
        str: Path to directory to be used as a profile.
    """
    profile = mkdtemp(prefix="ffprof_")
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
                    times_fp.write('{"created":%d}' % (int(time()) * 1000))
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
                            manifest = json_load(manifest)
                        ext_name = manifest["applications"]["gecko"]["id"]
                    except (IOError, KeyError, ValueError) as exc:
                        LOG.debug("Failed to parse manifest.json: %s", exc)
                elif isfile(pathjoin(ext, "install.rdf")):
                    try:
                        xmlns = {
                            "x": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                            "em": "http://www.mozilla.org/2004/em-rdf#",
                        }
                        tree = ElementTree.parse(pathjoin(ext, "install.rdf"))
                        assert tree.getroot().tag == "{%s}RDF" % xmlns["x"]
                        ids = tree.findall("./x:Description/em:id", namespaces=xmlns)
                        assert len(ids) == 1
                        ext_name = ids[0].text
                    except (AssertionError, IOError, ElementTree.ParseError) as exc:
                        LOG.debug("Failed to parse install.rdf: %s", exc)
                if ext_name is None:
                    raise RuntimeError(
                        "Failed to find extension id in manifest: %r" % ext
                    )
                copytree(abspath(ext), pathjoin(profile, "extensions", ext_name))
            else:
                raise RuntimeError("Unknown extension: %r" % ext)
    except Exception:
        # cleanup on failure
        rmtree(profile, True)
        raise
    return profile


def files_in_use(check_files, path_fix, procs):
    """Check if any of the given files are open by any of the given processes.

    Args:
        check_files (iterable(str)): Files path to check.
        path_fix (callable): Function to format paths.
        procs (iterable(Process)): Processes to scan for open files.

    Yields:
        tuple: Path of file, pid of process and process name.
    """
    if check_files:
        for proc in procs:
            try:
                # WARNING: Process.open_files() has issues on Windows!
                # https://psutil.readthedocs.io/en/latest/#psutil.Process.open_files
                proc_files = tuple(path_fix(x.path) for x in proc.open_files())
                if proc_files:
                    for efile in check_files:
                        if efile in proc_files:
                            yield efile, proc.pid, proc.name()
            except (AccessDenied, NoSuchProcess):  # pragma: no cover
                pass


def get_processes(pid, recursive=True):
    """From a given PID create a psutil.Process object and lookup all of its
    children.

    Args:
        pid (int): PID of the process to lookup.
        recursive (bool): Include the children (and so on) of the Process
                          that was created.

    Returns:
        list: A list of psutil.Process objects. The first object will always
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


def onerror(func, path, _exc_info):  # pragma: no cover
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


def prepare_environment(target_dir, sanitizer_log, env_mod=None):
    """Create environment that can be used when launching the browser.

    Args:
        target_dir (str): Path to the directory containing the Firefox binary.
        sanitizer_log (str): Location to write sanitizer logs. Log prefix set
                             with ASAN_OPTIONS=log_path=<sanitizer_log>.
        env_mod (dict): Environment modifier. Add, remove and update entries
                        in the prepared environment. Add and update by setting
                        value (str) and remove by setting entry value to None.

    Returns:
        dict: Environment to use when launching browser.
    """
    base = dict()
    env = dict(environ)

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

    configure_sanitizers(env, target_dir, sanitizer_log)

    return env


def true_path(path):
    """Use realpath() and normcase() on path for cross platform compatibility.

    Args:
        path (str): File or directory path.

    Returns:
        str: Normalized real path of given path.
    """
    return normcase(realpath(path))


def wait_on_files(procs, wait_files, poll_rate=0.25, timeout=60):
    """Wait for files in wait_files to no longer be use by any process.

    Args:
        procs (iterable(Process)): Processes to scan for open files.
        wait_files (iterable(str)): Files that must no longer be open by a process.
        poll_rate (float): Amount of time in seconds to wait between checks.
        timeout (int): Amount of time in seconds to poll.

    Returns:
        str: True if all files were closed within given time otherwise False.
    """
    assert poll_rate >= 0
    assert timeout >= 0
    wait_files = {true_path(x) for x in wait_files if isfile(x)}
    if not wait_files:
        return True
    poll_rate = min(poll_rate, timeout)
    deadline = time() + timeout
    while any(files_in_use(wait_files, true_path, procs)):
        if deadline <= time():
            LOG.debug("wait_on_files timeout (%ds)", timeout)
            break
        sleep(poll_rate)
    else:
        return True
    for entry in files_in_use(wait_files, true_path, procs):
        LOG.debug("%r open by %r (%d)", entry[0], entry[2], entry[1])
    return False


def warn_open(path):
    """Output a message via `LOG.warning` for each file found to be open by a Process.
    On Windows open files cannot be removed. Hopefully this can be used to help identify
    the processes using the files and the underlying issue.

    Args:
        path (str): Path to scan for initial files.

    Returns:
        None
    """
    check = tuple(abspath(x.path) for x in scandir(path))
    for entry in files_in_use(check, abspath, process_iter()):
        LOG.warning("%s open by %r (%d)", entry[0], entry[2], entry[1])
