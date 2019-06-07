# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import errno
import json
import logging
import os
import platform
import random
import re
import shutil
import socket
import stat
import tempfile
import time

from xml.etree import ElementTree
import psutil

from .exceptions import BrowserTerminatedError, BrowserTimeoutError, LaunchError


log = logging.getLogger("ffpuppet")  # pylint: disable=invalid-name

__author__ = "Tyson Smith"
__all__ = ("check_prefs", "create_profile", "get_processes", "onerror",
           "prepare_environment", "wait_on_files")


class SanitizerConfig(object):
    re_delim = re.compile(r":(?![\\|/])")

    def __init__(self):
        self._options = dict()

    def __contains__(self, item):
        return item in self._options

    def add(self, key, value, overwrite=False):
        if key not in self._options or overwrite:
            self._options[key] = value

    @staticmethod
    def is_quoted(token):
        if token.startswith("'") and token.endswith("'"):
            return True
        if token.startswith("\"") and token.endswith("\""):
            return True
        return False

    def load_options(self, env, key):
        assert isinstance(env, dict)
        if key not in env:
            return
        assert " " not in env[key], "%s should not contain spaces, join options with ':'" % key
        for option in self.re_delim.split(env[key]):
            try:
                opt_name, opt_value = option.split("=")
                if ":" in opt_value:
                    assert self.is_quoted(opt_value), "%s value must be quoted" % opt_name
                # add a sanity check for suppression files
                if opt_name == "suppressions":
                    sup_file = os.path.abspath(os.path.expanduser(opt_value.strip("'\"")))
                    if not os.path.isfile(sup_file):
                        raise IOError("Suppressions file %r does not exist" % sup_file)
                    opt_value = "'%s'" % sup_file
                self._options[opt_name] = opt_value
            except ValueError:
                log.warning("Malformed option in %r", key)

    @property
    def options(self):
        return ":".join("=".join([k, v]) for k, v in self._options.items())


class Bootstrapper(object):
    PORT_MAX = 0xFFFF  # bootstrap range
    PORT_MIN = 0x2000  # bootstrap range
    PORT_RETRIES = 100  # number of attempts to find an available port

    def __init__(self, poll_wait=0.25):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if platform.system().lower().startswith("windows"):
            self._socket.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_EXCLUSIVEADDRUSE,  # pylint: disable=no-member
                1)
        self._socket.settimeout(poll_wait)
        for _ in range(self.PORT_RETRIES):
            try:
                self._socket.bind(("127.0.0.1", random.randint(self.PORT_MIN, self.PORT_MAX)))
                self._socket.listen(5)
                break
            except socket.error as soc_e:
                if soc_e.errno in (errno.EADDRINUSE, 10013):
                    # Address already in use
                    continue
                raise soc_e  # pragma: no cover
        else:
            self._socket.close()
            raise LaunchError("Could not find available port")


    def close(self):
        if self._socket is not None:
            self._socket.close()
            self._socket = None


    @property
    def location(self):
        assert self._socket is not None
        return "http://127.0.0.1:%d" % self.port


    @property
    def port(self):
        assert self._socket is not None
        return self._socket.getsockname()[1]


    def wait(self, cb_continue, timeout=60, url=None):
        assert self._socket is not None
        conn = None
        start_time = time.time()
        time_limit = start_time + timeout
        try:
            # wait for browser connection
            while conn is None:
                try:
                    conn, _ = self._socket.accept()
                except socket.timeout:
                    if time.time() >= time_limit:
                        raise BrowserTimeoutError("Launching browser timed out (%ds)" % timeout)
                    if not cb_continue():
                        raise BrowserTerminatedError("Failure during browser startup")
                    # browser is alive but we have not received a connection
                    conn = None

            log.debug("waiting to receive browser request")
            buf_size = 4096
            received = False
            conn.settimeout(0.5)
            while True:
                try:
                    request = conn.recv(buf_size)
                except socket.timeout:
                    request = None
                if request or received:
                    if request is None:
                        log.debug("timeout waiting for more request data")
                        break
                    if len(request) < buf_size:
                        break
                    # handle receiving exactly 'buf_size' amount of data
                    received = True
                    continue
                if not cb_continue():
                    raise BrowserTerminatedError("Failure waiting for request")
                if time.time() >= time_limit:
                    raise BrowserTimeoutError("Timed out (%ds) waiting for request" % timeout)

            log.debug("sending response (redirect %r)", url)
            if url is None:
                resp = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
            else:
                resp = "HTTP/1.1 301 Moved Permanently\r\n" \
                       "Location: %s\r\n" \
                       "Connection: close\r\n\r\n" % url
            conn.settimeout(max(int(time_limit - time.time()), 1))
            conn.sendall(resp.encode("ascii"))
            log.debug("bootstrap complete (%0.2fs)", (time.time() - start_time))

        except socket.error as soc_e:
            raise LaunchError("Failed to launch browser: %s" % soc_e)

        except socket.timeout:
            raise BrowserTimeoutError("Connection timed out (%ds)" % timeout)

        finally:
            if conn is not None:
                conn.close()


def append_prefs(profile_path, prefs):
    assert isinstance(prefs, dict)
    with open(os.path.join(profile_path, "prefs.js"), "a") as prefs_fp:
        prefs_fp.write("\n")  # make sure there is a newline before appending to prefs.js
        for name, value in prefs.items():
            prefs_fp.write("user_pref('%s', %s);\n" % (name, value))


def check_prefs(prof_prefs, input_prefs):
    """
    Check that the current prefs.js file in use by the browser contains all the requested prefs.

    NOTE: There will be false positives if input_prefs does not adhere to the formatting that
    is used in prefs.js file generated by the browser.

    @type prof_prefs: String
    @param prof_prefs: Path to profile prefs.js file

    @type input_prefs: String
    @param input_prefs: Path to prefs.js file that contains prefs that should be merged
                        into the prefs.js file generated by the browser

    @rtype: bool
    @return: True if all prefs in input_prefs are merged otherwise False
    """

    if not os.path.isfile(input_prefs):
        raise IOError("Cannot find %r" % input_prefs)
    if not os.path.isfile(prof_prefs):
        raise IOError("Cannot find %r" % prof_prefs)

    with open(prof_prefs, "r") as p_fp, open(input_prefs, "r") as i_fp:
        p_prefs = {pref.split(",")[0] for pref in p_fp if pref.startswith("user_pref(")}
        i_prefs = {pref.split(",")[0] for pref in i_fp if pref.startswith("user_pref(")}

    missing_prefs = i_prefs - p_prefs
    log.debug(
        "prefs not set %r",
        ", ".join([m_pref.lstrip("user_pref(") for m_pref in missing_prefs]))

    return not missing_prefs


def configure_sanitizers(env, target_dir, log_path):
    # setup Address Sanitizer options if not set manually
    # https://github.com/google/sanitizers/wiki/AddressSanitizerFlags
    # https://github.com/google/sanitizers/wiki/SanitizerCommonFlags
    asan_config = SanitizerConfig()
    asan_config.load_options(env, "ASAN_OPTIONS")
    asan_config.add("abort_on_error", "false")
    #asan_config.add("alloc_dealloc_mismatch", "false")  # different defaults per OS
    asan_config.add("allocator_may_return_null", "true")
    asan_config.add("check_initialization_order", "true")
    #asan_config.add("detect_stack_use_after_return", "true")  # https://bugzil.la/1057551
    #asan_config.add("detect_stack_use_after_scope", "true")
    asan_config.add("detect_invalid_pointer_pairs", "1")
    asan_config.add("detect_leaks", "false")
    asan_config.add("disable_coredump", "true")
    # if handle_abort is true abort_on_error should be false to prevent hangs
    asan_config.add("handle_abort", "true")
    asan_config.add("handle_sigbus", "true")  # set to be safe
    asan_config.add("handle_sigfpe", "true")  # set to be safe
    asan_config.add("handle_sigill", "true")  # set to be safe
    # log_path is required for FFPuppet logging to function properly
    if "log_path" in asan_config:
        log.warning("ASAN_OPTIONS=log_path is used internally and cannot be set externally")
    asan_config.add("log_path", "'%s'" % log_path, overwrite=True)
    # attempt to save some memory during deep stack allocations
    asan_config.add("malloc_context_size", "20")
    asan_config.add("sleep_before_dying", "0")
    asan_config.add("strict_init_order", "true")
    #asan_config.add("strict_string_checks", "true") # breaks old builds (esr52)
    asan_config.add("symbolize", "true")
    env["ASAN_OPTIONS"] = asan_config.options

    # setup Leak Sanitizer options if not set manually
    # https://github.com/google/sanitizers/wiki/AddressSanitizerLeakSanitizer
    lsan_config = SanitizerConfig()
    lsan_config.load_options(env, "LSAN_OPTIONS")
    lsan_config.add("max_leaks", "1")
    lsan_config.add("print_suppressions", "false")
    env["LSAN_OPTIONS"] = lsan_config.options

    # setup Undefined Behavior Sanitizer options if not set manually
    ubsan_config = SanitizerConfig()
    ubsan_config.load_options(env, "UBSAN_OPTIONS")
    if "log_path" in ubsan_config:
        log.warning("UBSAN_OPTIONS=log_path is used internally and cannot be set externally")
    ubsan_config.add("log_path", "'%s'" % log_path, overwrite=True)
    ubsan_config.add("print_stacktrace", "1")
    env["UBSAN_OPTIONS"] = ubsan_config.options

    if "ASAN_SYMBOLIZER_PATH" not in env:
        # ASAN_SYMBOLIZER_PATH only needs to be set on platforms other than Windows
        if not platform.system().lower().startswith("windows"):
            symbolizer_bin = os.path.join(target_dir, "llvm-symbolizer")
            if os.path.isfile(symbolizer_bin):
                env["ASAN_SYMBOLIZER_PATH"] = symbolizer_bin
        elif not os.path.join(target_dir, "llvm-symbolizer.exe"):
            log.warning("llvm-symbolizer.exe should be next to the target binary")
    elif "ASAN_SYMBOLIZER_PATH" in env and not os.path.isfile(env["ASAN_SYMBOLIZER_PATH"]):
        log.warning("Invalid ASAN_SYMBOLIZER_PATH (%s)", env["ASAN_SYMBOLIZER_PATH"])


def create_profile(extension=None, prefs_js=None, template=None):
    """
    Create a profile to be used with Firefox

    @type extension: String, or list of Strings
    @param extension: Path to an extension (e.g. DOMFuzz fuzzPriv extension) to be installed.

    @type prefs_js: String
    @param prefs_js: Path to a prefs.js file to install in the Firefox profile.

    @type template: String
    @param template: Path to an existing profile directory to use.

    @rtype: String
    @return: Path to directory to be used as a profile
    """

    profile = tempfile.mkdtemp(prefix="ffprof_")
    log.debug("profile directory: %r", profile)

    if template is not None:
        log.debug("using profile template: %r", template)
        shutil.rmtree(profile) # reuse the directory name
        if not os.path.isdir(template):
            raise IOError("Cannot find template profile: %r" % template)
        shutil.copytree(template, profile)
        invalid_prefs = os.path.join(profile, "Invalidprefs.js")
        # if Invalidprefs.js was copied from the template profile remove it
        if os.path.isfile(invalid_prefs):
            os.remove(invalid_prefs)

    if prefs_js is not None:
        log.debug("using prefs.js: %r", prefs_js)
        if not os.path.isfile(prefs_js):
            shutil.rmtree(profile, True) # clean up on failure
            raise IOError("prefs.js file does not exist: %r" % prefs_js)
        shutil.copyfile(prefs_js, os.path.join(profile, "prefs.js"))

        # times.json only needs to be created when using a custom pref.js
        times_json = os.path.join(profile, "times.json")
        if not os.path.isfile(times_json):
            with open(times_json, "w") as times_fp:
                times_fp.write('{"created":%d}' % (int(time.time()) * 1000))

    # extension support
    try:
        if extension is None:
            extensions = []
        elif isinstance(extension, (list, tuple)):
            extensions = extension
        else:
            extensions = [extension]
        if extensions and not os.path.isdir(os.path.join(profile, "extensions")):
            os.mkdir(os.path.join(profile, "extensions"))
        for ext in extensions:
            if os.path.isfile(ext) and ext.endswith(".xpi"):
                shutil.copyfile(
                    ext,
                    os.path.join(profile, "extensions", os.path.basename(ext)))
            elif os.path.isdir(ext):
                # read manifest to see what the folder should be named
                ext_name = None
                if os.path.isfile(os.path.join(ext, "manifest.json")):
                    try:
                        with open(os.path.join(ext, "manifest.json")) as manifest:
                            manifest = json.load(manifest)
                        ext_name = manifest["applications"]["gecko"]["id"]
                    except (IOError, KeyError, ValueError) as exc:
                        log.debug("Failed to parse manifest.json: %s", exc)
                elif os.path.isfile(os.path.join(ext, "install.rdf")):
                    try:
                        xmlns = {"x": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                                 "em": "http://www.mozilla.org/2004/em-rdf#"}
                        tree = ElementTree.parse(os.path.join(ext, "install.rdf"))
                        assert tree.getroot().tag == "{%s}RDF" % xmlns["x"]
                        ids = tree.findall("./x:Description/em:id", namespaces=xmlns)
                        assert len(ids) == 1
                        ext_name = ids[0].text
                    except (AssertionError, IOError, ElementTree.ParseError) as exc:
                        log.debug("Failed to parse install.rdf: %s", exc)
                if ext_name is None:
                    raise RuntimeError("Failed to find extension id in manifest: %r" % ext)
                shutil.copytree(
                    os.path.abspath(ext),
                    os.path.join(profile, "extensions", ext_name))
            else:
                raise RuntimeError("Unknown extension: %r" % ext)
    except:
        shutil.rmtree(profile, True) # cleanup on failure
        raise
    return profile


def get_processes(pid, recursive=True):
    """
    From a given PID create a psutil.Process object and lookup all of it's
    children.

    @type pid: int
    @param pid: PID of the process to lookup

    @type recursive: bool
    @param recursive: Include the children (and so on) of the Process
                      that was created.

    @rtype: list
    @return: A list of psutil.Process objects. The first object will always
             be the Process that corresponds to PID
    """
    try:
        procs = [psutil.Process(pid)]
    except psutil.NoSuchProcess:
        return list()
    if not recursive:
        return procs
    try:
        procs += procs[0].children(recursive=True)
    except (psutil.AccessDenied, psutil.NoSuchProcess):  # pragma: no cover
        pass
    return procs


def onerror(func, path, _exc_info):
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
    if not os.access(path, os.W_OK):
        # Is the error an access error?
        os.chmod(path, stat.S_IWUSR)
        func(path)
    else:
        # this should only ever be called from an exception context
        raise  # pylint: disable=misplaced-bare-raise


def prepare_environment(target_dir, sanitizer_log, env_mod=None):
    """
    Get environment that can be used when launching the browser.

    @type target_dir: String
    @param target_dir: Path to the directory containing the Firefox binary

    @type sanitizer_log: String
    @param sanitizer_log: Log prefix set with ASAN_OPTIONS=log_path=<sanitizer_log>

    @type env_mod: dict
    @param env_mod: Environment modifier. Add, remove and update entries in the prepared
                    environment via this dict. Add and update using key, value pairs where
                    value is a string and to remove set the value to None. If it is None no
                    extra modifications are made.

    @rtype: dict
    @return: A dict representing the string environment
    """
    base = dict()
    env = dict(os.environ)

    # https://developer.gimp.org/api/2.0/glib/glib-running.html#G_SLICE
    base["G_SLICE"] = "always-malloc"
    base["MOZ_AUTOMATION"] = "1"
    base["MOZ_CC_RUN_DURING_SHUTDOWN"] = "1"
    base["MOZ_CRASHREPORTER"] = "1"
    base["MOZ_CRASHREPORTER_NO_REPORT"] = "1"
    base["MOZ_DISABLE_CONTENT_SANDBOX"] = "1"
    base["MOZ_DISABLE_GMP_SANDBOX"] = "1"
    base["MOZ_DISABLE_GPU_SANDBOX"] = "1"
    base["MOZ_DISABLE_NPAPI_SANDBOX"] = "1"
    base["MOZ_DISABLE_PDFIUM_SANDBOX"] = "1"
    base["MOZ_DISABLE_RDD_SANDBOX"] = "1"
    base["MOZ_DISABLE_VR_SANDBOX"] = "1"
    base["MOZ_GDB_SLEEP"] = "0"
    # https://bugzilla.mozilla.org/show_bug.cgi?id=1305151
    # skia assertions are easily hit and mostly due to precision, disable them.
    base["MOZ_SKIA_DISABLE_ASSERTS"] = "1"
    base["RUST_BACKTRACE"] = "full"
    base["XPCOM_DEBUG_BREAK"] = "warn"
    base["XRE_NO_WINDOWS_CRASH_DIALOG"] = "1"

    if env_mod is not None:
        assert isinstance(env_mod, dict)
        base.update(env_mod)

    # environment variable to skip if previously set in environ
    optional = (
        "_RR_TRACE_DIR", "MOZ_CRASHREPORTER", "MOZ_CRASHREPORTER_NO_REPORT",
        "MOZ_CRASHREPORTER_SHUTDOWN", "MOZ_SKIA_DISABLE_ASSERTS", "RUST_BACKTRACE")
    # merge presets and modifications
    for env_name, env_value in base.items():
        if env_value is None:
            if env_name in env:
                log.debug("removing env var %r", env_name)
                del env[env_name]
            continue
        if env_name in optional and env_name in env:
            log.debug("skipping optional env var %r", env_name)
            continue
        env[env_name] = env_value

    if env.get("MOZ_CRASHREPORTER_DISABLE") == "1":
        env.pop("MOZ_CRASHREPORTER", None)
        env.pop("MOZ_CRASHREPORTER_NO_REPORT", None)
        env.pop("MOZ_CRASHREPORTER_SHUTDOWN", None)

    configure_sanitizers(env, target_dir, sanitizer_log)

    return env


def true_path(path):
    """
    Use realpath() and normcase() on path for cross platform compatibility.

    @type path: String
    @param path: File or directory path

    @rtype: String
    @return: Normalized real path of given path
    """
    return os.path.normcase(os.path.realpath(path))


def wait_on_files(wait_files, poll_rate=0.25, timeout=60):
    """
    Wait for all processes to no longer be using any file in wait_files

    @type wait_files: iterable
    @param wait_files: Files that must no longer be open by a process

    @type poll_rate: float
    @param poll_rate: Amount of time in seconds to wait between checks

    @type timeout: float
    @param timeout: Amount of time in seconds to poll

    @rtype: bool
    @return: True if all files were closed within timeout else False
    """
    assert poll_rate >= 0, "Invalid poll_rate %d, must be greater than or equal to 0" % poll_rate
    assert timeout >= 0, "Invalid timeout %d, must be greater than or equal to 0" % timeout
    poll_rate = min(poll_rate, timeout)
    wait_files = {true_path(x) for x in wait_files if os.path.isfile(x)}
    if not wait_files:
        return True
    deadline = time.time() + timeout
    # collect all blocking processes
    procs = list()
    for proc in psutil.process_iter(attrs=["pid", "open_files"]):
        if not proc.info["open_files"]:
            continue
        # WARNING: Process.open_files() has issues on Windows!
        # https://psutil.readthedocs.io/en/latest/#psutil.Process.open_files
        if wait_files.intersection({true_path(x.path) for x in proc.info["open_files"]}):
            try:
                procs.append(psutil.Process(proc.info["pid"]))
            except psutil.NoSuchProcess:  # pragma: no cover
                pass
    # only check previously blocking processes
    while procs:
        try:
            if wait_files.intersection({true_path(x.path) for x in procs[-1].open_files()}):
                if deadline <= time.time():
                    log.debug("wait_on_files(timeout=%d) timed out", timeout)
                    return False
                time.sleep(poll_rate)
                continue
        except (psutil.AccessDenied, psutil.NoSuchProcess):  # pragma: no cover
            pass
        procs.pop()
    return True
