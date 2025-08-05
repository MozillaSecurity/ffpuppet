# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet helper utilities"""

from __future__ import annotations

import sys
from contextlib import suppress
from logging import getLogger
from mmap import ACCESS_READ, mmap
from os import environ
from pathlib import Path
from subprocess import STDOUT, CalledProcessError, check_output
from time import perf_counter, sleep
from typing import TYPE_CHECKING

from psutil import AccessDenied, NoSuchProcess, Process, process_iter

from .sanitizer_util import SanitizerOptions

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable, Mapping

if sys.platform == "win32":
    from .lsof import pids_by_file

    IS_WINDOWS = True
else:
    IS_WINDOWS = False

__author__ = "Tyson Smith"

CERTUTIL = "certutil.exe" if IS_WINDOWS else "certutil"
LOG = getLogger(__name__)


def _configure_sanitizers(
    orig_env: Mapping[str, str],
    log_path: Path,
    symbolize: bool = False,
) -> dict[str, str]:
    """Copy environment and update default values in *SAN_OPTIONS entries.
    These values are only updated if they are not provided, with the exception of
    'log_path'. 'log_path' is used by FFPuppet to detect results.

    Args:
        orig_env: Current environment.
        log_path: Location to write sanitizer logs to.
        symbolize: Enable automatic symbolizing. This should only used when required to
            minimize memory usage.

    Returns:
        Environment with *SAN_OPTIONS defaults set.
    """
    env = dict(orig_env)
    # https://github.com/google/sanitizers/wiki/SanitizerCommonFlags
    common_flags = (
        ("abort_on_error", "false"),
        ("allocator_may_return_null", "true"),
        ("disable_coredump", "true"),
        # use unique exitcode to help identify missed reports
        ("exitcode", "77"),
        # if true, abort_on_error=false to prevent hangs
        ("handle_abort", "true"),
        # set to be safe
        ("handle_sigbus", "true"),
        # set to be safe
        ("handle_sigfpe", "true"),
        # set to be safe
        ("handle_sigill", "true"),
    )

    # setup Address Sanitizer options ONLY if not set manually in environment
    # https://github.com/google/sanitizers/wiki/AddressSanitizerFlags
    asan_config = SanitizerOptions(env.get("ASAN_OPTIONS"))
    assert asan_config.check_path("suppressions"), "missing suppressions file"
    for flag in common_flags:
        asan_config.add(*flag)
    # different defaults per OS
    # asan_config.add("alloc_dealloc_mismatch", "false")
    asan_config.add("check_initialization_order", "true")
    # stack UAR detection works as of clang 18
    asan_config.add("detect_stack_use_after_return", "true")
    # asan_config.add("detect_stack_use_after_scope", "true")
    asan_config.add("detect_invalid_pointer_pairs", "1")
    asan_config.add("detect_leaks", "false")
    # hard_rss_limit_mb requires background thread so only works on Linux for now...
    # see https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/
    # sanitizer_common/sanitizer_common_libcdep.cpp#L116
    asan_config.add("hard_rss_limit_mb", "12288")
    # log_path is required for FFPuppet logging to function properly
    if "log_path" in asan_config:
        LOG.warning(
            "ASAN_OPTIONS=log_path is used internally and cannot be set externally"
        )
    asan_config.add("log_path", f"'{log_path}'", overwrite=True)
    # This is an experimental feature added in Bug 1792757
    asan_config.add("rss_limit_heap_profile", "true")
    asan_config.add("sleep_before_dying", "0")
    asan_config.add("strict_init_order", "true")
    # temporarily revert to default (false) until https://bugzil.la/1767068 is fixed
    # asan_config.add("strict_string_checks", "true")
    asan_config.add("symbolize", "1" if symbolize else "0")
    env["ASAN_OPTIONS"] = str(asan_config)

    # setup Leak Sanitizer options ONLY if not set manually in environment
    # https://github.com/google/sanitizers/wiki/AddressSanitizerLeakSanitizer
    lsan_config = SanitizerOptions(env.get("LSAN_OPTIONS"))
    assert lsan_config.check_path("suppressions"), "missing suppressions file"
    lsan_config.add("max_leaks", "1")
    lsan_config.add("print_suppressions", "false")
    # helpful with rr/Pernosco sessions
    lsan_config.add("report_objects", "1")
    env["LSAN_OPTIONS"] = str(lsan_config)

    # setup Thread Sanitizer options ONLY if not set manually in environment
    tsan_config = SanitizerOptions(env.get("TSAN_OPTIONS"))
    assert tsan_config.check_path("suppressions"), "missing suppressions file"
    tsan_config.add("halt_on_error", "1")
    # hard_rss_limit_mb requires background thread so only works on Linux for now...
    # see https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/
    # sanitizer_common/sanitizer_common_libcdep.cpp#L116
    tsan_config.add("hard_rss_limit_mb", "12288")
    if "log_path" in tsan_config:
        LOG.warning(
            "TSAN_OPTIONS=log_path is used internally and cannot be set externally"
        )
    tsan_config.add("log_path", f"'{log_path}'", overwrite=True)
    # This is an experimental feature added in Bug 1792757
    tsan_config.add("rss_limit_heap_profile", "true")
    tsan_config.add("symbolize", "1" if symbolize else "0")
    env["TSAN_OPTIONS"] = str(tsan_config)

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
    ubsan_config.add("symbolize", "1" if symbolize else "0")
    env["UBSAN_OPTIONS"] = str(ubsan_config)

    return env


def certutil_available(certutil: str) -> bool:
    """Check if NSS certutil is available.

    Args:
        certutil: certutil location.

    Returns:
        True if certutil is available for use otherwise False.
    """
    try:
        check_output([certutil], stderr=STDOUT, timeout=60)
    except CalledProcessError as exc:
        # there are multiple "certutil" tools and one is installed on Windows by default
        # check the help output to make sure we have the correct tool
        if (
            exc.output
            and b"Utility to manipulate NSS certificate databases" in exc.output
        ):
            return True
    except OSError as exc:
        LOG.debug(str(exc))
    LOG.debug("'%s' is not suitable for use", certutil)
    return False


def certutil_find(browser_bin: Path | None = None) -> str:
    """Look for NSS certutil in known location or fallback to built-in tool.

    Args:
        browser_bin: Location of browser binary.

    Returns:
        Path to certutil tool to use.
    """
    if browser_bin:
        path = browser_bin.parent / "bin" / CERTUTIL
        if path.is_file():
            return str(path.resolve())
    return CERTUTIL


def detect_sanitizer(binary: Path) -> str | None:
    """Detect sanitizer instrumentation in browser build.

    Args:
        binary: Location of browser binary.

    Returns:
        Name of sanitizer in use or None.
    """
    with (
        binary.open("rb") as bin_fp,
        mmap(bin_fp.fileno(), 0, access=ACCESS_READ) as bmm,
    ):
        if bmm.find(b"__tsan_") != -1:
            return "tsan"
        if bmm.find(b"__asan_") != -1:
            return "asan"
        if bmm.find(b"__ubsan_") != -1:
            return "ubsan"
    return None


def files_in_use(files: Iterable[Path]) -> Generator[tuple[Path, int, str]]:
    """Check if any of the given files are open.
    WARNING: This can be slow on Windows.

    Args:
        files: Files to check.

    Yields:
        Path of file, process ID and process name.
    """
    # only check existing file
    files = tuple(x for x in files if x.exists())
    if files:
        # WARNING: Process.open_files() has issues on Windows!
        # https://psutil.readthedocs.io/en/latest/#psutil.Process.open_files
        # use an alternative implementation instead
        if sys.platform == "win32":
            for open_file, pids in pids_by_file().items():
                for check_file in files:
                    # samefile() can raise if either file cannot be accessed
                    # this is triggered on Windows if a file is missing
                    with suppress(OSError):
                        if check_file.samefile(open_file):
                            for pid in pids:
                                with suppress(AccessDenied, NoSuchProcess):
                                    yield open_file, pid, Process(pid).name()
        else:
            for proc in process_iter(["pid", "name", "open_files"]):
                if not proc.info["open_files"]:
                    continue
                for open_file in (Path(x.path) for x in proc.info["open_files"]):
                    for check_file in files:
                        # samefile() can raise if either file cannot be accessed
                        with suppress(OSError):
                            if check_file.samefile(open_file):
                                yield open_file, proc.info["pid"], proc.info["name"]


def prepare_environment(
    sanitizer_log: Path,
    env_mod: Mapping[str, str | None] | None = None,
    sanitizer: str | None = None,
) -> dict[str, str]:
    """Create environment that can be used when launching the browser.

    Args:
        sanitizer_log: Location to write sanitizer logs. Log prefix set
                       with ASAN_OPTIONS=log_path=<sanitizer_log>.
        env_mod: Environment modifier. Add, remove and update entries
                 in the prepared environment. Add/update by setting
                 value or remove entry by setting value to None.
        sanitizer: Sanitizer in use.

    Returns:
        Environment to use when launching browser.
    """
    base: dict[str, str | None] = {}
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
    # shutdown all processes when a crash is detected
    base["MOZ_CRASHREPORTER_SHUTDOWN"] = "1"
    base["MOZ_DISABLE_CONTENT_SANDBOX"] = "1"
    base["MOZ_DISABLE_GMP_SANDBOX"] = "1"
    base["MOZ_DISABLE_GPU_SANDBOX"] = "1"
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
        base.update(env_mod)
    # environment variables to skip if previously set in environ
    optional = frozenset(
        (
            "_RR_TRACE_DIR",
            "MOZ_CRASHREPORTER",
            "MOZ_CRASHREPORTER_NO_DELETE_DUMP",
            "MOZ_CRASHREPORTER_NO_REPORT",
            "MOZ_CRASHREPORTER_SHUTDOWN",
            "MOZ_SKIA_DISABLE_ASSERTS",
            "RUST_BACKTRACE",
            "XPCOM_DEBUG_BREAK",
        )
    )
    # merge presets and modifications
    for env_name, env_value in base.items():
        if env_value is None:
            if env_name in env:
                LOG.debug("removing env var '%s'", env_name)
                del env[env_name]
            continue
        if env_name in optional and env_name in env:
            LOG.debug("skipping optional env var '%s'", env_name)
            continue
        env[env_name] = env_value

    if env.get("MOZ_CRASHREPORTER_DISABLE") == "1":
        env.pop("MOZ_CRASHREPORTER", None)
        env.pop("MOZ_CRASHREPORTER_NO_DELETE_DUMP", None)
        env.pop("MOZ_CRASHREPORTER_NO_REPORT", None)
        env.pop("MOZ_CRASHREPORTER_SHUTDOWN", None)

    # symbolize traces in process on Windows or when TSan is in use
    # it is required for runtime TSan suppressions
    in_process = IS_WINDOWS or sanitizer == "tsan"
    env = _configure_sanitizers(env, sanitizer_log, symbolize=in_process)
    # filter environment to avoid leaking sensitive information
    return {k: v for k, v in env.items() if "_SECRET" not in k}


def wait_on_files(
    wait_files: Iterable[Path],
    poll_rate: float = 1.0,
    timeout: float = 60,
) -> bool:
    """Wait while specified files are in use.

    Args:
        wait_files: Files that must no longer be open by a process.
        poll_rate: Time in seconds to wait between checks.
        timeout: Maximum number of seconds to wait.

    Returns:
        True if all files were closed within given time otherwise False.
    """
    assert poll_rate >= 0
    assert timeout >= 0
    all_closed = False
    poll_rate = min(poll_rate, timeout)
    deadline = perf_counter() + timeout
    while True:
        open_iter = files_in_use(wait_files)
        if deadline <= perf_counter():
            LOG.debug("wait_on_files() timeout (%ds)", timeout)
            for path, pid, name in open_iter:
                LOG.debug("'%s' open by '%s' (%d)", path, name, pid)
            break
        if not any(open_iter):
            all_closed = True
            break
        sleep(poll_rate)
    return all_closed


def warn_open(path: Path) -> None:
    """Output a message via `LOG.warning` for each file found to be open by a Process.
    On Windows open files cannot be removed. This can be used to help debug issues.

    Args:
        path: Directory to scan for initial files.

    Returns:
        None
    """
    for file_path, pid, name in files_in_use(path.iterdir()):
        LOG.warning("'%s' open by '%s' (%d)", file_path, name, pid)
