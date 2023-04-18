# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""ffpuppet main.py"""

from argparse import ArgumentParser, Namespace
from importlib.metadata import PackageNotFoundError, version
from logging import DEBUG, ERROR, INFO, WARNING, basicConfig, getLogger
from pathlib import Path
from platform import system
from shutil import rmtree
from tempfile import mkdtemp
from time import sleep, strftime
from typing import List, Optional

from .core import Debugger, FFPuppet, Reason
from .exceptions import BrowserExecutionError
from .helpers import certutil_available, certutil_find
from .profile import Profile

LOG = getLogger(__name__)

__author__ = "Tyson Smith"
try:
    __version__ = version("ffpuppet")
except PackageNotFoundError:  # pragma: no cover
    # package is not installed
    __version__ = "unknown"


def dump_to_console(log_dir: Path, log_quota: int = 0x8000) -> str:
    """Read and merge log files and format for output on the console.

    Args:
        log_dir: Directory to scan for logs.
        log_quota: Maximum number of bytes to read per log.

    Returns:
        Merged log data to be displayed on the console.
    """

    logs = list(x for x in log_dir.iterdir() if x.is_file())
    if not logs:
        return ""
    # display stdout and stderr last to avoid the need to scroll back
    # this assumes stderr contains the most relevant information
    for l_order in ("log_stdout", "log_stderr"):
        found = None
        for log in logs:
            if log.name.startswith(l_order):
                found = log
                break
        # move to the end of the print list
        if found and logs[-1] != found:
            logs.remove(found)
            logs.append(found)
    # merge logs
    lines = []
    for log in logs:
        fsize = log.stat().st_size
        lines.append("\n===\n")
        lines.append(f"=== Dumping {log.name!r} ({fsize / 1024.0:0.2f}KB)")
        with log.open("rb") as log_fp:
            # tail log if needed
            log_fp.seek(max(fsize - log_quota, 0))
            if log_fp.tell() > 0:
                lines.append(f" - tailed ({log_quota / 1024.0:0.2f}KB)")
            lines.append("\n===\n")
            lines.append(log_fp.read().decode("ascii", errors="ignore"))
    return "".join(lines)


def parse_args(argv: Optional[List[str]] = None) -> Namespace:
    """Handle argument parsing.

    Args:
        argv: Arguments from the user.

    Returns:
        Parsed and sanitized arguments.
    """

    log_level_map = {"ERROR": ERROR, "WARN": WARNING, "INFO": INFO, "DEBUG": DEBUG}

    parser = ArgumentParser(
        prog="ffpuppet",
        description="FFPuppet - Firefox process launcher and log collector. "
        "Happy bug hunting!",
    )
    parser.add_argument("binary", type=Path, help="Firefox binary to launch")
    parser.add_argument(
        "-d",
        "--display-logs",
        action="store_true",
        help="Display summary of browser logs on process exit.",
    )
    parser.add_argument(
        "--log-level",
        choices=sorted(log_level_map),
        default="INFO",
        help="Configure console logging (default: %(default)s)",
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show version number",
    )

    cfg_group = parser.add_argument_group("Browser Configuration")
    cfg_group.add_argument(
        "--certs",
        nargs="+",
        type=Path,
        help="Install trusted certificates.",
    )
    cfg_group.add_argument(
        "-e",
        "--extension",
        action="append",
        type=Path,
        help="Install extensions. Specify the path to the xpi or the directory "
        "containing the unpacked extension.",
    )
    headless_choices = ["default"]
    if system().startswith("Linux"):
        headless_choices.append("xvfb")
    cfg_group.add_argument(
        "--headless",
        choices=headless_choices,
        const="default",
        default=None,
        nargs="?",
        help="Headless mode. 'default' uses browser's built-in headless mode.",
    )
    cfg_group.add_argument(
        "-p",
        "--prefs",
        type=Path,
        help="Custom prefs.js file to use (default: profile default)",
    )
    cfg_group.add_argument(
        "-P",
        "--profile",
        type=Path,
        help="Profile to use. This is non-destructive. A copy of the target profile "
        "will be used. (default: temporary profile)",
    )
    cfg_group.add_argument(
        "-u", "--url", help="Server URL or path to local file to load."
    )
    if system().startswith("Linux"):
        cfg_group.add_argument(
            "--xvfb",
            action="store_true",
            help="DEPRECATED! Please use '--headless xvfb'",
        )
    else:
        cfg_group.set_defaults(xvfb=False)

    report_group = parser.add_argument_group("Issue Detection & Reporting")
    report_group.add_argument(
        "-a",
        "--abort-token",
        action="append",
        default=[],
        help="Scan the browser logs for the given value and close browser if detected. "
        "For example '-a ###!!! ASSERTION:' would be used to detect soft assertions.",
    )
    report_group.add_argument(
        "--launch-timeout",
        type=int,
        default=300,
        help="Number of seconds to wait for the browser to become "
        "responsive after launching. (default: %(default)s)",
    )
    report_group.add_argument(
        "-l",
        "--logs",
        default=Path.cwd(),
        type=Path,
        help="Location to save browser logs. "
        "A sub-directory containing the browser logs will be created.",
    )
    report_group.add_argument(
        "--log-limit",
        type=int,
        default=0,
        help="Browser log file size limit in MBs (default: %(default)s, no limit)",
    )
    report_group.add_argument(
        "-m",
        "--memory",
        type=int,
        default=0,
        help="Browser memory limit in MBs (default: %(default)s, no limit)",
    )
    report_group.add_argument(
        "--poll-interval",
        type=float,
        default=0.5,
        help="Delay between checks for results (default: %(default)s)",
    )
    report_group.add_argument(
        "--save-all",
        action="store_true",
        help="Always save logs."
        " By default logs are saved only when an issue is detected.",
    )

    if system().startswith("Linux"):
        dbg_group = parser.add_argument_group("Available Debuggers")
        # Add the mutually exclusive group to a regular group
        # because mutually exclusive groups don't accept a title
        dbg_group = dbg_group.add_mutually_exclusive_group()
        dbg_group.add_argument(
            "--gdb",
            action="store_const",
            const=Debugger.GDB,
            dest="debugger",
            help="Use GDB.",
        )
        dbg_group.add_argument(
            "--pernosco",
            action="store_const",
            const=Debugger.PERNOSCO,
            dest="debugger",
            help="Use rr. Trace intended to be submitted to Pernosco.",
        )
        dbg_group.add_argument(
            "--rr",
            action="store_const",
            const=Debugger.RR,
            dest="debugger",
            help="Use rr.",
        )
        dbg_group.add_argument(
            "--valgrind",
            action="store_const",
            const=Debugger.VALGRIND,
            dest="debugger",
            help="Use Valgrind.",
        )

    parser.set_defaults(debugger=Debugger.NONE)

    args = parser.parse_args(argv)

    # sanity checks
    if not args.binary.is_file():
        parser.error(f"Invalid browser binary '{args.binary}'")
    if args.certs:
        if not certutil_available(certutil_find(args.binary)):
            parser.error("'--certs' requires NSS certutil")
        for cert in args.certs:
            if not cert.is_file():
                parser.error(f"Invalid certificate file '{cert}'")
    if args.extension:
        for ext in args.extension:
            if not ext.exists():
                parser.error(f"Extension '{ext}' does not exist")
    if not args.logs.is_dir():
        parser.error(f"Log output directory is invalid '{args.logs}'")
    args.log_level = log_level_map[args.log_level]
    if args.log_limit < 0:
        parser.error("--log-limit must be >= 0")
    args.log_limit *= 1_048_576
    if args.memory < 0:
        parser.error("--memory must be >= 0")
    args.memory *= 1_048_576
    if args.prefs is not None and not args.prefs.is_file():
        parser.error(f"Invalid prefs.js file '{args.prefs}'")
    if args.xvfb:
        LOG.warning("'--xvfb' is DEPRECATED. Please use '--headless xvfb'")
        args.headless = "xvfb"

    return args


def main(argv: Optional[List[str]] = None) -> None:  # pylint: disable=missing-docstring
    args = parse_args(argv)
    # set output verbosity
    if args.log_level == DEBUG:
        date_fmt = None
        log_fmt = "%(asctime)s %(levelname).1s %(name)s | %(message)s"
    else:
        date_fmt = "%Y-%m-%d %H:%M:%S"
        log_fmt = "[%(asctime)s] %(message)s"
    basicConfig(format=log_fmt, datefmt=date_fmt, level=args.log_level)

    ffp = FFPuppet(
        debugger=args.debugger,
        headless=args.headless,
        use_profile=args.profile,
    )
    for a_token in args.abort_token:
        ffp.add_abort_token(a_token)

    user_exit = False
    try:
        LOG.info("Launching Firefox...")
        ffp.launch(
            args.binary,
            location=args.url,
            launch_timeout=args.launch_timeout,
            log_limit=args.log_limit,
            memory_limit=args.memory,
            prefs_js=args.prefs,
            extension=args.extension,
            cert_files=args.certs,
        )
        if args.prefs and args.prefs.is_file():
            assert ffp.profile is not None
            assert ffp.profile.path is not None
            Profile.check_prefs(ffp.profile.path / "prefs.js", args.prefs)
        LOG.info("Running Firefox (pid: %d)...", ffp.get_pid())
        while ffp.is_healthy():
            sleep(args.poll_interval)
    except BrowserExecutionError:
        LOG.error("Cannot execute binary. Perhaps required libraries are missing?")
    except KeyboardInterrupt:
        user_exit = True
        LOG.info("Ctrl+C detected.")
    finally:
        LOG.info("Shutting down...")
        ffp.close()
        if ffp.reason is not None:
            LOG.info("Firefox process is closed. (Reason: %s)", ffp.reason.name)
        else:
            LOG.error("FFPuppet.close() failed")
        logs = Path(mkdtemp(prefix=strftime("%Y%m%d-%H%M%S_ffp_logs_"), dir=args.logs))
        ffp.save_logs(logs, logs_only=user_exit)
        if args.display_logs:
            LOG.info("Displaying logs...%s", dump_to_console(logs))
        if ffp.reason == Reason.ALERT or args.save_all:
            LOG.info("Browser logs available here '%s'", logs.resolve())
        else:
            rmtree(logs)
        ffp.clean_up()
