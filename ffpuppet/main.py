# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import logging
import os
import shutil
import sys
import tempfile
import time

from .core import FFPuppet
from .helpers import check_prefs

log = logging.getLogger("ffpuppet")  # pylint: disable=invalid-name

__author__ = "Tyson Smith"

def dump_to_console(log_dir, log_quota=0x8000):
    """
    Read and merge log files and format for output on the console

    @type log_dir: String
    @param log_dir: directory to scan for logs

    @type log_quota: int
    @param log_quota: maximum number of bytes to read per log

    @rtype: String
    @return: Merged log data to be displayed on the console
    """

    logs = list(x for x in os.listdir(log_dir) if os.path.isfile(os.path.join(log_dir, x)))
    if not logs:
        return ""
    # display stdout and stderr last to avoid the need to scroll back
    # this assumes stderr contains the most relevant information
    for l_order in ("log_stdout", "log_stderr"):
        found = None
        for fname in logs:
            if fname.startswith(l_order):
                found = fname
                break
        # move to the end of the print list
        if found and logs[-1] != found:
            logs.remove(found)
            logs.append(found)
    # merge logs
    lines = list()
    for fname in logs:
        full_path = os.path.join(log_dir, fname)
        fsize = os.stat(full_path).st_size
        lines.append("\n===\n")
        lines.append("=== Dumping %r (%0.2fKB)" % (fname, fsize / 1024.0))
        with open(full_path, "rb") as log_fp:
            # tail log if needed
            log_fp.seek(max(fsize - log_quota, 0))
            if log_fp.tell() > 0:
                lines.append(" - tailed (%0.2fKB)" % (log_quota / 1024.0))
            lines.append("\n===\n")
            lines.append(log_fp.read().decode("ascii", errors="ignore"))
    return "".join(lines)


def parse_args(argv=None):
    log_level_map = {
        "ERROR": logging.ERROR,
        "WARN": logging.WARNING,
        "INFO": logging.INFO,
        "DEBUG": logging.DEBUG}

    parser = argparse.ArgumentParser(
        description="FFPuppet - Firefox process launcher and log collector. Happy bug hunting!")
    parser.add_argument(
        "binary",
        help="Firefox binary to launch")
    parser.add_argument(
        "-d", "--display-logs", action="store_true",
        help="Display summary of browser logs on process exit.")
    parser.add_argument(
        "--log-level", default="INFO",
        help="Configure console logging. Options: %s (default: %%(default)s)" %
        ", ".join(k for k, v in sorted(log_level_map.items(), key=lambda x: x[1])))

    cfg_group = parser.add_argument_group("Browser Configuration")
    cfg_group.add_argument(
        "-e", "--extension", action="append",
        help="Install extensions. Specify the path to the xpi or the directory " \
             "containing the unpacked extension.")
    cfg_group.add_argument(
        "-p", "--prefs",
        help="Custom prefs.js file to use (default: profile default)")
    cfg_group.add_argument(
        "-P", "--profile",
        help="Profile to use. This is non-destructive. A copy of the target profile " \
             "will be used. (default: temporary profile)")
    cfg_group.add_argument(
        "-u", "--url",
        help="Server URL or path to local file to load.")
    if sys.platform.startswith("linux"):
        cfg_group.add_argument(
            "--xvfb", action="store_true",
            help="Use Xvfb")

    report_group = parser.add_argument_group("Issue Detection & Reporting")
    report_group.add_argument(
        "-a", "--abort-token", action="append", default=list(),
        help="Scan the browser logs for the given value and close browser if detected. " \
             "For example '-a ###!!! ASSERTION:' would be used to detect soft assertions.")
    report_group.add_argument(
        "--launch-timeout", type=int, default=300,
        help="Number of seconds to wait for the browser to become " \
             "responsive after launching. (default: %(default)s)")
    report_group.add_argument(
        "-l", "--logs", default=".",
        help="Location to save browser logs. A sub-directory containing the browser logs" \
             " will be created.")
    report_group.add_argument(
        "--log-limit", type=int, default=0,
        help="Browser log file size limit in MBs (default: %(default)s, no limit)")
    report_group.add_argument(
        "-m", "--memory", type=int, default=0,
        help="Browser memory limit in MBs (default: %(default)s, no limit)")
    report_group.add_argument(
        "--poll-interval", type=float, default=0.5,
        help="Delay between checks for results (default: %(default)s)")
    report_group.add_argument(
        "--save-all", action="store_true",
        help="Always save logs. By default logs are saved only when an issue is detected.")

    if sys.platform.startswith("linux"):
        dbg_group = parser.add_argument_group("Available Debuggers")
        dbg_group.add_argument(
            "--gdb", action="store_true",
            help="Use GDB")
        dbg_group.add_argument(
            "--rr", action="store_true",
            help="Use rr")
        dbg_group.add_argument(
            "--valgrind", action="store_true",
            help="Use Valgrind")

    args = parser.parse_args(argv)

    # sanity checks
    if not os.path.isfile(args.binary):
        parser.error("Invalid browser binary %r" % args.binary)
    if args.extension is not None:
        for ext in args.extension:
            if not os.path.exists(ext):
                parser.error("Extension %r does not exist" % ext)
    if not os.path.isdir(args.logs):
        parser.error("Log output directory is invalid %r" % args.logs)
    log_level = log_level_map.get(args.log_level.upper(), None)
    if log_level is None:
        parser.error("Invalid log-level %r" % args.log_level)
    args.log_level = log_level
    if args.log_limit < 0:
        parser.error("--log-limit must be >= 0")
    args.log_limit *= 1048576
    if args.memory < 0:
        parser.error("--memory must be >= 0")
    args.memory *= 1048576
    if args.prefs is not None and not os.path.isfile(args.prefs):
        parser.error("file not found %r" % args.prefs)
    # NOTE: mutually_exclusive_group will fail if no arguments are added
    # so sum() enabled debuggers instead
    use_gdb = getattr(args, "gdb", False)
    use_rr = getattr(args, "rr", False)
    use_valgrind = getattr(args, "valgrind", False)
    if sum((use_gdb, use_rr, use_valgrind)) > 1:
        parser.error("Only a single debugger can be enabled")

    return args


def main(argv=None):  # pylint: disable=missing-docstring
    args = parse_args(argv)
    # set output verbosity
    if args.log_level == logging.DEBUG:
        log_fmt = "%(levelname).1s %(name)s [%(asctime)s] %(message)s"
    else:
        log_fmt = "[%(asctime)s] %(message)s"
    logging.basicConfig(
        format=log_fmt,
        datefmt="%Y-%m-%d %H:%M:%S",
        level=args.log_level)

    ffp = FFPuppet(
        use_profile=args.profile,
        use_valgrind=getattr(args, "valgrind", False),
        use_xvfb=getattr(args, "xvfb", False),
        use_gdb=getattr(args, "gdb", False),
        use_rr=getattr(args, "rr", False))
    for a_token in args.abort_token:
        ffp.add_abort_token(a_token)

    user_exit = False
    try:
        log.info("Launching Firefox...")
        ffp.launch(
            args.binary,
            location=args.url,
            launch_timeout=args.launch_timeout,
            log_limit=args.log_limit,
            memory_limit=args.memory,
            prefs_js=args.prefs,
            extension=args.extension)
        if args.prefs and os.path.isfile(args.prefs):
            check_prefs(os.path.join(ffp.profile, "prefs.js"), args.prefs)
        log.info("Running Firefox (pid: %d)...", ffp.get_pid())
        while ffp.is_healthy():
            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        user_exit = True
        log.info("Ctrl+C detected.")
    finally:
        log.info("Shutting down...")
        ffp.close()
        log.info("Firefox process is closed. (Reason: %r)", ffp.reason)
        log_path = tempfile.mkdtemp(
            prefix=time.strftime("%Y%m%d-%H%M%S_", time.localtime()),
            suffix="_ffp_logs",
            dir=args.logs)
        ffp.save_logs(log_path, logs_only=user_exit)
        if args.display_logs:
            log.info("Displaying logs...%s", dump_to_console(log_path))
        if ffp.reason == ffp.RC_ALERT or args.save_all:
            log.info("Browser logs available here %r", os.path.abspath(log_path))
        else:
            shutil.rmtree(log_path)
        ffp.clean_up()
