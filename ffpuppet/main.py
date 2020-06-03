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

def dump_to_console(log_dir, save_path, log_quota=0x8000):
    """
    Read and merge log files and format for output on the console

    @type log_dir: String
    @param log_dir: directory to scan for logs

    @type save_path: String
    @param save_path: directory full logs are saved to

    @type log_quota: int
    @param log_quota: maximum number of bytes to read per log

    @rtype: String
    @return: Merged log data to be displayed on the console
    """

    logs = list(x for x in os.listdir(log_dir) if os.path.isfile(os.path.join(log_dir, x)))
    if not logs:
        return ""
    logs.sort()
    # display stdout and stderr last to prevent scrolling
    # this assumes stderr contains the relevant information
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

    tailed = False
    # merge logs
    with tempfile.SpooledTemporaryFile(max_size=0x40000, mode="w+") as out_fp:
        for fname in logs:
            full_path = os.path.join(log_dir, fname)
            fsize = os.stat(full_path).st_size
            out_fp.write("\n===\n")
            out_fp.write("=== Dumping %r (%0.2fKB)" % (fname, fsize / 1024.0))
            with open(full_path, "rb") as log_fp:
                # tail log if needed
                log_fp.seek(max((fsize - log_quota), 0))
                if log_fp.tell() > 0:
                    tailed = True
                    out_fp.write(" - tailed (%0.2fKB)" % (log_quota / 1024.0))
                out_fp.write("\n===\n")
                # using decode() is a workaround for python 3.4
                out_fp.write(log_fp.read().decode("ascii", errors="ignore"))
        if tailed:
            out_fp.write("\n===\n")
            if save_path is None:
                out_fp.write("=== To capture complete logs use '--log'")
            else:
                out_fp.write("=== Full logs available here %r" % (os.path.abspath(save_path),))
            out_fp.write("\n===\n")
        out_fp.seek(0)
        return out_fp.read()


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
        "-d", "--dump", action="store_true",
        help="Display browser logs on process exit. This is only meant to provide a " \
             "summary of the logs. To collect full logs use '--log'.")
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
        "-l", "--log",
        help="Location to save logs. If the path exists it must be empty, if it " \
             "does not exist it will be created.")
    report_group.add_argument(
        "--log-limit", type=int, default=0,
        help="Browser log file size limit in MBs (default: %(default)s, no limit)")
    report_group.add_argument(
        "-m", "--memory", type=int, default=0,
        help="Browser process memory limit in MBs (default: %(default)s, no limit)")
    report_group.add_argument(
        "--poll-interval", type=float, default=0.5,
        help="Delay between checks for results (default: %(default)s)")
    report_group.add_argument(
        "-t", "--timeout", type=int, default=300,
        help="Number of seconds to wait for the browser to become " \
             "responsive after launching. (default: %(default)s)")

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
    if args.log and os.path.isdir(args.log) and os.listdir(args.log):
        parser.error("--log %r must be empty" % args.log)
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
    if use_rr and args.log is None:
        parser.error("--rr must be used with -l/--log")

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
            launch_timeout=args.timeout,
            log_limit=args.log_limit,
            memory_limit=args.memory,
            prefs_js=args.prefs,
            extension=args.extension)
        if args.prefs is not None and os.path.isfile(args.prefs):
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
        if args.log is not None:
            log.info("Saving logs to %r", os.path.abspath(args.log))
            ffp.save_logs(args.log, logs_only=user_exit)
        if args.dump:
            log_path = args.log
            try:
                if log_path is None:
                    # collect logs and store in temporary path
                    log_path = tempfile.mkdtemp(prefix="ffp_log_")
                    ffp.save_logs(log_path, logs_only=True)
                log.info("Displaying logs...\n%s", dump_to_console(log_path, args.log))
            finally:
                # only remove log_path if it was a temporary path
                if args.log is None and os.path.isdir(log_path):
                    shutil.rmtree(log_path)
        ffp.clean_up()
