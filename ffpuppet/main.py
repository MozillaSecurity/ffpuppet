# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import logging
import os
import shutil
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

    logs = os.listdir(log_dir)
    if not logs:
        return ""
    logs.sort()  # sort alphabetically
    # display stdout and stderr last to prevent scrolling
    # this assumes stderr contains the relevant information
    order = ("log_stdout", "log_stderr")
    for l_order in order:
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
    with tempfile.SpooledTemporaryFile(max_size=0x40000, mode="wb+") as out_fp:
        for fname in logs:
            full_path = os.path.join(log_dir, fname)
            fsize = os.stat(full_path).st_size
            header = list()
            header.append("\n===\n")
            header.append("=== Dumping %r (%0.2fKB)" % (fname, fsize / 1024.0))
            with open(full_path, "rb") as log_fp:
                # tail if needed
                log_fp.seek(max((fsize - log_quota), 0))
                if log_fp.tell() > 0:
                    tailed = True
                    header.append(" - tailed (%0.2fKB)" % (log_quota / 1024.0))
                header.append("\n===\n")
                # workaround for python 3.2
                log_fp.write("".join(header).encode("ascii", errors="ignore"))
                shutil.copyfileobj(log_fp, out_fp)
        if tailed:
            out_fp.write(b"\n===\n")
            out_fp.write(b"=== To capture complete logs use '--log'")
            out_fp.write(b"\n===\n")
        out_fp.seek(0)
        return out_fp.read().decode("ascii", errors="ignore")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Firefox launcher/wrapper")
    parser.add_argument(
        "binary",
        help="Firefox binary to execute")
    parser.add_argument(
        "-a", "--abort-token", action="append", default=list(),
        help="Scan the log for the given value and close browser on detection. " \
             "For example '-a ###!!! ASSERTION:' would be used to detect soft assertions.")
    parser.add_argument(
        "-d", "--dump", action="store_true",
        help="Display browser logs on process exit. This is only meant to provide a " \
             "summary of the logs. To collect full logs use '--log'.")
    parser.add_argument(
        "-e", "--extension", action="append",
        help="Use the fuzzPriv extension. Specify the path to the xpi or the directory " \
             "containing the unpacked extension.")
    parser.add_argument(
        "-g", "--gdb", action="store_true",
        help="Use GDB (Linux only)")
    parser.add_argument(
        "-l", "--log",
        help="Location to save log files")
    parser.add_argument(
        "--log-limit", type=int,
        help="Log file size limit in MBs (default: no limit)")
    parser.add_argument(
        "-m", "--memory", type=int,
        help="Process memory limit in MBs (default: no limit)")
    parser.add_argument(
        "-p", "--prefs",
        help="Custom prefs.js file to use (default: profile default)")
    parser.add_argument(
        "-P", "--profile",
        help="Profile to use. This is non-destructive. A copy of the target profile " \
             "will be used. (default: new temporary profile is created)")
    parser.add_argument(
        "--rr", action="store_true",
        help="Use RR (Linux only)")
    parser.add_argument(
        "--safe-mode", action="store_true",
        help="Launch browser in 'safe-mode'. WARNING: Launching in safe mode blocks with a " \
             "dialog that must be dismissed manually.")
    parser.add_argument(
        "-t", "--timeout", type=int, default=300,
        help="Number of seconds to wait for the browser to become " \
             "responsive after launching. (default: %(default)s)")
    parser.add_argument(
        "-u", "--url",
        help="Server URL or local file to load.")
    parser.add_argument(
        "--valgrind", action="store_true",
        help="Use Valgrind (Linux only)")
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Output includes debug prints")
    parser.add_argument(
        "--xvfb", action="store_true",
        help="Use Xvfb (Linux only)")
    return parser.parse_args(argv)


def main(argv=None):  # pylint: disable=missing-docstring
    args = parse_args(argv)

    # set output verbosity
    if args.verbose or bool(os.getenv("DEBUG")):
        log_level = logging.DEBUG
        log_fmt = "%(levelname).1s %(name)s [%(asctime)s] %(message)s"
    else:
        log_level = logging.INFO
        log_fmt = "[%(asctime)s] %(message)s"
    logging.basicConfig(format=log_fmt, datefmt="%Y-%m-%d %H:%M:%S", level=log_level)

    ffp = FFPuppet(
        use_profile=args.profile,
        use_valgrind=args.valgrind,
        use_xvfb=args.xvfb,
        use_gdb=args.gdb,
        use_rr=args.rr)
    for a_token in args.abort_token:
        ffp.add_abort_token(a_token)

    try:
        ffp.launch(
            args.binary,
            location=args.url,
            launch_timeout=args.timeout,
            log_limit=args.log_limit * 1024 * 1024 if args.log_limit else 0,
            memory_limit=args.memory * 1024 * 1024 if args.memory else 0,
            prefs_js=args.prefs,
            safe_mode=args.safe_mode,
            extension=args.extension)
        if args.prefs is not None and os.path.isfile(args.prefs):
            check_prefs(os.path.join(ffp.profile, "prefs.js"), args.prefs)
        log.info("Running Firefox (pid: %d)...", ffp.get_pid())
        while ffp.is_healthy():
            time.sleep(0.25)
    except KeyboardInterrupt:
        log.info("Ctrl+C detected.")
    finally:
        log.info("Shutting down...")
        ffp.close()
        log.info("Firefox process closed")
        if args.log is not None:
            ffp.save_logs(args.log)
        if args.dump:
            log_dir = tempfile.mkdtemp(prefix="ffp_log_")
            try:
                ffp.save_logs(log_dir)
                log.info("Dumping browser log...\n%s", dump_to_console(log_dir))
            finally:
                if os.path.isdir(log_dir):
                    shutil.rmtree(log_dir)
        ffp.clean_up()
