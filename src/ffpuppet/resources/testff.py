#!/usr/bin/env python
"""fake firefox"""

import sys
from argparse import ArgumentParser
from enum import IntEnum, auto, unique
from pathlib import Path
from time import sleep
from urllib.error import URLError
from urllib.request import urlopen

EXIT_DELAY = 45


@unique
class Mode(IntEnum):
    """Available testing modes"""

    BIG_LOG = auto()
    EXIT_CODE = auto()
    INVALID_JS = auto()
    MEMORY = auto()
    NONE = auto()
    SOFT_ASSERT = auto()


def main() -> int:
    """Fake Firefox for testing"""
    parser = ArgumentParser(prog="testff", description="Fake Firefox for testing")
    parser.add_argument("url")
    parser.add_argument("-headless", action="store_true", help="ignored")
    parser.add_argument("-marionette", nargs="?", type=int, help="ignored")
    parser.add_argument("-new-instance", action="store_true", help="ignored")
    parser.add_argument("-no-deelevate", action="store_true", help="ignored")
    parser.add_argument("-wait-for-browser", action="store_true", help="ignored")
    parser.add_argument("-profile", type=Path, required=True)
    args = parser.parse_args()

    # read prefs to see how to run
    exit_code = 0
    mode = Mode.NONE
    with (args.profile / "prefs.js").open() as prefs_js:
        for line in prefs_js:
            if line.startswith("user_pref"):
                pass
            elif line.startswith("/"):
                line = line.lstrip("/").strip()
                if line == "fftest_memory":
                    mode = Mode.MEMORY
                elif line == "fftest_soft_assert":
                    mode = Mode.SOFT_ASSERT
                elif line == "fftest_invalid_js":
                    mode = Mode.INVALID_JS
                elif line == "fftest_big_log":
                    mode = Mode.BIG_LOG
                elif line.startswith("fftest_exit_code_"):
                    mode = Mode.EXIT_CODE
                    exit_code = int(line.split("fftest_exit_code_")[-1])
                # don't worry about unknown values
            elif line.startswith("#"):
                pass  # skip comments
            elif line.strip():
                raise RuntimeError(f"unknown value in prefs.js: {line}")
    # sys.stdout.write(f'cmd: {cmd}\n')
    # sys.stdout.flush()

    if mode == Mode.INVALID_JS:
        (args.profile / "Invalidprefs.js").write_text("bad!")

    target_url = None
    try:
        # pylint: disable=consider-using-with
        conn = urlopen(args.url)
    except URLError as req_err:
        # can't redirect to file:// from http://
        # pylint: disable=consider-using-with
        conn = urlopen(str(req_err.reason).split("'")[1])
    try:
        target_url = conn.geturl()
        if target_url == args.url:
            target_url = None
        sys.stdout.write(conn.read().decode())
        sys.stdout.write("\n")
        sys.stdout.flush()
    finally:
        conn.close()

    sys.stdout.write(f"url: {target_url!r}\n")
    sys.stdout.flush()

    if mode == Mode.MEMORY:
        sys.stdout.write("simulating high memory usage\n")
        sys.stdout.flush()
        _ = ["A" * 1024 * 1024 for _ in range(200)]
    elif mode == Mode.SOFT_ASSERT:
        sys.stdout.write("simulating soft assertion\n")
        sys.stdout.flush()
        sys.stderr.write("A" * 512 * 1024)
        sys.stderr.write("\n###!!! ASSERTION: test\n\nblah...\n")
        sys.stderr.flush()
    elif mode == Mode.BIG_LOG:
        sys.stdout.write("simulating big logs\n")
        buf = "A" * (512 * 1024)  # 512KB
        for _ in range(25):
            sys.stdout.write(buf)
            sys.stderr.write(buf)
            sys.stdout.flush()
            sys.stderr.flush()
    elif mode == Mode.EXIT_CODE:
        sys.stdout.write(f"exit code test ({exit_code})\n")
        sys.stdout.flush()
        return exit_code

    sys.stdout.write(f"running... (sleep {EXIT_DELAY})\n")
    sys.stdout.flush()
    sleep(EXIT_DELAY)  # wait before closing (should be terminated before elapse)
    sys.stdout.write("exiting normally\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
