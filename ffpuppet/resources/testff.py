#!/usr/bin/env python
"""fake firefox"""

import os
import platform
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen

EXIT_DELAY = 45


def main() -> int:  # pylint: disable=missing-docstring
    os_name = platform.system()
    profile = url = None
    while len(sys.argv) > 1:
        arg = sys.argv.pop(1)
        if arg in ("-headless", "-no-remote"):
            pass
        elif os_name == "Windows" and arg in ("-no-deelevate", "-wait-for-browser"):
            pass
        elif arg.startswith("http://"):
            url = arg
        elif arg == "-profile":
            profile = sys.argv.pop(1)
        else:
            raise RuntimeError(f"unknown argument: {arg}")
    if url is None:
        sys.stderr.write("missing url\n")
        return 1
    # read prefs to see how to run
    cmd = None
    exit_code = 0
    if profile is not None:
        with open(os.path.join(profile, "prefs.js")) as prefs_js:
            for line in prefs_js:
                if line.startswith("user_pref"):
                    pass
                elif line.startswith("/"):
                    line = line.lstrip("/").strip()
                    if line == "fftest_memory":
                        cmd = "memory"
                    elif line == "fftest_soft_assert":
                        cmd = "soft_assert"
                    elif line == "fftest_invalid_js":
                        cmd = "invalid_js"
                    elif line == "fftest_big_log":
                        cmd = "big_log"
                    elif line.startswith("fftest_exit_code_"):
                        cmd = "exit_code"
                        exit_code = int(line.split("fftest_exit_code_")[-1])
                    # don't worry about unknown values
                elif line.startswith("#"):
                    pass  # skip comments
                elif line.strip():
                    raise RuntimeError(f"unknown value in prefs.js: {line}")
    # sys.stdout.write(f'cmd: {cmd}\n')
    # sys.stdout.flush()

    assert profile is not None
    if cmd == "invalid_js":
        with open(os.path.join(profile, "Invalidprefs.js"), "w") as prefs_js:
            prefs_js.write("bad!")

    target_url = None
    if url:
        try:
            # pylint: disable=consider-using-with
            conn = urlopen(url)
        except URLError as req_err:
            # can't redirect to file:// from http://
            # pylint: disable=consider-using-with
            conn = urlopen(str(req_err.reason).split("'")[1])
        try:
            target_url = conn.geturl()
            if target_url == url:
                target_url = None
            sys.stdout.write(conn.read().decode())
            sys.stdout.write("\n")
            sys.stdout.flush()
        finally:
            conn.close()

    sys.stdout.write(f"url: {target_url!r}\n")
    sys.stdout.flush()

    if cmd == "memory":
        sys.stdout.write("simulating high memory usage\n")
        sys.stdout.flush()
        blob = []
        for _ in range(200):
            blob.append("A" * 1024 * 1024)
    elif cmd == "soft_assert":
        sys.stdout.write("simulating soft assertion\n")
        sys.stdout.flush()
        sys.stderr.write("A" * 512 * 1024)
        sys.stderr.write("\n###!!! ASSERTION: test\n\nblah...\n")
        sys.stderr.flush()
    elif cmd == "big_log":
        sys.stdout.write("simulating big logs\n")
        buf = "A" * (512 * 1024)  # 512KB
        for _ in range(25):
            sys.stdout.write(buf)
            sys.stderr.write(buf)
            sys.stdout.flush()
            sys.stderr.flush()
    elif cmd == "exit_code":
        sys.stdout.write(f"exit code test ({exit_code})\n")
        sys.stdout.flush()
        return exit_code

    sys.stdout.write(f"running... (sleep {EXIT_DELAY})\n")
    sys.stdout.flush()
    time.sleep(EXIT_DELAY)  # wait before closing (should be terminated before elapse)
    sys.stdout.write("exiting normally\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
