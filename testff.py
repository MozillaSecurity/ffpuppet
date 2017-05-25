#!/usr/bin/env python3

# To create an exe file for testing on Windows (tested with Python 3.4):
# python -m py2exe.build_exe -O -b 0 -d testff testff.py

import os.path
import re
import sys
import time
import urllib.request


def main():
    profile = url = None
    while len(sys.argv) > 1:
        arg = sys.argv.pop(1)
        if arg in {'-no-remote', '-safe-mode'}:
            pass
        elif arg.startswith('http://'):
            url = arg
        elif arg == '-profile':
            profile = sys.argv.pop(1)
        else:
            raise RuntimeError('unknown argument: %s' % arg)
    assert url is not None
    # read prefs to see how to run
    cmd = None
    if profile is not None:
        with open(os.path.join(profile, 'prefs.js'), "r") as prefs_js:
            for line in prefs_js:
                if line.startswith('user_pref'):
                    pass
                elif line.startswith('/'):
                    line = line.lstrip('/').strip()
                    if line == 'fftest_hang':
                        cmd = 'hang'
                    elif line == 'fftest_startup_crash':
                        cmd = 'start_crash'
                    elif line == 'fftest_memory':
                        cmd = 'memory'
                    elif line == 'fftest_soft_assert':
                        cmd = 'soft_assert'
                    elif line == 'fftest_invalid_js':
                        cmd = 'invalid_js'
                    # don't worry about unknown values
                elif line.startswith('#'):
                    pass # skip comments
                elif line.strip():
                    raise RuntimeError('unknown value in prefs.js: %s' % line)
    #sys.stdout.write('cmd: %s\n' % cmd)
    #sys.stdout.flush()
    if cmd == 'hang':
        sys.stdout.write('hanging\n')
        sys.stdout.flush()
        while True:
            time.sleep(60)
    elif cmd == 'start_crash':
        sys.stdout.write('simulating start up crash\n')
        sys.stdout.flush()
        sys.exit(1)
    elif cmd == 'invalid_js':
        with open(os.path.join(profile, 'Invalidprefs.js'), "w") as prefs_js:
            prefs_js.write("bad!")

    while url is not None:
        if url.startswith("about"):
            break
        with urllib.request.urlopen(url) as conn:
            data = conn.read().decode('utf-8')
            # check for redirects
            redirect = re.search(r"content=\"0;\surl=([^\"]+)\"", data)
            if redirect is not None:
                url = redirect.group(1)
                continue
            sys.stdout.write(data)
            sys.stdout.write('\n')
            sys.stdout.flush()
        break


    if cmd == 'memory':
        sys.stdout.write('simulating high memory usage\n')
        sys.stdout.flush()
        blob = []
        with open(os.devnull, "r") as r_fp:
            for _ in range(200):
                blob.append(r_fp.read(1024*1024))
        time.sleep(60) # wait to be terminated
    elif cmd == 'soft_assert':
        sys.stdout.write('simulating soft assertion\n')
        sys.stdout.write('###!!! ASSERTION: test\n')
        sys.stdout.flush()
        time.sleep(1) # wait to be terminated
        sys.exit(0)

if __name__ == '__main__':
    main()
