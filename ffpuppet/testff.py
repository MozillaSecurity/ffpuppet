#!/usr/bin/env python

# To create an exe file for testing on Windows (tested with Python 3.4):
# python -m py2exe.build_exe -O -b 0 -d testff testff.py

import os.path
import re
import sys
import time
try:
    from urllib.request import urlopen
except ImportError:
    from urllib2 import urlopen


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
    exit_code = 0
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
                    elif line == 'fftest_big_log':
                        cmd = 'big_log'
                    elif line.startswith('fftest_exit_code_'):
                        cmd = 'exit_code'
                        exit_code = int(line.split('fftest_exit_code_')[-1])
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

    target_url = None # should be set to the value passed to launch()'s 'location' arg
    while url is not None:
        if url.startswith("about"):
            break
        elif url.startswith("file://"):
            break

        conn = urlopen(url)
        try:
            data = conn.read().decode('utf-8')
            # check for redirects
            redirect = re.search(r"content=\"0;\surl=([^\"]+)\"", data)
            if redirect is not None:
                url = redirect.group(1)
                if url is not None:
                    target_url = url
                continue
            sys.stdout.write(data)
            sys.stdout.write('\n')
            sys.stdout.flush()
        finally:
            conn.close()
        break

    sys.stdout.write('url: %s\n' % target_url)
    sys.stdout.flush()

    if cmd == 'memory':
        sys.stdout.write('simulating high memory usage\n')
        sys.stdout.flush()
        blob = []
        with open(os.devnull, "r") as r_fp:
            for _ in range(200):
                blob.append(r_fp.read(1024*1024))
    elif cmd == 'soft_assert':
        sys.stdout.write('simulating soft assertion\n')
        # split '###!!! ASSERTION: tests\n' across multiple reads by the log scanner
        sys.stdout.write('###!!! ')
        sys.stdout.flush()
        time.sleep(0.25)
        sys.stdout.write('ASSERT')
        sys.stdout.flush()
        time.sleep(0.25)
        sys.stdout.write('ION: test\n\nblah...')
        sys.stdout.flush()
    elif cmd == 'big_log':
        sys.stdout.write('simulating big logs\n')
        buf = "A" * (1024*1024) # 1MB
        for _ in range(25):
            sys.stdout.write(buf)
            sys.stdout.flush()
    elif cmd == 'exit_code':
        sys.stdout.write('exit code test\n')
        sys.exit(exit_code)

    time.sleep(45) # wait before closing (should be terminated before elapse)
    sys.exit(0)

if __name__ == '__main__':
    main()
