#!/usr/bin/env python

# To create an exe file for testing on Windows (tested with Python 3.4):
# python -m py2exe.build_exe -O -b 0 -d testff testff.py

from multiprocessing import Event, freeze_support, Process
import os
import sys
import time
try:
    from urllib.request import urlopen, URLError
except ImportError:
    from urllib2 import urlopen, URLError

EXIT_DELAY = 45
POOL_SIZE = 4  # number of child procs to create


def dummy_process(is_alive, parent_done):
    is_alive.set()
    sys.stdout.write('child process, pid: %d\n' % os.getpid())
    parent_done.wait(EXIT_DELAY)


def main(parent_done):
    profile = url = None
    while len(sys.argv) > 1:
        arg = sys.argv.pop(1)
        if arg in ('-no-remote', '-safe-mode'):
            pass
        elif arg.startswith('http://'):
            url = arg
        elif arg == '-profile':
            profile = sys.argv.pop(1)
        else:
            raise RuntimeError('unknown argument: %s' % arg)
    if url is None:
        sys.stderr.write('missing url\n')
        return 1
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
                    if line == 'fftest_startup_hang':
                        cmd = 'hang'
                    elif line == 'fftest_startup_crash':
                        cmd = 'start_crash'
                    elif line == 'fftest_memory':
                        cmd = 'memory'
                    elif line == 'fftest_multi_proc':
                        cmd = 'multi_proc'
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

    proc_pool = list()
    if cmd == 'hang':
        sys.stdout.write('hanging\n')
        sys.stdout.flush()
        for _ in range(10):  # 10 minutes (basically forever)
            time.sleep(60)
        return 1
    elif cmd == 'start_crash':
        sys.stdout.write('simulating start up crash\n')
        sys.stdout.flush()
        os.mkdir(os.path.join(profile, "minidumps"))
        with open(os.path.join(profile, "minidumps", "fake_mini.dmp"), "w") as _:
            pass
        return -11
    elif cmd == 'invalid_js':
        with open(os.path.join(profile, 'Invalidprefs.js'), "w") as prefs_js:
            prefs_js.write("bad!")
    elif cmd in ('memory', 'multi_proc'):
        is_alive = Event()
        for _ in range(POOL_SIZE):
            proc_pool.append(Process(target=dummy_process, args=(is_alive, parent_done)))
            proc_pool[-1].start()
            is_alive.wait()
            is_alive.clear()

    target_url = None
    if url:
        try:
            conn = urlopen(url)
        except URLError as req_err:
            # can't redirect to file:// from http://
            conn = urlopen(req_err.reason.split('\'')[1])
        try:
            # this should set target_url to the value passed to launch()'s 'location' arg
            target_url = conn.geturl()
            if target_url == url:
                target_url = None
            sys.stdout.write(conn.read().decode('utf-8'))
            sys.stdout.write('\n')
            sys.stdout.flush()
        finally:
            conn.close()

    sys.stdout.write('url: %r\n' % target_url)
    sys.stdout.flush()

    if cmd == 'memory':
        sys.stdout.write('simulating high memory usage\n')
        sys.stdout.flush()
        blob = []
        for _ in range(200):
            blob.append("A" * 1024 * 1024)
    elif cmd == 'soft_assert':
        sys.stdout.write('simulating soft assertion\n')
        sys.stdout.flush()
        sys.stderr.write('A' * 512 * 1024)
        sys.stderr.write('\n###!!! ASSERTION: test\n\nblah...\n')
        sys.stderr.flush()
    elif cmd == 'big_log':
        sys.stdout.write('simulating big logs\n')
        buf = 'A' * (512 * 1024) # 512KB
        for _ in range(25):
            sys.stdout.write(buf)
            sys.stderr.write(buf)
            sys.stdout.flush()
            sys.stderr.flush()
    elif cmd == 'exit_code':
        sys.stdout.write('exit code test\n')
        return exit_code

    try:
        sys.stdout.write('running... (sleep %d)\n' % EXIT_DELAY)
        sys.stdout.flush()
        time.sleep(EXIT_DELAY) # wait before closing (should be terminated before elapse)
    finally:
        parent_done.set()
        # cleanup for multiprocess
        for proc in proc_pool:
            proc.join()

    sys.stdout.write('exitting normally\n')
    sys.stdout.flush()
    return 0

if __name__ == '__main__':
    freeze_support()  # needed on Windows
    parent_done = Event()
    try:
        sys.exit(main(parent_done))
    finally:
        parent_done.set()
