#!/usr/bin/env python3
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
    with open(os.path.join(profile, 'prefs.js')) as prefs_js:
        for line in prefs_js:
            if line.startswith('user_pref'):
                pass
            elif line.startswith('#'):
                line = line.lstrip('#').strip()
                if line == 'fftest_hang':
                    cmd = 'hang'
                # don't worry about unknown values
            elif line.strip():
                raise RuntimeError('unknown value in prefs.js: %s' % line)
    if cmd == 'hang':
        print('hanging')
        while True:
            time.sleep(60)
    initial_req = urllib.request.urlopen(url).read().decode("utf-8")
    redirect = re.search(r"window.location='([^']+)'", initial_req).group(1)
    real_req = urllib.request.urlopen(redirect).read().decode("utf-8")
    print(real_req)


if __name__ == '__main__':
    main()

