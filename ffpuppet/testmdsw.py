#!/usr/bin/env python
"""fake minidump_stackwalk"""

import os
import sys


def main():
    dmp_file = None
    if len(sys.argv) > 2:
        if os.path.isfile(sys.argv[-2]):
            dmp_file = sys.argv[-2]

    if dmp_file is not None:
        with open(dmp_file, "r") as in_fp:
            data = in_fp.read()
        if data.startswith("return=1"):
            # fake an error
            sys.exit(1)
        sys.stdout.write(data)
    else:
        sys.stdout.write("COULD NOT OPEN %r\n" % dmp_file)
        sys.exit(1)

    sys.exit(0)

if __name__ == '__main__':
    main()
