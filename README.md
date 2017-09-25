FFPuppet
=======

[![Build Status](https://api.travis-ci.org/MozillaSecurity/ffpuppet.svg)](https://travis-ci.org/MozillaSecurity/ffpuppet)
[![Coverage Status](https://coveralls.io/repos/github/MozillaSecurity/ffpuppet/badge.svg)](https://coveralls.io/github/MozillaSecurity/ffpuppet)
[![Build status](https://ci.appveyor.com/api/projects/status/7r1sx0iad8wksfmw/branch/master?svg=true)](https://ci.appveyor.com/project/tysmith/ffpuppet/branch/master)

FFPuppet is a python module that automates browser process related tasks to aid in fuzzing.

Installation
------------

At this time no modules are required to run FFPuppet however some features may not be available.

##### To install after cloning the repository

    pip install --user -e <ffpuppet_repo>

Once installed ffpuppet can be run using the following command:

    python -m ffpuppet

##### Installing python modules
  
    pip install -r requirements.txt

In order to enable memory limiting `psutil` is required on all supported operating systems. Linux requires `xvfb` in order to run headless (this is not the same as Firefox's `-headless` mode).

##### Ubuntu

    apt-get install xvfb

##### Installing minidump_stackwalk

`minidump_stackwalk` is used to extract a crash report when the browser crashes without a debugger (GDB) or
instrumentation (Valgrind/Asan). If desired, `minidump_stackwalk` should be installed in the users path after obtaining
it from [tooltool](https://wiki.mozilla.org/ReleaseEngineering/Applications/Tooltool). Choose the appropriate platform
from [tooltool-manifests](https://hg.mozilla.org/mozilla-central/file/tip/testing/config/tooltool-manifests) in the
mozilla-central tree, then open or download `releng.manifest`. Either use `tooltool.py fetch -m releng.manifest` or
copy the digest from the file and download it from `https://api.pub.build.mozilla.org/tooltool/sha512/<digest>`.
In either case, the file should be renamed to `minidump_stackwalk` and marked executable (or `minidump_stackwalk.exe`
on Windows).


Usage
-----
```
usage: __main__.py [-h] [-a ABORT_TOKEN] [-d] [-e EXTENSION] [-g] [-l LOG]
                   [--log-limit LOG_LIMIT] [-m MEMORY] [-p PREFS] [-P PROFILE]
                   [--safe-mode] [-t TIMEOUT] [-u URL] [--valgrind] [-v]
                   [--xvfb]
                   binary

Firefox launcher/wrapper

positional arguments:
  binary                Firefox binary to execute

optional arguments:
  -h, --help            show this help message and exit
  -a ABORT_TOKEN, --abort-token ABORT_TOKEN
                        Scan the log for the given value and close browser on
                        detection. For example '-a ###!!! ASSERTION:' would be
                        used to detect soft assertions.
  -d, --dump            Display browser log on process exit
  -e EXTENSION, --extension EXTENSION
                        Install the fuzzPriv extension (specify path to
                        funfuzz/dom/extension)
  -g, --gdb             Use GDB (Linux only)
  -l LOG, --log LOG     Location to save log files
  --log-limit LOG_LIMIT
                        Log file size limit in MBs (default: 'no limit')
  -m MEMORY, --memory MEMORY
                        Process memory limit in MBs (Requires psutil)
  -p PREFS, --prefs PREFS
                        prefs.js file to use
  -P PROFILE, --profile PROFILE
                        Profile to use. (default: a temporary profile is
                        created)
  --safe-mode           Launch browser in 'safe-mode'. WARNING: Launching in
                        safe mode blocks with a dialog that must be dismissed
                        manually.
  -t TIMEOUT, --timeout TIMEOUT
                        Number of seconds to wait for the browser to become
                        responsive after launching. (default: 300)
  -u URL, --url URL     Server URL or local file to load.
  --valgrind            Use Valgrind (Linux only)
  -v, --verbose         Output includes debug prints
  --xvfb                Use Xvfb (Linux only)
```
