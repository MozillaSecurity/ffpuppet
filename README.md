FFPuppet
========

[![Build Status](https://api.travis-ci.org/MozillaSecurity/ffpuppet.svg)](https://travis-ci.org/MozillaSecurity/ffpuppet)
[![Build status](https://ci.appveyor.com/api/projects/status/7r1sx0iad8wksfmw/branch/master?svg=true)](https://ci.appveyor.com/project/tysmith/ffpuppet/branch/master)
[![Coverage Status](https://coveralls.io/repos/github/MozillaSecurity/ffpuppet/badge.svg)](https://coveralls.io/github/MozillaSecurity/ffpuppet)
[![IRC](https://img.shields.io/badge/IRC-%23fuzzing-1e72ff.svg?style=flat)](https://www.irccloud.com/invite?channel=%23fuzzing&amp;hostname=irc.mozilla.org&amp;port=6697&amp;ssl=1)

FFPuppet is a python module that automates browser process related tasks to aid in fuzzing. Happy bug hunting!

Installation
------------

##### To install after cloning the repository

    pip install --user -e <ffpuppet_repository>

##### Installing python modules

    pip install -r requirements.txt

##### Xvfb on Linux

On Linux `xvfb` can be used in order to run headless (this is not the same as Firefox's `-headless` mode).

To install `xvfb` on Ubuntu run:

    apt-get install xvfb

##### Installing minidump_stackwalk

`minidump_stackwalk` is used to extract a crash report when the browser crashes without a debugger (GDB/Valgrind) or
instrumentation (ASan). If desired, `minidump_stackwalk` should be installed in the users path after obtaining
it from [tooltool](https://wiki.mozilla.org/ReleaseEngineering/Applications/Tooltool). Choose the appropriate platform
from [tooltool-manifests](https://hg.mozilla.org/mozilla-central/file/tip/testing/config/tooltool-manifests) in the
mozilla-central tree, then open or download `releng.manifest`. Either use `tooltool.py fetch -m releng.manifest` or
copy the digest from the file and download it from `https://api.pub.build.mozilla.org/tooltool/sha512/<digest>`.
In either case, the file should be renamed to `minidump_stackwalk` and marked executable (or `minidump_stackwalk.exe`
on Windows).

##### fuzzPriv Extension

This provides access to operations that are helpful when fuzzing such as calling the garbage collector.
At the moment there are two versions:

The [legacy](https://github.com/MozillaSecurity/fuzzpriv/tree/legacy) version (the fuzzPriv you know and love)
can only be used with Nighty, mozilla-central builds and old versions of Firefox. The xpi is available [here](https://www.squarefree.com/extensions/domFuzzLite3.xpi).

The [WebExtension](https://github.com/MozillaSecurity/fuzzpriv/tree/master) version can be used with any build
that supports WebExtensions but certain features are only available when combined with [fuzzing builds](https://tools.taskcluster.net/index/gecko.v2.mozilla-central.latest.firefox/linux64-fuzzing-asan-opt).


Browser Builds
--------------

If you are looking for builds to use with FFPuppet here are a few options.

##### Taskcluster

Taskcluster has a collection of many different build types for multiple platforms and branches.
An index of the latest mozilla-central builds can be found [here](https://tools.taskcluster.net/index/gecko.v2.mozilla-central.latest.firefox).
Or you can use [fuzzfetch](https://github.com/MozillaSecurity/fuzzfetch) which is very helpful in automation.

##### Build your own

If you would like to compile your own build instructions can be found [here](https://developer.mozilla.org/en-US/docs/Mozilla/Developer_guide/Build_Instructions/Simple_Firefox_build)


Usage
-----

Once installed FFPuppet can be run using the following command:

    python -m ffpuppet

```
$ python -m ffpuppet -h
usage: __main__.py [-h] [-a ABORT_TOKEN] [-d] [-e EXTENSION] [-g]
                   [--ignore-crashes] [-l LOG] [--log-limit LOG_LIMIT]
                   [-m MEMORY] [-p PREFS] [-P PROFILE] [--safe-mode]
                   [-t TIMEOUT] [-u URL] [--valgrind] [-v] [--xvfb]
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
  -d, --dump            Display browser logs on process exit
  -e EXTENSION, --extension EXTENSION
                        Use the fuzzPriv extension. Specify the path to the
                        xpi or the directory containing the unpacked extension.
  -g, --gdb             Use GDB (Linux only)
  --ignore-crashes      Do not close the browser when a crash is detected
                        (e10s only)
  -l LOG, --log LOG     Location to save log files
  --log-limit LOG_LIMIT
                        Log file size limit in MBs (default: no limit)
  -m MEMORY, --memory MEMORY
                        Process memory limit in MBs (default: no limit)
  -p PREFS, --prefs PREFS
                        Custom prefs.js file to use (default: profile default)
  -P PROFILE, --profile PROFILE
                        Profile to use. This is non-destructive. A copy of the
                        target profile will be used. (default: new temporary
                        profile is created)
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

##### Replaying a test case

    python -m ffpuppet <firefox_binary> -p <custom_prefs.js> -d -u <testcase>

This will open the provided test case file in Firefox using the provided prefs.js file and any log data (stderr, stdout, ASan logs... etc) will be dumped to the console when the browser process terminates.
