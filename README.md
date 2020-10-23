FFPuppet
========

[![Build Status](https://travis-ci.com/MozillaSecurity/ffpuppet.svg?branch=master)](https://travis-ci.com/MozillaSecurity/ffpuppet)
[![codecov](https://codecov.io/gh/MozillaSecurity/ffpuppet/branch/master/graph/badge.svg)](https://codecov.io/gh/MozillaSecurity/ffpuppet)
[![Matrix](https://img.shields.io/badge/dynamic/json?color=green&label=chat&query=%24.chunk[%3F(%40.canonical_alias%3D%3D%22%23fuzzing%3Amozilla.org%22)].num_joined_members&suffix=%20users&url=https%3A%2F%2Fmozilla.modular.im%2F_matrix%2Fclient%2Fr0%2FpublicRooms&style=flat&logo=matrix)](https://riot.im/app/#/room/#fuzzing:mozilla.org)
[![PyPI](https://img.shields.io/pypi/v/ffpuppet)](https://pypi.org/project/ffpuppet)

FFPuppet is a Python module that automates browser process related tasks to aid in fuzzing. Happy bug hunting!

Are you [fuzzing](https://firefox-source-docs.mozilla.org/tools/fuzzing/index.html) the browser? [Grizzly](https://github.com/MozillaSecurity/grizzly) can help.

Installation
------------

##### To install after cloning the repository

    pip install --user -e <ffpuppet_repository>

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
copy the digest from the file and download it from `https://tooltool.mozilla-releng.net/sha512/<digest>`.
In either case, the file should be renamed to `minidump_stackwalk` and marked executable (or `minidump_stackwalk.exe`
on Windows).

Browser Builds
--------------

If you are looking for builds to use with FFPuppet here are a few options.

##### Taskcluster

Taskcluster has a collection of many different build types for multiple platforms and branches.
An index of the latest mozilla-central builds can be found [here](https://firefox-ci-tc.services.mozilla.com/tasks/index/gecko.v2.mozilla-central.latest.firefox/).
Or you can use [fuzzfetch](https://github.com/MozillaSecurity/fuzzfetch) (recommended) which is very helpful in automation.

##### Build your own

If you would like to compile your own build instructions can be found [here](https://developer.mozilla.org/en-US/docs/Mozilla/Developer_guide/Build_Instructions/Simple_Firefox_build).


Usage
-----

Once installed FFPuppet can be run using the following command:

    python -m ffpuppet

```
usage: __main__.py [-h] [-d] [--log-level LOG_LEVEL] [-e EXTENSION] [-p PREFS]
                   [-P PROFILE] [-u URL] [--xvfb] [-a ABORT_TOKEN]
                   [--launch-timeout LAUNCH_TIMEOUT] [-l LOGS]
                   [--log-limit LOG_LIMIT] [-m MEMORY]
                   [--poll-interval POLL_INTERVAL] [--save-all] [--gdb] [--rr]
                   [--valgrind]
                   binary

FFPuppet - Firefox process launcher and log collector. Happy bug hunting!

positional arguments:
  binary                Firefox binary to launch

optional arguments:
  -h, --help            show this help message and exit
  -d, --display-logs    Display summary of browser logs on process exit.
  --log-level LOG_LEVEL
                        Configure console logging. Options: DEBUG, INFO, WARN,
                        ERROR (default: INFO)

Browser Configuration:
  -e EXTENSION, --extension EXTENSION
                        Install extensions. Specify the path to the xpi or the
                        directory containing the unpacked extension.
  -p PREFS, --prefs PREFS
                        Custom prefs.js file to use (default: profile default)
  -P PROFILE, --profile PROFILE
                        Profile to use. This is non-destructive. A copy of the
                        target profile will be used. (default: temporary
                        profile)
  -u URL, --url URL     Server URL or path to local file to load.
  --xvfb                Use Xvfb (Linux only)

Issue Detection & Reporting:
  -a ABORT_TOKEN, --abort-token ABORT_TOKEN
                        Scan the browser logs for the given value and close
                        browser if detected. For example '-a ###!!!
                        ASSERTION:' would be used to detect soft assertions.
  --launch-timeout LAUNCH_TIMEOUT
                        Number of seconds to wait for the browser to become
                        responsive after launching. (default: 300)
  -l LOGS, --logs LOGS  Location to save browser logs. A sub-directory
                        containing the browser logs will be created.
  --log-limit LOG_LIMIT
                        Browser log file size limit in MBs (default: 0, no
                        limit)
  -m MEMORY, --memory MEMORY
                        Browser memory limit in MBs (default: 0, no limit)
  --poll-interval POLL_INTERVAL
                        Delay between checks for results (default: 0.5)
  --save-all            Always save logs. By default logs are saved only when
                        an issue is detected.

Available Debuggers:
  --gdb                 Use GDB (Linux only)
  --rr                  Use rr (Linux only)
  --valgrind            Use Valgrind (Linux only)
```

##### Replaying a test case

    python -m ffpuppet <firefox_binary> -p <custom_prefs.js> -d -u <testcase>

This will open the provided test case file in Firefox using the provided prefs.js file and any log data (stderr, stdout, ASan logs... etc) will be dumped to the console when the browser process terminates.

##### Prefs.js files

prefs.js files that can be used for fuzzing or other automated testing can be generated with [PrefPicker](https://github.com/MozillaSecurity/prefpicker).
