FFPuppet
========

[![CI](https://github.com/MozillaSecurity/ffpuppet/actions/workflows/ci.yml/badge.svg)](https://github.com/MozillaSecurity/ffpuppet/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/MozillaSecurity/ffpuppet/branch/master/graph/badge.svg)](https://codecov.io/gh/MozillaSecurity/ffpuppet)
[![Matrix](https://img.shields.io/badge/chat-%23fuzzing-green?logo=matrix)](https://matrix.to/#/#fuzzing:mozilla.org)
[![PyPI](https://img.shields.io/pypi/v/ffpuppet)](https://pypi.org/project/ffpuppet)

FFPuppet is a Python module that automates browser process related tasks to aid in fuzzing. Happy bug hunting!

Are you [fuzzing](https://firefox-source-docs.mozilla.org/tools/fuzzing/index.html) the browser? [Grizzly](https://github.com/MozillaSecurity/grizzly) can help.

Installation
------------

##### To install the latest version from PyPI

    pip install ffpuppet

##### Xvfb on Linux

On Linux `xvfb` can be used in order to run headless (this is not the same as Firefox's `-headless` mode).

To install `xvfb` on Ubuntu run:

    apt-get install xvfb

##### Install minidump-stackwalk

`minidump-stackwalk` is used to collect crash reports from minidump files. More
information can be found [here](https://lib.rs/crates/minidump-stackwalk).

Browser Builds
--------------

If you are looking for builds to use with FFPuppet there are a few options.

##### Download a build

[fuzzfetch](https://github.com/MozillaSecurity/fuzzfetch) is the recommended method for obtaining builds and is also very helpful in automation.

Taskcluster has a collection of many different build types for multiple platforms and branches.
An index of the latest mozilla-central builds can be found [here](https://firefox-ci-tc.services.mozilla.com/tasks/index/gecko.v2.mozilla-central.latest.firefox/).

##### Create your own build

If you would like to compile your own, build instructions can be found [here](https://firefox-source-docs.mozilla.org/setup/index.html). When using `minidump-stackwalk`
breakpad [symbols](https://firefox-source-docs.mozilla.org/setup/building_with_debug_symbols.html#building-with-debug-symbols) are required for symbolized stacks.

Usage
-----

Once installed FFPuppet can be run using the following command:

    ffpuppet <firefox_binary>

##### Replaying a test case

    ffpuppet <firefox_binary> -p <custom_prefs.js> -d -u <testcase>

This will open the provided test case file in Firefox using the provided prefs.js file. Any log data (stderr, stdout, ASan logs... etc) will be dumped to the console if a failure is detected. [Grizzly Replay](https://github.com/MozillaSecurity/grizzly/wiki/Grizzly-Replay) is recommended for replaying test cases.

##### Prefs.js files

prefs.js files that can be used for fuzzing or other automated testing can be generated with [PrefPicker](https://github.com/MozillaSecurity/prefpicker).
