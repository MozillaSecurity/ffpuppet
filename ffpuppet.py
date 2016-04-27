import argparse
import os
import platform
import random
import shutil
import socket
import subprocess
import tempfile
import threading
import time

try:
    import psutil
except ImportError:
    pass

class LaunchException(Exception):
    pass

class FFPuppet(object):
    def __init__(self, use_profile=None, use_valgrind=False, use_xvfb=False):
        self._display = ':0'
        self._exit_code = None
        self._log = None
        self._log_fp = None
        self._nul = None
        self._mem_mon_thread = None
        self._platform = platform.system().lower()
        self._proc = None
        self._profile_dir = use_profile
        self._tmp_prof = use_profile is None # remove temp profile
        self._use_valgrind = use_valgrind
        self._xvfb = None

        if self._profile_dir is not None:
            if not os.path.isdir(self._profile_dir):
                raise IOError('Cannot find profile %s' % self._profile_dir)
            self._profile_dir = os.path.abspath(self._profile_dir)

        if use_valgrind:
            with open(os.devnull, "w") as fp:
                subprocess.call(
                    ['valgrind', '--version'],
                    stdout=fp,
                    stderr=fp) # TODO: improve this check

        if use_xvfb:
            self._nul = open(os.devnull, "w")
            # launch Xvfb
            for _ in range(10):
                # Find a screen value not in use.
                # NOTE: this limits number of possible Xvfb instances but 255 is lots
                self._display = ":%d" % random.randint(1, 255)
                try:
                    self._xvfb = subprocess.Popen(
                        ['/usr/bin/Xvfb', self._display, '-screen', '0', '1280x1024x24'],
                        shell=False,
                        stdout=self._nul,
                        stderr=self._nul
                    )
                    time.sleep(0.5) # wait to be sure Xvfb is running and doesn't just exit
                    if self._xvfb.poll() is None:
                        break # xvfb is running
                except OSError:
                    self._nul.close()
                    raise LaunchException('Could not find Xvfb!')

            if self._xvfb.poll() is not None:
                self._nul.close()
                raise LaunchException('Could not launch Xvfb!')


    def _create_profile(self):
        self._profile_dir = tempfile.mkdtemp(prefix='ffprof_')
        self.build_prefs(self._profile_dir)


    @staticmethod
    def build_prefs(file_dir):
        prefs = {
            'app.update.enabled':False,
            'app.update.staging.enabled':False,
            'browser.cache.disk.enable':False,
            'browser.cache.disk_cache_ssl':False,
            'browser.cache.memory.enable':False,
            'browser.cache.offline.enable':False,
            'browser.chrome.favicons':False,
            'browser.chrome.site_icons':False,
            'browser.displayedE10SNotice':2,
            'browser.dom.window.dump.enabled':True, # Prints messages to the (native) console
            'browser.EULA.override':True,
            'browser.firstrun.show.localepicker':False,
            'browser.firstrun.show.uidiscovery':False,
            'browser.microsummary.enabled':False,
            'browser.offline-apps.notify':False,
            'browser.rights.3.shown':True,
            'browser.safebrowsing.enabled':False,
            'browser.safebrowsing.malware.enabled':False,
            'browser.search.update':False,
            'browser.sessionhistory.max_total_viewers':1,
            'browser.sessionstore.resume_from_crash':False,
            'browser.shell.checkDefaultBrowser':False,
            'browser.startup.homepage':'"about:blank"',
            'browser.startup.homepage_override.mstone':'"ignore"',
            'browser.startup.page':0, # use about:blank
            'browser.tabs.remote.autostart':False, # disable e10s
            'browser.tabs.remote.autostart.1':False, # disable e10s
            'browser.tabs.remote.autostart.2':False, # disable e10s
            'browser.tabs.warnOnClose':False,
            'browser.tabs.warnOnCloseOtherTabs':False,
            'browser.webapps.checkForUpdates':0,
            'datareporting.policy.dataSubmissionEnabled':False,
            'datareporting.policy.dataSubmissionPolicyAcceptedVersion':2,
            'datareporting.healthreport.service.enabled':False,
            'datareporting.healthreport.service.firstRun':False,
            'datareporting.healthreport.uploadEnabled':False,
            'dom.allow_scripts_to_close_windows':True,
            'dom.disable_open_during_load':False, # Determines popup blocker behavior
            'dom.disable_window_flip':False, # Determines whether windows can be focus()ed via non-chrome JavaScript
            'dom.disable_window_move_resize':False,
            'dom.disable_window_status_change':False, # text in the browser status bar may be set by non-chrome JavaScript
            'dom.ipc.plugins.flash.subprocess.crashreporter.enabled':False,
            'dom.max_chrome_script_run_time':0,
            'dom.max_script_run_time':0,
            'dom.min_background_timeout_value':4,
            'dom.send_after_paint_to_content':True, # needed when using IMGCorpman with MozAfterPaint event
            'extensions.blocklist.enabled':False,
            'extensions.testpilot.runStudies':False,
            'extensions.update.enabled':False,
            'general.warnOnAboutConfig':False,
            'geo.enabled':False,
            'image.cache.size':0,
            'image.multithreaded_decoding.limit':1,
            'layout.debug.enable_data_xbl':True,
            'lightweightThemes.update.enabled':False,

            #'media.autoplay.enabled':False,
            'media.mediasource.enabled':True,
            'media.mediasource.mp4.enabled':True,
            'media.fragmented-mp4.enabled':True,
            'media.fragmented-mp4.exposed':True,
            'media.fragmented-mp4.ffmpeg.enabled':True,
            'media.fragmented-mp4.gmp.enabled':True,
            'media.ogg.enabled':True,
            'media.opus.enabled':True,
            #'media.use-blank-decoder':True,
            'media.wave.decoder.enabled':True,
            'media.wave.enabled':True,

            'network.http.max-connections':1,
            'network.http.spdy.enabled':False,
            'network.http.use-cache':False,
            'network.prefetch-next':False,
            #'network.proxy.share_proxy_settings':True,
            #'network.proxy.type':2,
            #'network.proxy.autoconfig_url':'"data:text/plain,function FindProxyForURL(url, host) ' \
            #                               '{ if (host == \'localhost\' || host == \'127.0.0.1\') ' \
            #                               '{ return \'DIRECT\'; } else { return \'PROXY 127.0.0.1:6\'; } }"',
            'network.network.protocol-handler.external.mailto':False,
            'nglayout.debug.disable_xul_cache':False,
            'plugins.hide_infobar_for_missing_plugin':True,
            'plugins.update.url':'""',
            'security.fileuri.strict_origin_policy':False,
            'security.OCSP.enabled':0,
            'shumway.disabled':True,
            'toolkit.startup.max_resumed_crashes':-1,
            'toolkit.telemetry.prompted':2,
            'toolkit.telemetry.rejected':True,
            'toolkit.telemetry.server':'""',
        }

        file_path = os.path.join(file_dir, 'prefs.js')
        with open(file_path, 'w') as fp:
            for key, value in prefs.items():
                fp.write('user_pref("%s", %s);\n' % (key, str(value).lower()))


    def close(self, save_log=None):
        if self._proc is not None:
            if self._proc.poll() is None:
                self._proc.terminate()
            self._exit_code = self._proc.wait()

        if self._log_fp is not None:
            self._log_fp.close()

            if save_log and os.path.isfile(self._log):
                if not os.path.dirname(save_log):
                    save_log = os.path.join(os.getcwd(), save_log)
                shutil.move(self._log, save_log)
            elif os.path.isfile(self._log):
                os.remove(self._log)

        # remove temporary profile directory
        if self._tmp_prof and self._profile_dir is not None and os.path.isdir(self._profile_dir):
            shutil.rmtree(self._profile_dir)

        # close Xfvb
        if self._xvfb is not None and self._xvfb.poll() is None:
            self._xvfb.terminate()
            self._xvfb.wait()

        if self._nul is not None:
            self._nul.close()

        if self._mem_mon_thread is not None:
            self._mem_mon_thread.join()


    def get_pid(self):
        return None if self._proc is None else self._proc.pid


    def launch(self, bin_path, launch_timeout=300, location=None, memory_limit=None):
        if launch_timeout is None or launch_timeout < 1:
            raise LaunchException("Launch timeout must be >= 1")

        bin_path = os.path.abspath(bin_path)
        if not os.path.isfile(bin_path):
            raise IOError('%s does not exist' % bin_path)

        env = os.environ
        env['DISPLAY'] = self._display
        if self._use_valgrind:
            # https://developer.gimp.org/api/2.0/glib/glib-running.html#G_DEBUG
            env['G_DEBUG'] = 'gc-friendly'
        # https://developer.gimp.org/api/2.0/glib/glib-running.html#G_SLICE
        env['G_SLICE'] = 'always-malloc'
        env['MOZ_CC_RUN_DURING_SHUTDOWN'] = '1'
        env['MOZ_CRASHREPORTER_DISABLE'] = '1'
        env['MOZ_GDB_SLEEP'] = '0'
        env['XRE_NO_WINDOWS_CRASH_DIALOG'] = '1'
        env['XPCOM_DEBUG_BREAK'] = 'warn'

        # setup Address Sanitizer options if not set manually
        if not env.has_key('ASAN_OPTIONS'):
            env['ASAN_OPTIONS'] = ' '.join((
                'alloc_dealloc_mismatch=0',
                'allocator_may_return_null=0',
                'check_initialization_order=1',
                'check_malloc_usable_size=0',
                #'detect_leaks=1',
                'detect_stack_use_after_return=0',
                'disable_core=1',
                'strict_init_order=1',
                'strict_memcmp=0',
                'symbolize=1'
            ))

        if os.path.isfile(os.path.join(os.path.dirname(bin_path), 'llvm-symbolizer')):
            env['ASAN_SYMBOLIZER_PATH'] = os.path.join(os.path.dirname(bin_path), 'llvm-symbolizer')
            env['MSAN_SYMBOLIZER_PATH'] = os.path.join(os.path.dirname(bin_path), 'llvm-symbolizer')
        if os.environ.has_key('ASAN_SYMBOLIZER_PATH'):
            env['ASAN_SYMBOLIZER_PATH'] = os.environ['ASAN_SYMBOLIZER_PATH']
            env['MSAN_SYMBOLIZER_PATH'] = os.environ['ASAN_SYMBOLIZER_PATH']
            if not os.path.isfile(env['ASAN_SYMBOLIZER_PATH']):
                print('WARNING: Invalid ASAN_SYMBOLIZER_PATH (%s)' % (
                    env['ASAN_SYMBOLIZER_PATH']
                ))

        if self._profile_dir is None:
            self._create_profile()

        fd, self._log = tempfile.mkstemp(
            suffix='_log.txt',
            prefix=time.strftime('ffp_%Y-%m-%d_%H-%M-%S_')
        )
        os.close(fd)
        self._log_fp = open(self._log, 'wb')

        init_soc = self._bootstrap_start(timeout=launch_timeout)
        # build Firefox launch command
        cmd = [
            bin_path,
            '-no-remote',
            '-profile',
            self._profile_dir,
            'http://127.0.0.1:%d' % init_soc.getsockname()[1]
        ]

        if self._use_valgrind:
            cmd = [
                'valgrind',
                '-q',
                #'---error-limit=no',
                '--smc-check=all-non-file',
                '--show-mismatched-frees=no',
                '--show-possibly-lost=no',
                '--read-inline-info=yes',
                #'--leak-check=full',
                '--trace-children=yes',
                #'--track-origins=yes',
                '--vex-iropt-register-updates=allregs-at-mem-access'
            ] + cmd # enable valgrind

        if self._platform == 'windows':
            self._proc = subprocess.Popen(
                cmd,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                env=env,
                shell=False,
                stderr=self._log_fp,
                stdout=self._log_fp
            )
        else: # not windows
            self._proc = subprocess.Popen(
                cmd,
                env=env,
                shell=False,
                stderr=self._log_fp,
                stdout=self._log_fp
            )

        self._bootstrap_finish(init_soc, timeout=launch_timeout, url=location)

        if memory_limit is not None:
            # launch memory monitor thread
            self._mem_mon_thread = threading.Thread(
                target=self._memory_monitor,
                args=(self._proc, memory_limit)
            )
            self._mem_mon_thread.start()


    def is_running(self):
        return self._proc is not None and self._proc.poll() is None


    def _bootstrap_start(self, timeout=60):
        while True:
            try:
                init_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                init_soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                init_soc.settimeout(timeout) # don't catch socket.timeout
                init_soc.bind(('127.0.0.1', random.randint(1024, 0xFFFF)))
                init_soc.listen(0)
                break
            except socket.error as soc_e:
                if soc_e.errno == 98: # Address already in use
                    continue
                raise soc_e

        return init_soc


    def _bootstrap_finish(self, init_soc, timeout=60, url=None):
        conn = None
        max_wait_time = time.time() + timeout
        try:
            # wait for browser test connection
            while True:
                try:
                    init_soc.settimeout(1.0)
                    conn, _ = init_soc.accept()
                    conn.settimeout(timeout)
                except socket.timeout:
                    if max_wait_time <= time.time():
                        # timeout waiting browser connection
                        raise LaunchException("Launching browser timed out")
                    elif not self.is_running():
                        # browser must have died
                        raise LaunchException("Failure during browser startup")
                    continue # have not received connection
                break # received connection

            # handle browser test connection in coming data
            while len(conn.recv(4096)) == 4096:
                pass

            # redirect to about:blank
            body = "<script>window.onload=function(){window.location='%s'}</script>" % (
                "about:blank" if url is None else url)

            # send response
            conn.sendall(
                "HTTP/1.1 200 OK\r\n" \
                "Cache-Control: max-age=0, no-cache\r\n" \
                "Content-Length: %s\r\n" \
                "Content-Type: text/html; charset=UTF-8\r\n" \
                "Connection: close\r\n\r\n%s" % (len(body), body)
            )

        except socket.error:
            raise LaunchException("Failed to launch browser")

        except socket.timeout:
            raise LaunchException("Test connection timed out")

        finally:
            if conn is not None:
                conn.close()
            init_soc.close()


    def read_log(self, offset=None, from_what=os.SEEK_SET, count=None):
        '''
        read the contents of the log file

        returns a string containing the contents for the log file
        '''

        with open(self._log, "r") as fp:
            if offset is not None:
                fp.seek(offset, from_what)

            if count:
                return fp.read(count)
            return fp.read()


    @staticmethod
    def _memory_monitor(proc, limit):
        try:
            try:
                ps_proc = psutil.Process(proc.pid)
            except psutil.NoSuchProcess:
                # process is dead?
                return
        except NameError:
            # psutil not installed
            return

        while proc.poll() is None:
            try:
                proc_mem = ps_proc.memory_info().rss
                for child in ps_proc.children(recursive=True):
                    try:
                        proc_mem += child.memory_info().rss
                    except psutil.NoSuchProcess:
                        pass
            except psutil.NoSuchProcess:
                # process is dead?
                break

            # did we hit the memory limit?
            if proc_mem >= limit:
                proc.terminate()
                break

            time.sleep(0.1) # check 10x a second

        return


    def wait(self, timeout=0):
        '''
        wait for process to terminate

        returns return code if process exits and None if timeout expired
        '''

        if timeout <= 0:
            return self._proc.wait() # blocks until process exits

        end = time.time() + timeout
        while time.time() < end:
            if self._proc.poll() is not None:
                return self._proc.poll()
            time.sleep(0.1)

        return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firefox launcher/wrapper')
    parser.add_argument(
        'binary',
        help='Binary to run')
    parser.add_argument(
        '-l', '--log', default=None,
        help='log file name')
    parser.add_argument(
        '-m', '--memory', type=int, default=None,
        help='Process memory limit in MBs')
    parser.add_argument(
        '-p', '--profile', default=None,
        help='profile to use')
    parser.add_argument(
        '-t', '--timeout', type=int, default=60,
        help='launch timeout')
    parser.add_argument(
        '-u', '--url', default=None,
        help='URL to load')
    parser.add_argument(
        '--valgrind', default=False, action='store_true',
        help='Use valgrind')
    parser.add_argument(
        '--xvfb', default=False, action='store_true',
        help='Use xvfb')

    args = parser.parse_args()

    ffp = FFPuppet(
        use_profile=args.profile,
        use_valgrind=args.valgrind,
        use_xvfb=args.xvfb)
    try:
        ffp.launch(
            args.binary,
            location=args.url,
            launch_timeout=args.timeout,
            memory_limit=args.memory * 1024 * 1024 if args.memory else None)
        ffp.wait()
    except KeyboardInterrupt:
        print("Ctrl+C detected. Shutting down...")
    finally:
        ffp.close(args.log)

