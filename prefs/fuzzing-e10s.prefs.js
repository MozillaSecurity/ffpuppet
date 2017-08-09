user_pref("app.update.enabled", false);
user_pref("app.update.stage.enabled", false); // domfuzz
user_pref("app.update.staging.enabled", false);
user_pref("app.update.url.android", ""); // domfuzz
user_pref("browser.EULA.override", true);
user_pref("browser.aboutHomeSnippets.updateUrl", "nonexistent://test"); // domfuzz
user_pref("browser.addon-watch.interval", -1); // domfuzz
user_pref("browser.cache.disk.enable", false);
user_pref("browser.cache.disk_cache_ssl", false);
user_pref("browser.cache.memory.enable", false);
user_pref("browser.cache.offline.enable", false);
user_pref("browser.chrome.favicons", false);
user_pref("browser.chrome.site_icons", false);
user_pref("browser.displayedE10SNotice", 5);
user_pref("browser.dom.window.dump.enabled", true); // Prints messages to the (native) console
user_pref("browser.firstrun.show.localepicker", false);
user_pref("browser.firstrun.show.uidiscovery", false);
user_pref("browser.newtabpage.directory.ping", ""); // domfuzz
user_pref("browser.newtabpage.directory.source", 'data:application/json,{"testing":1}'); // domfuzz
user_pref("browser.newtabpage.enhanced", false); // domfuzz
user_pref("browser.newtabpage.introShown", true); // domfuzz
user_pref("browser.newtabpage.updateIntroShown", true); // domfuzz
user_pref("browser.offline-apps.notify", false);
user_pref("browser.pageThumbs.enabled", false); // domfuzz
user_pref("browser.pagethumbnails.capturing_disabled", true); // domfuzz
user_pref("browser.reader.detectedFirstArticle", true); // domfuzz
user_pref("browser.rights.3.shown", true);
user_pref("browser.rights.override", true); // domfuzz
user_pref("browser.safebrowsing.enabled", false);
user_pref("browser.safebrowsing.blockedURIs.enabled", false);
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.search.geoip.url", "");
user_pref("browser.search.suggest.enabled", false); // domfuzz
user_pref("browser.search.update", false);
user_pref("browser.sessionhistory.max_entries", 0);
user_pref("browser.sessionhistory.max_total_viewers", 0);
user_pref("browser.sessionstore.resume_from_crash", false);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.snippets.enabled", false); // domfuzz
user_pref("browser.snippets.firstrunHomepage.enabled", false); // domfuzz
user_pref("browser.snippets.syncPromo.enabled", false); // domfuzz
user_pref("browser.ssl_override_behavior", 1); // domfuzz
user_pref("browser.startup.homepage", "about:blank");
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("browser.startup.page", 0); // use about:blank
user_pref("browser.tabs.warnOnClose", false);
user_pref("browser.tabs.warnOnCloseOtherTabs", false);
user_pref("browser.urlbar.userMadeSearchSuggestionsChoice", true); // domfuzz
user_pref("browser.warnOnQuit", false); // domfuzz
user_pref("browser.webapps.checkForUpdates", 0);
user_pref("canvas.capturestream.enabled", true);
user_pref("canvas.customfocusring.enabled", true);
user_pref("canvas.focusring.enabled", true);
user_pref("canvas.hitregions.enabled", true);
user_pref("canvas.imagebitmap_extensions.enabled", true);
user_pref("captivedetect.canonicalURL", "");
user_pref("datareporting.healthreport.service.enabled", false);
user_pref("datareporting.healthreport.service.firstRun", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("datareporting.policy.dataSubmissionPolicyAcceptedVersion", 2);
user_pref("datareporting.policy.dataSubmissionPolicyBypassNotification", true); // domfuzz
user_pref("dom.allow_scripts_to_close_windows", true);
user_pref("dom.always_stop_slow_scripts", true); // domfuzz
user_pref("dom.disable_open_during_load", false); // Determines popup blocker behavior
user_pref("dom.disable_window_flip", false); // Determines whether windows can be focus()ed via non-chrome JavaScript
user_pref("dom.disable_window_move_resize", false);
user_pref("dom.disable_window_status_change", false); // text in the browser status bar may be set by non-chrome JavaScript
user_pref("dom.ipc.plugins.flash.subprocess.crashreporter.enabled", false);
user_pref("dom.max_chrome_script_run_time", 0);
user_pref("dom.max_script_run_time", 0);
user_pref("dom.min_background_timeout_value", 4);
user_pref("dom.send_after_paint_to_content", true); // needed when using IMGCorpman with MozAfterPaint event
user_pref("dom.successive_dialog_time_limit", 0); // domfuzz
user_pref("extensions.allow-non-mpc-extensions", true); // Required to load fuzzPriv
user_pref("extensions.autoDisableScopes", 0); // domfuzz
user_pref("extensions.blocklist.enabled", false);
user_pref("extensions.enabledScopes", 5); // domfuzz
user_pref("extensions.getAddons.cache.enabled", false); // domfuzz
user_pref("extensions.installDistroAddons", false); // domfuzz
user_pref("extensions.showMismatchUI", false); // domfuzz
user_pref("extensions.testpilot.runStudies", false);
user_pref("extensions.update.enabled", false);
user_pref("extensions.update.notifyUser", false); // domfuzz
user_pref("general.useragent.updates.enabled", false); // domfuzz
user_pref("general.warnOnAboutConfig", false);
user_pref("geo.enabled", false);
user_pref("gfx.canvas.azure.accelerated", true);
user_pref("gfx.color_management.mode", 2); // domfuzz
user_pref("image.cache.size", 0);
user_pref("image.multithreaded_decoding.limit", 1);
user_pref("javascript.options.gczeal", 0); // domfuzz
user_pref("layers.acceleration.disabled", true);
user_pref("layers.acceleration.force-enabled", true);
user_pref("layout.css.ruby.enabled", true);
user_pref("layout.css.vertical-text.enabled", true);
user_pref("layout.debug.enable_data_xbl", true);
user_pref("layout.spammy_warnings.enabled", false); // domfuzz
user_pref("lightweightThemes.update.enabled", false);
user_pref("media.apple.mp3.enabled", true);
user_pref("media.apple.mp4.enabled", true);
user_pref("media.audio_data.enabled", true);
//user_pref("media.autoplay.enabled", false);
//user_pref("media.forcestereo.enabled", true);
user_pref("media.fragmented-mp4.enabled", true);
user_pref("media.fragmented-mp4.exposed", true);
user_pref("media.fragmented-mp4.ffmpeg.enabled", true);
user_pref("media.fragmented-mp4.gmp.enabled", true);
user_pref("media.gmp-manager.url.override", "http://127.0.0.1:6/dummy-gmp-manager.xml"); // domfuzz
user_pref("media.mediasource.enabled", true);
user_pref("media.mediasource.mp4.enabled", true);
user_pref("media.num-decode-threads", 1);
user_pref("media.peerconnection.aec", 1); // domfuzz
user_pref("media.peerconnection.aec_enabled", true); // domfuzz
user_pref("media.peerconnection.agc", 1); // domfuzz
user_pref("media.peerconnection.agc_enabled", false); // domfuzz
user_pref("media.peerconnection.default_iceservers", '[{"url": "stun:23.21.150.121"}]'); // domfuzz
user_pref("media.peerconnection.noise", 1); // domfuzz
user_pref("media.peerconnection.noise_enabled", false); // domfuzz
user_pref("media.peerconnection.turn.disable", false); // domfuzz
user_pref("media.peerconnection.use_document_iceservers", true); // domfuzz
//user_pref("media.resampling.enabled", true);
//user_pref("media.resampling.rate", 49000);
user_pref("media.track.enabled", true);
user_pref("media.use-blank-decoder", false);
user_pref("media.useAudioChannelAPI", true);
user_pref("media.webaudio.enabled", true);
user_pref("media.webspeech.recognition.enable", true);
user_pref("network.http.response.timeout", 1); // max time to wait for connection (default is 300)
user_pref("network.http.spdy.enabled", false);
user_pref("network.http.use-cache", false);
user_pref("network.jar.open-unsafe-types", true); // domfuzz
user_pref("network.manage-offline-status", false); // domfuzz
user_pref("network.network.protocol-handler.external.mailto", false);
user_pref("network.prefetch-next", false); // helps keep browser and fuzzer sync'd
//user_pref("network.proxy.autoconfig_url", "data:text/plain,function FindProxyForURL(url, host) " +
//                                          "{ if (host == 'localhost' || host == '127.0.0.1') " +
//                                          "{ return 'DIRECT'; } else { return 'PROXY 127.0.0.1:6'; } }"); // domfuzz
//user_pref("network.proxy.share_proxy_settings", true); // domfuzz
//user_pref("network.proxy.type", 2); // domfuzz
user_pref("network.proxy.use_direct_on_fail", false); // domfuzz
user_pref("nglayout.debug.disable_xul_cache", false);
user_pref("plugin.disable", true);
user_pref("plugins.hide_infobar_for_missing_plugin", true);
user_pref("plugins.update.url", "");
user_pref("privacy.trackingprotection.pbmode.enabled", false); // domfuzz
user_pref("security.OCSP.enabled", 0);
user_pref("security.fileuri.strict_origin_policy", false);
user_pref("shumway.disabled", true);
user_pref("toolkit.startup.max_resumed_crashes", -1);
user_pref("toolkit.telemetry.prompted", 2);
user_pref("toolkit.telemetry.rejected", true);
user_pref("toolkit.telemetry.server", "");
user_pref("toolkit.telemetry.unified", false); // domfuzz
user_pref("xpinstall.signatures.required", false); // domfuzz

//user_pref("gfx.blocklist.all", -1); // force unblock gfx cards
