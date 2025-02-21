## Installation

### Firefox
1. Open `about:support` and note your "Profile Directory". Then, in
   `about:config`, set `media.gmp-widevinecdm.autoupdate` to `false` (creating
   it if needed) and set `media.gmp-widevinecdm.version` to `openwv` (or to any
   other name for the directory you create in step 3).
2. Navigate to `gmp-widevinecdm/` within your profile directory.
3. Create a subdirectory named `openwv` and place OpenWV's `libwidevinecdm.so`
   and `manifest.json` directly inside it. Note that you **must** use OpenWV's
   `manifest.json` instead of Google's, as Firefox uses the manifest to
   determine what video codecs a CDM supports.

### Chrome/Chromium
1. Open `chrome://version/` and note the **parent** directory of your "Profile
   Path". This is Chrome's "User Data Directory".
2. Navigate to `WidevineCdm/` within the user data directory.
3. If there are any existing subdirectories, delete them.
4. Create a subdirectory named `9999` (or any numeric version greater than that
   of Google's CDM), and place OpenWV's `manifest.json` directly inside it.
5. Beside `manifest.json`, create a directory named `_platform_specific` with
   a directory named `{linux,win,mac}_{x86,x64,arm,arm64}`, as appropriate,
   inside it. For example, `_platform_specific/linux_x64/` on 64-bit Intel
   Linux. Place OpenWV's `libwidevinecdm.so` in this innermost directory.

### Kodi (via [InputStream Adaptive](https://github.com/xbmc/inputstream.adaptive))
1. In Kodi, navigate to "Add-ons > My add-ons > VideoPlayer InputStream >
   InputStream Adaptive" and select "Configure".
2. Ensure the settings level (the gear icon) is set to at least "Advanced".
3. In the "Expert" tab, set "Decrypter path" to the directory where you've put
   OpenWV's `libwidevinecdm.so`. Don't include the filename itself.

## References

The APIs, algorithms, and data types used in OpenWV were gathered from a variety of official and
unofficial sources:

- API headers (`third-party/cdm/`) come from [the Chromium source][chromium-cdm-api].
- Widevine protobuf definitions (`third-party/widevine_protos.pb`) were extracted from
  `chromecast_oss/chromium/src/out_chromecast_steak/release/pyproto/` in Google's
  [Chromecast Ultra v1.42 source drop][steak-1.42-oss].
- The `.wvd` format and many algorithmic details come from the [pywidevine][pywidevine] project.

[chromium-cdm-api]: https://chromium.googlesource.com/chromium/cdm/
[pywidevine]: https://github.com/devine-dl/pywidevine/
[steak-1.42-oss]: https://drive.google.com/file/d/153TuZqh9FTBKRabGx686tbJefeqM2sJf/view?usp=drive_link
