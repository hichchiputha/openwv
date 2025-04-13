OpenWV is a free and open-source reimplementation of Google's Widevine Content
Decryption Module (CDM), the portion of the Widevine DRM system that runs in
your browser, obtains content keys for protected media, and decrypts the media
using those keys. OpenWV is a drop-in replacement for Google's [official,
proprietary CDM][official-cdm] and implements the same [shared library
API][chromium-cdm-api].

OpenWV does **not** come with a device identity and will not work without one.
A device identity, typically stored as a `.wvd` file, contains metadata about a
Widevine client as well as a private key that authenticates that client to
Widevine license servers. Depending on the client's identity, a license server
may give it low-value content keys (e.g. standard definition only), high-value
keys (e.g. HD/UHD), or no keys at all. If you want to use OpenWV, you must
obtain an appropriate `.wvd` file yourself and include it in the build as
described below.

[official-cdm]: https://hg-edge.mozilla.org/mozilla-central/file/tip/toolkit/content/gmp-sources/widevinecdm.json

## Compilation

Because CDM libraries are heavily sandboxed by browsers, OpenWV cannot read
configuration from disk at runtime. That means that all configuration,
including the device identity mentioned above, must be present at build-time.
As such, there are no official precompiled binaries: **the only way to use
OpenWV is to build it yourself**.

To get yourself a copy of OpenWV, follow these steps:

1. Make sure both [Git][git] and [Rust][rust] are installed on your system.
2. Clone this repository: `git clone https://github.com/tchebb/openwv.git`
3. Enter the newly-cloned `openwv/` directory, then fetch Git submodules:
   `git submodule init && git submodule update`
4. Place your `.wvd` file in the project root (alongside this README) and name
   it `embedded.wvd`. You may set other configuration options as desired by
   editing the `CONFIG` variable in `src/config.rs`.
5. Build the library: `cargo build --release`
6. Find the built library in `target/release/`. Depending on your OS, it will
   be named `libwidevinecdm.so`, `widevinecdm.dll`, or `libwidevinecdm.dylib`.

[git]: https://git-scm.com/downloads
[rust]: https://rustup.rs/

## Installation

*NOTE: In these instructions, "the OpenWV library" means the library you built
in the last section—`libwidevinecdm.so` on Linux, `widevinecdm.dll` on Windows,
or `libwidevinecdm.dylib` on macOS.*

### Firefox (version 136+ only)
1. Open `about:support` and note your "Profile Directory".
2. Open `about:config`. Set `media.gmp-widevinecdm.autoupdate` to `false`
   (creating it if needed), and set `media.gmp-widevinecdm.version` to `openwv`
   (or to any other name for the directory you create in step 3).
3. Navigate to `gmp-widevinecdm/` within your profile directory.
4. Create a subdirectory named `openwv` and place the OpenWV library and
   `manifest-firefox.json`, renamed to `manifest.json`, inside it. Note that
   you **must** use OpenWV's `manifest.json` instead of Google's, as Firefox
   will not play video if we falsely advertise decoding support.

### Chrome/Chromium
1. Open `chrome://version/` and note the **parent** directory of your "Profile
   Path". This is Chrome's "User Data Directory".
2. Navigate to `WidevineCdm/` within the user data directory.
3. If there are any existing subdirectories, delete them.
4. Create a subdirectory named `9999` (or any numeric version greater than that
   of Google's CDM), and place OpenWV's `manifest-chromium.json`, renamed to
   `manifest.json`, inside it.
5. Beside `manifest.json`, create a directory named `_platform_specific` with
   a directory named `{linux,win,mac}_{x86,x64,arm,arm64}`, as appropriate,
   inside it. For example, `_platform_specific/linux_x64/` on 64-bit Intel
   Linux. Place the OpenWV library in this innermost directory.
6. On Linux only, launch and quit the browser once before playing any Widevine-
   protected media. OpenWV will not be loaded on the first launch, due to an
   [implementation quirk][chromium-hint] of Chromium.

### Kodi (via [InputStream Adaptive](https://github.com/xbmc/inputstream.adaptive))
1. Build OpenWV with `encrypt_client_id: EncryptClientId::Never`, as Kodi
   cannot handle service certificate request messages as of this writing
   (InputStream Adaptive v21.5.10).
2. In Kodi, navigate to "Add-ons > My add-ons > VideoPlayer InputStream >
   InputStream Adaptive" and select "Configure".
3. Ensure the settings level (the gear icon) is set to at least "Advanced".
4. In the "Expert" tab, set "Decrypter path" to the directory where you've put
   the OpenWV library. Don't include the library name itself.

[chromium-hint]: https://source.chromium.org/chromium/chromium/src/+/main:chrome/common/media/cdm_registration.cc;l=163-187;drc=e1e92741ef5eac000a66a712ae1af2c44781bc40

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
