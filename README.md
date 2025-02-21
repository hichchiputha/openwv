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
