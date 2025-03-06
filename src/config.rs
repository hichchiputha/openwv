/// Compile-time configuration for OpenWV. Because we cannot access files
/// outside the CDM sandbox, this holds various parameters that would typically
/// go in a configuration file. See the comments on the structs and enums below
/// for information on the meaning of each parameter.
pub const CONFIG: OpenWvConfig = OpenWvConfig {
    widevine_device: include_bytes!("embedded.wvd"),
    log_level: log::LevelFilter::Info,
};

pub struct OpenWvConfig {
    /// A pywidevine `.wvd` file containing the private key and Client ID to
    /// present in license requests. You must obtain this on your own.
    pub widevine_device: &'static [u8],

    /// This can be overridden by the OPENWV_LOG environment variable, but some
    /// browsers like Firefox don't let CDMs see the full environment.
    pub log_level: log::LevelFilter,
}
