/// Compile-time configuration for OpenWV. Because we cannot access files
/// outside the CDM sandbox, this holds various parameters that would typically
/// go in a configuration file. See the comments on the structs and enums below
/// for information on the meaning of each parameter.
pub const CONFIG: OpenWvConfig = OpenWvConfig {
    widevine_device: include_bytes!("../embedded.wvd"),
    log_level: log::LevelFilter::Info,
    encrypt_client_id: EncryptClientId::Always,
};

pub struct OpenWvConfig {
    /// A pywidevine `.wvd` file containing the private key and Client ID to
    /// present in license requests. You must obtain this on your own.
    pub widevine_device: &'static [u8],

    /// This can be overridden by the OPENWV_LOG environment variable, but some
    /// browsers like Firefox don't let CDMs see the full environment.
    pub log_level: log::LevelFilter,

    /// Policy for when to encrypt Client ID. Chrome uses `Always` if Verified
    /// Media Path is in use and `Never` otherwise. Similarly, Chrome OS uses
    /// `Always` if Platform Verification is enabled (i.e. when Developer Mode
    /// is off) and `Never` otherwise. The Android devices I've tested use
    /// `Always`. Chromecasts use `Never`.
    pub encrypt_client_id: EncryptClientId,
}

#[allow(dead_code)]
pub enum EncryptClientId {
    /// Always send plaintext ClientIdentification, even if the application
    /// explicitly provided an encryption key with `setServerCertificate()`.
    Never,

    /// Send encrypted ClientIdentification if the application called
    /// `setServerCertificate()`. Send plaintext otherwise.
    IfCertificateSet,

    /// Always send encrypted ClientIdentification. If `setServerCertificate()`
    /// wasn't called, this results in an extra round trip to request the
    /// certificate from the license server.
    Always,
}
