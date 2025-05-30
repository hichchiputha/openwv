use autocxx::include_cpp;

mod config;
mod util;

mod common_host;
mod content_key;
mod decrypt;
mod init_data;
mod license;
mod openwv;
mod service_certificate;
mod session;
mod signed_message;
mod wvd_file;

use openwv::OpenWv;
include_cpp! {
    #include "common_cdm.h"
    safety!(unsafe)
    // FIXME: We can directly subclass from `cdm::ContentDecryptionModule_NN`
    // here if autocxx ever supports multiple inheritance for subclasses.
    subclass!("cdm::CommonCdm", OpenWv)
    generate!("cdm::Host_10")
    generate!("cdm::Host_11")
    generate!("cdm::Buffer")
    generate!("cdm::DecryptedBlock")
    generate_pod!("cdm::KeyInformation")
    generate_pod!("cdm::InputBuffer_2")
    generate_pod!("cdm::SubsampleEntry")
    generate_pod!("cdm::Pattern")
}

// These are all just plain enums, totally safe to copy.
impl Copy for ffi::cdm::Status {}
impl Copy for ffi::cdm::Exception {}
impl Copy for ffi::cdm::EncryptionScheme {}
impl Copy for ffi::cdm::KeyStatus {}
impl Copy for ffi::cdm::InitDataType {}
impl Copy for ffi::cdm::SessionType {}
impl Copy for ffi::cdm::MessageType {}

mod video_widevine {
    include!(concat!(env!("OUT_DIR"), "/video_widevine.rs"));
}

pub trait CdmError {
    fn cdm_exception(&self) -> ffi::cdm::Exception;
    fn cdm_system_code(&self) -> u32 {
        0
    }
}
