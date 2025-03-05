use autocxx::include_cpp;

mod util;

mod decrypt;
mod init_data;
mod keys;
mod license;
mod openwv;
mod service_certificate;
mod session;
mod wvd_file;

use openwv::OpenWv;
include_cpp! {
    #include "content_decryption_module.h"
    safety!(unsafe)
    subclass!("cdm::ContentDecryptionModule_11", OpenWv)
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
