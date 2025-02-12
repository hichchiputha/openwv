use autocxx::include_cpp;

mod util;

mod init_data;
mod keys;
mod openwv;
mod session;
mod wvd_file;

use openwv::OpenWv;
include_cpp! {
    #include "content_decryption_module.h"
    safety!(unsafe)
    subclass!("cdm::ContentDecryptionModule_10", OpenWv)
    generate!("cdm::Host_10")
    generate_pod!("cdm::KeyInformation")
}

mod video_widevine {
    include!(concat!(env!("OUT_DIR"), "/video_widevine.rs"));
}

pub trait CdmError {
    fn cdm_exception(&self) -> ffi::cdm::Exception;
    fn cdm_system_code(&self) -> u32 {
        0
    }
}
