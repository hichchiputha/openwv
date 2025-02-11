use autocxx::include_cpp;

mod util;

mod init_data;
mod openwv;
mod wvd_file;

use openwv::OpenWv;
include_cpp! {
    #include "content_decryption_module.h"
    safety!(unsafe)
    subclass!("cdm::ContentDecryptionModule_10", OpenWv)
    generate!("cdm::Host_10")
}

mod video_widevine {
    include!(concat!(env!("OUT_DIR"), "/video_widevine.rs"));
}
