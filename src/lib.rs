use autocxx::include_cpp;

mod util;

mod openwv;

use openwv::OpenWv;
include_cpp! {
    #include "content_decryption_module.h"
    safety!(unsafe)
    subclass!("cdm::ContentDecryptionModule_10", OpenWv)
    generate!("cdm::Host_10")
}
