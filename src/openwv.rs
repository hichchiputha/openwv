use std::ffi::{c_char, c_int, c_uchar, c_void};
use std::pin::Pin;
use std::ptr::null_mut;
use std::slice;

use crate::ffi::cdm;
use crate::util::cstr_from_str;

use autocxx::subclass::{subclass, CppSubclassSelfOwned};
use log::{debug, error};

// To change this, also change ContentDecryptionModule_NN and Host_NN.
const CDM_INTERFACE: c_int = 10;

#[no_mangle]
extern "C" fn InitializeCdmModule_4() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();
    debug!("InitializeCdmModule()")
}

#[no_mangle]
extern "C" fn DeinitializeCdmModule() {
    debug!("DeinitializeCdmModule()")
}

const WV_KEY_SYSTEM: &[u8] = b"com.widevine.alpha";
type GetCdmHostFunc = unsafe extern "C" fn(c_int, *mut c_void) -> *mut c_void;
#[no_mangle]
extern "C" fn CreateCdmInstance(
    cdm_interface_version: c_int,
    key_system: *const c_char,
    key_system_size: u32,
    get_cdm_host_func: Option<GetCdmHostFunc>,
    user_data: *mut c_void,
) -> *mut cdm::ContentDecryptionModule_10 {
    debug!("CreateCdmInstance()");

    if cdm_interface_version != CDM_INTERFACE {
        error!(
            "Unsupported interface version {} requested, expected {}",
            cdm_interface_version, CDM_INTERFACE
        );
        return null_mut();
    }

    if key_system.is_null() {
        error!("Got NULL key_system pointer");
        return null_mut();
    }

    // SAFETY: The API contract requires that `key_system`` be a valid pointer
    // to a buffer of length `key_system_size``.
    let key_system_str =
        unsafe { slice::from_raw_parts(key_system as *const c_uchar, key_system_size as _) };

    if key_system_str != WV_KEY_SYSTEM {
        error!(
            "Unsupported key system '{}', expected '{}'",
            key_system_str.escape_ascii(),
            WV_KEY_SYSTEM.escape_ascii()
        );
        return null_mut();
    }

    // SAFETY: API contract requires that `get_cdm_host_func` returns an
    // appropriate C++ Host_NN object.
    let host_raw: *mut cdm::Host_10 = match get_cdm_host_func {
        None => {
            error!("Got NULL get_cdm_host_func pointer");
            return null_mut();
        }
        Some(f) => unsafe { f(CDM_INTERFACE, user_data) }.cast(),
    };

    // SAFETY: Although not explicitly documented, we can infer from the fact
    // that the Host_NN class does not allow us to move or free it that this
    // object remains owned by C++. As such, we only want a reference.
    let host = match unsafe { host_raw.as_mut() } {
        None => {
            error!("No host functions available");
            return null_mut();
        }
        // SAFETY: Objects owned by C++ never move.
        Some(p) => unsafe { Pin::new_unchecked(p) },
    };

    let openwv = OpenWv::new_self_owned(OpenWv {
        host,
        cpp_peer: Default::default(),
    });

    let mut openwv_ref = openwv.borrow_mut();
    let cdm = openwv_ref.pin_mut();

    // SAFETY: C++ will not try to move the pointer we give it.
    unsafe { cdm.get_unchecked_mut() }
}

const VERSION_STR: &std::ffi::CStr =
    cstr_from_str(concat!("OpenWV version ", env!("CARGO_PKG_VERSION"), "\0"));
#[no_mangle]
extern "C" fn GetCdmVersion() -> *const c_char {
    VERSION_STR.as_ptr()
}

// This is needed because autocxx's `#[subclass]` currently hardcodes an `ffi::`
// module prefix. If autocxx gets more hygienic, we should remove this.
use crate::ffi;

#[subclass(self_owned)]
pub struct OpenWv {
    host: Pin<&'static mut cdm::Host_10>,
}

impl cdm::ContentDecryptionModule_10_methods for OpenWv {
    fn Initialize(
        &mut self,
        allow_distinctive_identifier: bool,
        allow_persistent_state: bool,
        use_hw_secure_codecs: bool,
    ) {
        debug!(
            "INITIALIZE CALLED: {}",
            self.host.as_mut().GetCurrentWallTime()
        );
        todo!()
    }

    fn GetStatusForPolicy(&mut self, promise_id: u32, policy: &cdm::Policy) {
        todo!()
    }

    unsafe fn SetServerCertificate(
        &mut self,
        promise_id: u32,
        server_certificate_data: *const u8,
        server_certificate_data_size: u32,
    ) {
        todo!()
    }

    unsafe fn CreateSessionAndGenerateRequest(
        &mut self,
        promise_id: u32,
        session_type: cdm::SessionType,
        init_data_type: cdm::InitDataType,
        init_data: *const u8,
        init_data_size: u32,
    ) {
        todo!()
    }

    unsafe fn LoadSession(
        &mut self,
        promise_id: u32,
        session_type: cdm::SessionType,
        session_id: *const c_char,
        session_id_size: u32,
    ) {
        todo!()
    }

    unsafe fn UpdateSession(
        &mut self,
        promise_id: u32,
        session_id: *const c_char,
        session_id_size: u32,
        response: *const u8,
        response_size: u32,
    ) {
        todo!()
    }

    unsafe fn CloseSession(
        &mut self,
        promise_id: u32,
        session_id: *const c_char,
        session_id_size: u32,
    ) {
        todo!()
    }

    unsafe fn RemoveSession(
        &mut self,
        promise_id: u32,
        session_id: *const c_char,
        session_id_size: u32,
    ) {
        todo!()
    }

    unsafe fn TimerExpired(&mut self, context: *mut autocxx::c_void) {
        todo!()
    }

    unsafe fn Decrypt(
        &mut self,
        encrypted_buffer: &cdm::InputBuffer_2,
        decrypted_buffer: *mut cdm::DecryptedBlock,
    ) -> cdm::Status {
        todo!()
    }

    fn InitializeAudioDecoder(
        &mut self,
        audio_decoder_config: &cdm::AudioDecoderConfig_2,
    ) -> cdm::Status {
        todo!()
    }

    fn InitializeVideoDecoder(
        &mut self,
        video_decoder_config: &cdm::VideoDecoderConfig_2,
    ) -> cdm::Status {
        todo!()
    }

    fn DeinitializeDecoder(&mut self, decoder_type: cdm::StreamType) {
        todo!()
    }

    fn ResetDecoder(&mut self, decoder_type: cdm::StreamType) {
        todo!()
    }

    unsafe fn DecryptAndDecodeFrame(
        &mut self,
        encrypted_buffer: &cdm::InputBuffer_2,
        video_frame: *mut cdm::VideoFrame,
    ) -> cdm::Status {
        todo!()
    }

    unsafe fn DecryptAndDecodeSamples(
        &mut self,
        encrypted_buffer: &cdm::InputBuffer_2,
        audio_frames: *mut cdm::AudioFrames,
    ) -> cdm::Status {
        todo!()
    }

    fn OnPlatformChallengeResponse(&mut self, response: &cdm::PlatformChallengeResponse) {
        todo!()
    }

    fn OnQueryOutputProtectionStatus(
        &mut self,
        result: cdm::QueryResult,
        link_mask: u32,
        output_protection_mask: u32,
    ) {
        todo!()
    }

    unsafe fn OnStorageId(&mut self, version: u32, storage_id: *const u8, storage_id_size: u32) {
        todo!()
    }

    fn Destroy(&mut self) {
        todo!()
    }
}
