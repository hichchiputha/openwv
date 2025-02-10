use autocxx::subclass::{subclass, CppSubclassSelfOwned};
use log::{debug, error};
use std::ffi::{c_char, c_int, c_uchar, c_void};
use std::pin::Pin;
use std::ptr::null_mut;
use std::slice;

use crate::ffi::cdm;
use crate::util::cstr_from_str;

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
        allow_persistent_state: false,
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
    allow_persistent_state: bool,
}

impl OpenWv {
    fn reject(&mut self, promise_id: u32, exception: cdm::Exception, msg: &std::ffi::CStr) {
        unsafe {
            self.host.as_mut().OnRejectPromise(
                promise_id,
                exception,
                0,
                msg.as_ptr(),
                msg.count_bytes() as _,
            );
        }
    }
}

impl cdm::ContentDecryptionModule_10_methods for OpenWv {
    fn Initialize(
        &mut self,
        _allow_distinctive_identifier: bool,
        allow_persistent_state: bool,
        _use_hw_secure_codecs: bool,
    ) {
        debug!("OpenWv({:p}).Initialize()", self);
        self.allow_persistent_state = allow_persistent_state;
        self.host.as_mut().OnInitialized(true);
    }

    fn GetStatusForPolicy(&mut self, promise_id: u32, policy: &cdm::Policy) {
        debug!("OpenWv({:p}).GetStatusForPolicy()", self);
        todo!()
    }

    unsafe fn SetServerCertificate(
        &mut self,
        promise_id: u32,
        _server_certificate_data: *const u8,
        _server_certificate_data_size: u32,
    ) {
        debug!("OpenWv({:p}).SetServerCertificate()", self);

        // TODO: Implement
        self.reject(
            promise_id,
            cdm::Exception::kExceptionNotSupportedError,
            c"server certificate not yet implemented",
        );
    }

    unsafe fn CreateSessionAndGenerateRequest(
        &mut self,
        promise_id: u32,
        session_type: cdm::SessionType,
        init_data_type: cdm::InitDataType,
        init_data: *const u8,
        init_data_size: u32,
    ) {
        debug!("OpenWv({:p}).CreateSessionAndGenerateRequest()", self);
        todo!()
    }

    unsafe fn LoadSession(
        &mut self,
        promise_id: u32,
        _session_type: cdm::SessionType,
        _session_id: *const c_char,
        _session_id_size: u32,
    ) {
        debug!("OpenWv({:p}).LoadSession()", self);

        // TODO: Implement
        self.reject(
            promise_id,
            cdm::Exception::kExceptionNotSupportedError,
            c"no persistent sessions",
        );
    }

    unsafe fn UpdateSession(
        &mut self,
        promise_id: u32,
        session_id: *const c_char,
        session_id_size: u32,
        response: *const u8,
        response_size: u32,
    ) {
        debug!("OpenWv({:p}).UpdateSession()", self);
        todo!()
    }

    unsafe fn CloseSession(
        &mut self,
        promise_id: u32,
        session_id: *const c_char,
        session_id_size: u32,
    ) {
        debug!("OpenWv({:p}).CloseSession()", self);
        todo!()
    }

    unsafe fn RemoveSession(
        &mut self,
        promise_id: u32,
        session_id: *const c_char,
        session_id_size: u32,
    ) {
        debug!("OpenWv({:p}).RemoveSession()", self);
        todo!()
    }

    // TODO: what's this for?
    unsafe fn TimerExpired(&mut self, context: *mut autocxx::c_void) {
        debug!("OpenWv({:p}).TimerExpired()", self);
        todo!()
    }

    unsafe fn Decrypt(
        &mut self,
        encrypted_buffer: &cdm::InputBuffer_2,
        decrypted_buffer: *mut cdm::DecryptedBlock,
    ) -> cdm::Status {
        debug!("OpenWv({:p}).Decrypt()", self);
        todo!()
    }

    fn InitializeAudioDecoder(
        &mut self,
        _audio_decoder_config: &cdm::AudioDecoderConfig_2,
    ) -> cdm::Status {
        debug!("OpenWv({:p}).InitializeAudioDecoder()", self);
        cdm::Status::kInitializationError
    }

    fn InitializeVideoDecoder(
        &mut self,
        _video_decoder_config: &cdm::VideoDecoderConfig_2,
    ) -> cdm::Status {
        debug!("OpenWv({:p}).InitializeVideoDecoder()", self);
        cdm::Status::kInitializationError
    }

    fn DeinitializeDecoder(&mut self, decoder_type: cdm::StreamType) {
        debug!("OpenWv({:p}).DeinitializeDecoder()", self);
    }

    fn ResetDecoder(&mut self, decoder_type: cdm::StreamType) {
        debug!("OpenWv({:p}).ResetDecoder()", self);
    }

    unsafe fn DecryptAndDecodeFrame(
        &mut self,
        _encrypted_buffer: &cdm::InputBuffer_2,
        _video_frame: *mut cdm::VideoFrame,
    ) -> cdm::Status {
        debug!("OpenWv({:p}).DecryptAndDecodeFrame()", self);
        cdm::Status::kDecodeError
    }

    unsafe fn DecryptAndDecodeSamples(
        &mut self,
        _encrypted_buffer: &cdm::InputBuffer_2,
        _audio_frames: *mut cdm::AudioFrames,
    ) -> cdm::Status {
        debug!("OpenWv({:p}).DecryptAndDecodeSamples()", self);
        cdm::Status::kDecodeError
    }

    fn OnPlatformChallengeResponse(&mut self, _response: &cdm::PlatformChallengeResponse) {
        debug!("OpenWv({:p}).OnPlatformChallengeResponse()", self);
    }

    fn OnQueryOutputProtectionStatus(
        &mut self,
        _result: cdm::QueryResult,
        _link_mask: u32,
        _output_protection_mask: u32,
    ) {
        debug!("OpenWv({:p}).OnQueryOutputProtectionStatus()", self);
    }

    unsafe fn OnStorageId(&mut self, _version: u32, _storage_id: *const u8, _storage_id_size: u32) {
        debug!("OpenWv({:p}).OnStorageId()", self);
    }

    fn Destroy(&mut self) {
        self.delete_self();
    }
}
