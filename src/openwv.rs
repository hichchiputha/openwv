use autocxx::subclass::{subclass, CppSubclassSelfOwned};
use log::{debug, error, info, warn};
use prost::Message;
use std::ffi::{c_char, c_int, c_uchar, c_void};
use std::pin::Pin;
use std::ptr::{null, null_mut};
use std::slice;
use std::sync::OnceLock;

use crate::ffi::cdm;
use crate::keys::ContentKey;
use crate::session::{Session, SessionStore};
use crate::util::cstr_from_str;
use crate::wvd_file;
use crate::CdmError;

// To change this, also change ContentDecryptionModule_NN and Host_NN.
const CDM_INTERFACE: c_int = 10;

// Holds the private key and client ID we use for license requests. Loaded once
// during InitializeCdmModule() and referenced by all subsequently-created
// Session structs.
static DEVICE: OnceLock<wvd_file::WidevineDevice> = OnceLock::new();

// Ideally, we'd read this dynamically from the filesystem, but currently we
// embed it because the Firefox GMP sandbox forbids filesystem reads.
const EMBEDDED_WVD: &[u8] = include_bytes!("embedded.wvd");

#[no_mangle]
extern "C" fn InitializeCdmModule_4() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();
    debug!("InitializeCdmModule()");

    let mut embedded_wvd = std::io::Cursor::new(EMBEDDED_WVD);
    match wvd_file::parse_wvd(&mut embedded_wvd) {
        Ok(dev) => {
            if DEVICE.set(dev).is_err() {
                warn!("Tried to initialize CDM twice!");
            } else {
                info!("Successfully loaded embedded device!");
            }
        }
        Err(e) => error!("Could not parse embedded device: {}", e),
    }
}

#[no_mangle]
extern "C" fn DeinitializeCdmModule() {
    debug!("DeinitializeCdmModule()");
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

    let Some(device) = DEVICE.get() else {
        error!("Called CreateCdmInstance() before initializing module");
        return null_mut();
    };

    let openwv = OpenWv::new_self_owned(OpenWv {
        host,
        sessions: SessionStore::new(),
        device,
        keys: vec![],
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
    sessions: SessionStore,
    keys: Vec<ContentKey>,
    device: &'static wvd_file::WidevineDevice,
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
                msg.count_bytes().try_into().unwrap(),
            );
        }
    }

    fn throw(&mut self, promise_id: u32, e: &(impl std::error::Error + CdmError)) {
        warn!("Returning API error: {}", e);

        // Need to keep this alive until after the FFI call, or else we'll be
        // passing a dangling pointer.
        let msg_str = std::ffi::CString::new(e.to_string()).ok();

        let (msg_ptr, msg_size) = match &msg_str {
            None => (null(), 0),
            Some(s) => (s.as_ptr(), s.count_bytes()),
        };

        unsafe {
            self.host.as_mut().OnRejectPromise(
                promise_id,
                e.cdm_exception(),
                e.cdm_system_code(),
                msg_ptr,
                msg_size.try_into().unwrap(),
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
        if session_type == cdm::SessionType::kPersistentLicense && !self.allow_persistent_state {
            // TODO: error details, better error framework
            self.reject(
                promise_id,
                cdm::Exception::kExceptionNotSupportedError,
                c"persistent state not allowed",
            );
            return;
        }

        let mut sess = Session::new(self.device);

        let init_data_raw = unsafe { slice::from_raw_parts(init_data, init_data_size as _) };
        match sess.generate_request(init_data_type, init_data_raw) {
            Ok(request) => {
                let session_id = sess.id();

                self.sessions.add(sess);
                info!("Registered new session {}", session_id);

                let request_raw = request.encode_to_vec();
                let (id_ptr, id_len) = session_id.as_cxx();

                unsafe {
                    self.host
                        .as_mut()
                        .OnResolveNewSessionPromise(promise_id, id_ptr, id_len);

                    self.host.as_mut().OnSessionMessage(
                        id_ptr,
                        id_len,
                        cdm::MessageType::kLicenseRequest,
                        request_raw.as_ptr() as _,
                        request_raw.len() as _,
                    );
                }
            }
            Err(e) => self.throw(promise_id, &e),
        }
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
        let sess = match self.sessions.lookup(session_id, session_id_size) {
            Ok(s) => s,
            Err(e) => {
                self.throw(promise_id, &e);
                return;
            }
        };

        let response_raw = unsafe { slice::from_raw_parts(response, response_size as _) };
        if let Err(e) = sess.load_license_keys(response_raw, &mut self.keys) {
            self.throw(promise_id, &e);
            return;
        }

        self.host.as_mut().OnResolvePromise(promise_id);

        if !self.keys.is_empty() {
            // Build an array of KeyInformation structs that point into keys.
            let key_infos: Vec<cdm::KeyInformation> = self
                .keys
                .iter()
                .map(|k| cdm::KeyInformation {
                    key_id: k.data.as_ptr(),
                    key_id_size: k.data.len() as _,
                    status: cdm::KeyStatus::kUsable,
                    system_code: 0,
                })
                .collect();

            unsafe {
                self.host.as_mut().OnSessionKeysChange(
                    session_id,
                    session_id_size,
                    true,
                    key_infos.as_ptr(),
                    key_infos.len() as _,
                );
            }
        }
    }

    unsafe fn CloseSession(
        &mut self,
        promise_id: u32,
        session_id: *const c_char,
        session_id_size: u32,
    ) {
        debug!("OpenWv({:p}).CloseSession()", self);
        match self.sessions.lookup(session_id, session_id_size) {
            Ok(s) => {
                let id = s.id();
                self.sessions.delete(id);
                self.host.as_mut().OnResolvePromise(promise_id);
            }
            Err(e) => self.throw(promise_id, &e),
        };
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
