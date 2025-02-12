use prost::Message;
use rand::Rng;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use std::ffi::c_char;
use std::fmt::Display;
use thiserror::Error;

use crate::ffi::cdm::{Exception, InitDataType};
use crate::init_data::{init_data_to_content_id, InitDataError};
use crate::util::now;
use crate::video_widevine;
use crate::wvd_file::WidevineDevice;
use crate::CdmError;

/// Represents a session ID. We want this both to be copyable (so ideally
/// entirely stack-allocated) and passable to C++ as a NUL-terminated string,
/// which is why we do all this array to C string munging manually.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct SessionId([u8; Self::LEN + 1]);

impl SessionId {
    const LEN: usize = 32;

    fn generate() -> SessionId {
        // Technically, we can be any C string, but Google uses 32 characters
        // of uppercase hex.
        const CHARS: &[u8] = b"0123456789ABCDEF";

        let dist = rand::distr::slice::Choose::new(CHARS).unwrap();
        let mut rng = rand::rng();

        let mut id = [0u8; Self::LEN + 1];

        // Leave last element unfilled as NUL terminator
        for i in id[..Self::LEN].iter_mut() {
            *i = *rng.sample(dist);
        }

        SessionId(id)
    }

    pub unsafe fn from_cxx(ptr: *const c_char, size: u32) -> Result<SessionId, BadSessionId> {
        let slice =
            unsafe { std::slice::from_raw_parts(ptr as *const std::ffi::c_uchar, size as _) };

        if slice.len() != Self::LEN {
            return Err(BadSessionId);
        }

        let mut id = [0u8; Self::LEN + 1];
        id[..Self::LEN].copy_from_slice(slice);

        Ok(SessionId(id))
    }

    pub unsafe fn as_cxx(&self) -> (*const c_char, u32) {
        (self.0.as_ptr() as _, Self::LEN as _)
    }
}

impl Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0[..Self::LEN].escape_ascii())
    }
}

#[derive(Error, Debug)]
#[error("invalid or non-existent session ID")]
pub struct BadSessionId;
impl CdmError for BadSessionId {
    fn cdm_exception(&self) -> Exception {
        Exception::kExceptionInvalidStateError
    }
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum LicenseError {
    #[error("bad protobuf serialization")]
    BadProto(#[from] prost::DecodeError),
}

impl CdmError for LicenseError {
    fn cdm_exception(&self) -> crate::ffi::cdm::Exception {
        use crate::ffi::cdm::Exception::*;

        match self {
            LicenseError::BadProto(_) => kExceptionTypeError,
        }
    }
}

pub struct Session {
    id: SessionId,
    device: &'static WidevineDevice,
}

impl Session {
    pub fn new(device: &'static WidevineDevice) -> Session {
        Session {
            id: SessionId::generate(),
            device,
        }
    }

    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn generate_request(
        &self,
        init_data_type: InitDataType,
        init_data: &[u8],
    ) -> Result<video_widevine::SignedMessage, InitDataError> {
        let key_control_nonce: u32 = rand::random();

        let req = video_widevine::LicenseRequest {
            client_id: Some(self.device.client_id.clone()),
            content_id: Some(init_data_to_content_id(init_data_type, init_data)?),
            r#type: Some(video_widevine::license_request::RequestType::New as i32),
            request_time: Some(now()),
            key_control_nonce_deprecated: None,
            protocol_version: Some(video_widevine::ProtocolVersion::Version21 as i32),
            key_control_nonce: Some(key_control_nonce),
            encrypted_client_id: None,
            sub_session_data: vec![],
        };
        let req_raw = req.encode_to_vec();

        let signing_key: rsa::pss::SigningKey<sha1::digest::core_api::CoreWrapper<sha1::Sha1Core>> =
            rsa::pss::SigningKey::<sha1::Sha1>::new(self.device.private_key.clone());
        let signature = signing_key
            .sign_with_rng(&mut rand8::thread_rng(), &req_raw)
            .to_vec();

        Ok(video_widevine::SignedMessage {
            r#type: Some(video_widevine::signed_message::MessageType::LicenseRequest as i32),
            msg: Some(req_raw),
            signature: Some(signature),
            session_key: None,
            remote_attestation: None,
            metric_data: vec![],
        })
    }

    pub fn update(&mut self, response_raw: &[u8]) -> Result<(), LicenseError> {
        let response = video_widevine::SignedMessage::decode(response_raw)?;
        todo!()
    }
}
