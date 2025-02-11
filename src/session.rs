use prost::Message;
use ring::rand::SystemRandom;
use std::fmt::Display;
use thiserror::Error;

use crate::ffi::cdm::InitDataType;
use crate::init_data::{init_data_to_content_id, InitDataError};
use crate::util::now;
use crate::video_widevine;
use crate::wvd_file::WidevineDevice;
use crate::CdmError;

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct SessionId([u8; 16]);

impl SessionId {
    fn generate() -> SessionId {
        SessionId(rand::random())
    }

    pub unsafe fn from_cxx(
        ptr: *const std::ffi::c_char,
        size: u32,
    ) -> Result<SessionId, std::array::TryFromSliceError> {
        let slice =
            unsafe { std::slice::from_raw_parts(ptr as *const std::ffi::c_uchar, size as _) };
        Ok(SessionId(slice.try_into()?))
    }

    pub unsafe fn as_cxx(&self) -> (*const std::ffi::c_char, u32) {
        (self.0.as_ptr() as _, self.0.len() as _)
    }
}

impl Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{:02X}", b)?
        }
        Ok(())
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

        let mut signature = vec![0u8; self.device.private_key.public().modulus_len()];
        self.device
            .private_key
            .sign(
                &ring::signature::RSA_PSS_SHA1_FOR_LEGACY_USE_ONLY,
                &SystemRandom::new(),
                &req_raw,
                &mut signature,
            )
            .unwrap();

        Ok(video_widevine::SignedMessage {
            r#type: Some(video_widevine::signed_message::MessageType::LicenseRequest as i32),
            msg: Some(req_raw),
            signature: Some(signature),
            session_key: None,
            remote_attestation: None,
            metric_data: vec![],
        })
    }
}
