use prost::Message;
use rand::{Rng, TryRngCore};
use std::collections::HashMap;
use std::ffi::c_char;
use std::fmt::Display;
use thiserror::Error;

use crate::CdmError;
use crate::config::{CONFIG, EncryptClientId};
use crate::content_key::ContentKey;
use crate::ffi::cdm;
use crate::init_data::{InitDataError, init_data_to_content_id};
use crate::license::{LicenseError, load_license_keys, request_license};
use crate::service_certificate::{
    ServerCertificate, ServerCertificateError, parse_service_cert_message,
};
use crate::util::slice_from_c;
use crate::video_widevine;
use crate::wvd_file::WidevineDevice;

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
        let mut rng = rand::rngs::OsRng.unwrap_err();

        let mut id = [0u8; Self::LEN + 1];

        // Leave last element unfilled as NUL terminator
        for i in &mut id[..Self::LEN] {
            *i = *rng.sample(dist);
        }

        SessionId(id)
    }

    pub unsafe fn from_cxx(ptr: *const c_char, size: u32) -> Result<SessionId, BadSessionId> {
        let slice = unsafe { slice_from_c(ptr.cast::<std::ffi::c_uchar>(), size) }.unwrap();

        if slice.len() != Self::LEN {
            return Err(BadSessionId);
        }

        let mut id = [0u8; Self::LEN + 1];
        id[..Self::LEN].copy_from_slice(slice);

        Ok(SessionId(id))
    }

    pub fn as_cxx(&self) -> (*const c_char, u32) {
        (self.0.as_ptr().cast(), Self::LEN as _)
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
    fn cdm_exception(&self) -> cdm::Exception {
        cdm::Exception::kExceptionInvalidStateError
    }
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum SessionError {
    #[error("update is not valid for state")]
    InvalidState,
    #[error("couldn't load server certificate: {0}")]
    ServiceCertError(#[from] ServerCertificateError),
    #[error("couldn't load license: {0}")]
    LicenseError(#[from] LicenseError),
}

impl CdmError for SessionError {
    fn cdm_exception(&self) -> cdm::Exception {
        cdm::Exception::kExceptionTypeError
    }

    fn cdm_system_code(&self) -> u32 {
        0
    }
}

enum SessionState {
    AwaitingServiceCert(Box<video_widevine::license_request::ContentIdentification>),
    AwaitingLicense { request_bytes: Vec<u8> },
    Active,
    Invalid,
}

pub enum SessionEvent {
    None,
    Message(Vec<u8>),
    KeysChange { new_keys: bool },
}

pub struct Session {
    id: SessionId,
    device: &'static WidevineDevice,
    state: SessionState,
    keys: Vec<ContentKey>,
}

impl Session {
    pub fn create(
        device: &'static WidevineDevice,
        init_data_type: cdm::InitDataType,
        init_data: &[u8],
        mut server_certificate: Option<&ServerCertificate>,
    ) -> Result<(Self, SessionEvent), InitDataError> {
        // If we've been asked never to encrypt, pretend we weren't given a
        // server certificate.
        if let EncryptClientId::Never = CONFIG.encrypt_client_id {
            server_certificate = None;
        }

        let content_id = init_data_to_content_id(init_data_type, init_data)?;
        let (msg, state) = match (CONFIG.encrypt_client_id, server_certificate) {
            (EncryptClientId::Always, None) => (
                video_widevine::SignedMessage {
                    r#type: Some(
                        video_widevine::signed_message::MessageType::ServiceCertificateRequest
                            as i32,
                    ),
                    ..Default::default()
                },
                SessionState::AwaitingServiceCert(Box::new(content_id)),
            ),
            (_, cert) => {
                let (msg, request_bytes) = request_license(content_id, cert, device);
                (msg, SessionState::AwaitingLicense { request_bytes })
            }
        };

        Ok((
            Session {
                id: SessionId::generate(),
                device,
                state,
                keys: vec![],
            },
            SessionEvent::Message(msg.encode_to_vec()),
        ))
    }

    pub fn update(&mut self, message: &[u8]) -> Result<SessionEvent, SessionError> {
        match std::mem::replace(&mut self.state, SessionState::Invalid) {
            SessionState::AwaitingServiceCert(cid) => {
                let cert = parse_service_cert_message(message)?;
                let (msg, request_bytes) = request_license(*cid, Some(&cert), self.device);
                self.state = SessionState::AwaitingLicense { request_bytes };
                Ok(SessionEvent::Message(msg.encode_to_vec()))
            }
            SessionState::AwaitingLicense { request_bytes } => {
                let new_keys =
                    load_license_keys(message, &request_bytes, self.device, &mut self.keys)?;
                self.state = SessionState::Active;
                match new_keys {
                    true => Ok(SessionEvent::KeysChange { new_keys: true }),
                    false => Ok(SessionEvent::None),
                }
            }
            _ => Err(SessionError::InvalidState),
        }
    }

    pub fn clear_licenses(&mut self) {
        self.keys.clear();
    }

    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn keys(&self) -> &[ContentKey] {
        &self.keys
    }
}

pub struct SessionStore(HashMap<SessionId, Session>);
impl SessionStore {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn add(&mut self, session: Session) {
        self.0.insert(session.id, session);
    }

    pub unsafe fn lookup(
        &mut self,
        id: *const c_char,
        id_len: u32,
    ) -> Result<&mut Session, BadSessionId> {
        let session_id = unsafe { SessionId::from_cxx(id, id_len) }.or(Err(BadSessionId))?;
        self.0.get_mut(&session_id).ok_or(BadSessionId)
    }

    pub fn lookup_key(&self, id: &[u8]) -> Option<&ContentKey> {
        // A linear search of each session's keys is probably in practice
        // faster than a HashMap would be, given that we expect each session
        // to have on the order of 10 keys at most.
        self.0
            .values()
            .flat_map(|s| &s.keys)
            .find(|&k| k.id.as_ref().is_some_and(|x| x == id))
    }

    pub fn delete(&mut self, id: SessionId) -> bool {
        self.0.remove(&id).is_some()
    }
}
