use aes::cipher::{BlockDecryptMut, KeyIvInit};
use byteorder::{ByteOrder, BE};
use cmac::Mac;
use log::info;
use prost::Message;
use rand::Rng;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use std::collections::HashMap;
use std::ffi::c_char;
use std::fmt::Display;
use thiserror::Error;

use crate::ffi::cdm;
use crate::init_data::{init_data_to_content_id, InitDataError};
use crate::keys::ContentKey;
use crate::server_certificate::{encrypt_client_id, ServerCertificate};
use crate::util::{now, slice_from_c};
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
        let slice = unsafe { slice_from_c(ptr as *const std::ffi::c_uchar, size) }.unwrap();

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
    fn cdm_exception(&self) -> cdm::Exception {
        cdm::Exception::kExceptionInvalidStateError
    }
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum LicenseError {
    #[error("no stored request")]
    NoRequest,
    #[error("bad protobuf serialization")]
    BadProto(#[from] prost::DecodeError),
    #[error("not a license message")]
    WrongType,
    #[error("no key in SignedMessage")]
    NoSessionKey,
    #[error("couldn't decrypt key")]
    BadSessionKeyCrypto(#[from] rsa::Error),
    #[error("session key wrong length")]
    BadSessionKeyLength(#[from] cmac::digest::InvalidLength),
    #[error("no signature for SignedMessage")]
    NoSignature,
    #[error("could not verify signature")]
    BadSignature,
    #[error("no License message in proto")]
    NoLicense,
    #[error("bad padding in content key")]
    BadContentKey(#[from] aes::cipher::block_padding::UnpadError),
}

impl CdmError for LicenseError {
    fn cdm_exception(&self) -> cdm::Exception {
        cdm::Exception::kExceptionTypeError
    }
}

pub struct Session {
    id: SessionId,
    device: &'static WidevineDevice,
    request_msg: Option<Vec<u8>>,
    keys: Vec<ContentKey>,
}

impl Session {
    pub fn new(device: &'static WidevineDevice) -> Self {
        Session {
            id: SessionId::generate(),
            device,
            request_msg: None,
            keys: vec![],
        }
    }

    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn keys(&self) -> &[ContentKey] {
        &self.keys
    }

    pub fn generate_request(
        &mut self,
        init_data_type: cdm::InitDataType,
        init_data: &[u8],
        server_certificate: Option<&ServerCertificate>,
    ) -> Result<video_widevine::SignedMessage, InitDataError> {
        let key_control_nonce: u32 = rand::random();

        let mut req = video_widevine::LicenseRequest {
            content_id: Some(init_data_to_content_id(init_data_type, init_data)?),
            r#type: Some(video_widevine::license_request::RequestType::New as i32),
            request_time: Some(now()),
            protocol_version: Some(video_widevine::ProtocolVersion::Version21 as i32),
            key_control_nonce: Some(key_control_nonce),
            ..Default::default()
        };

        match server_certificate {
            None => req.client_id = Some(self.device.client_id.clone()),
            Some(cert) => {
                req.encrypted_client_id = Some(encrypt_client_id(cert, &self.device.client_id))
            }
        }

        let req_raw = req.encode_to_vec();

        let signing_key = rsa::pss::SigningKey::<sha1::Sha1>::new(self.device.private_key.clone());
        let signature = signing_key
            .sign_with_rng(&mut rand8::thread_rng(), &req_raw)
            .to_vec();

        self.request_msg = Some(req_raw.clone());

        Ok(video_widevine::SignedMessage {
            r#type: Some(video_widevine::signed_message::MessageType::LicenseRequest as i32),
            msg: Some(req_raw),
            signature: Some(signature),
            session_key: None,
            remote_attestation: None,
            metric_data: vec![],
        })
    }

    pub fn load_license_keys(&mut self, response_raw: &[u8]) -> Result<bool, LicenseError> {
        let response = video_widevine::SignedMessage::decode(response_raw)?;

        if response.r#type != Some(video_widevine::signed_message::MessageType::License as i32) {
            return Err(LicenseError::WrongType);
        }

        let wrapped_key = response.session_key.ok_or(LicenseError::NoSessionKey)?;

        let padding = rsa::Oaep::new::<sha1::Sha1>();
        let session_key = self.device.private_key.decrypt(padding, &wrapped_key)?;
        let session_keys = derive_session_keys(
            self.request_msg.as_ref().ok_or(LicenseError::NoRequest)?,
            &session_key,
        )?;

        let license_raw = response.msg.ok_or(LicenseError::NoLicense)?;

        let mut digester =
            hmac::Hmac::<sha2::Sha256>::new_from_slice(&session_keys.mac_server).unwrap();
        digester.update(&license_raw);
        let expected_sig = digester.finalize().into_bytes();

        let actual_sig = response.signature.ok_or(LicenseError::NoSignature)?;
        if actual_sig != expected_sig.as_slice() {
            return Err(LicenseError::BadSignature);
        }

        let license = video_widevine::License::decode(license_raw.as_slice())?;

        let mut added_keys = false;
        for key in license.key {
            let (Some(iv), Some(mut data)) = (key.iv, key.key) else {
                continue;
            };

            let decryptor =
                cbc::Decryptor::<aes::Aes128>::new_from_slices(&session_keys.encryption, &iv)
                    .unwrap();
            let new_size = decryptor
                .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(data.as_mut_slice())?
                .len();
            data.truncate(new_size);

            let new_key = ContentKey {
                id: key.id.unwrap_or_default(),
                data,
                key_type: key.r#type,
            };

            info!("Loaded content key: {}", &new_key);
            self.keys.push(new_key);
            added_keys = true;
        }

        Ok(added_keys)
    }

    pub fn clear_licenses(&mut self) {
        self.keys.clear();
    }
}

#[derive(Debug)]
pub struct SessionKeys {
    encryption: [u8; 16],
    mac_server: [u8; 32],
    #[allow(dead_code)]
    mac_client: [u8; 32],
}

fn derive_session_keys(
    request_msg: &[u8],
    session_key: &[u8],
) -> Result<SessionKeys, cmac::digest::InvalidLength> {
    let mut cmac = cmac::Cmac::<aes::Aes128>::new_from_slice(session_key)?;

    let mut derive_key = |counter, label, key_size| {
        cmac.update(&[counter]);
        cmac.update(label);
        cmac.update(&[0]);
        cmac.update(request_msg);

        let mut buf = [0u8; 4];
        BE::write_u32(&mut buf, key_size);
        cmac.update(&buf);

        cmac.finalize_reset().into_bytes()
    };

    let encryption = derive_key(1, b"ENCRYPTION", 128).into();

    const AUTH_LABEL: &[u8] = b"AUTHENTICATION";

    let mut mac_server = [0u8; 32];
    mac_server[..16].copy_from_slice(derive_key(1, AUTH_LABEL, 512).as_slice());
    mac_server[16..].copy_from_slice(derive_key(2, AUTH_LABEL, 512).as_slice());

    let mut mac_client = [0u8; 32];
    mac_client[..16].copy_from_slice(derive_key(3, AUTH_LABEL, 512).as_slice());
    mac_client[16..].copy_from_slice(derive_key(4, AUTH_LABEL, 512).as_slice());

    Ok(SessionKeys {
        encryption,
        mac_server,
        mac_client,
    })
}

pub struct SessionStore(HashMap<SessionId, Session>);
impl SessionStore {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn add(&mut self, session: Session) {
        self.0.insert(session.id, session);
    }

    pub fn lookup(&mut self, id: *const c_char, id_len: u32) -> Result<&mut Session, BadSessionId> {
        let session_id = unsafe { SessionId::from_cxx(id, id_len) }.or(Err(BadSessionId))?;
        self.0.get_mut(&session_id).ok_or(BadSessionId)
    }

    pub fn lookup_key(&self, id: &[u8]) -> Option<&ContentKey> {
        // A linear search of each session's keys is probably in practice
        // faster than a HashMap would be, given that we expect each session
        // to have on the order of 10 keys at most.
        self.0.values().flat_map(|s| &s.keys).find(|&k| k.id == id)
    }

    pub fn delete(&mut self, id: SessionId) -> bool {
        self.0.remove(&id).is_some()
    }
}
