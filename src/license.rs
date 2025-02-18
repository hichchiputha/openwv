use aes::cipher::{BlockDecryptMut, KeyIvInit};
use byteorder::{ByteOrder, BE};
use cmac::Mac;
use log::info;
use prost::Message;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use thiserror::Error;

use crate::ffi::cdm;
use crate::keys::ContentKey;
use crate::service_certificate::{encrypt_client_id, ServerCertificate};
use crate::util::now;
use crate::video_widevine;
use crate::wvd_file::WidevineDevice;
use crate::CdmError;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum LicenseError {
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

pub fn request_license(
    content_id: video_widevine::license_request::ContentIdentification,
    server_certificate: Option<&ServerCertificate>,
    device: &WidevineDevice,
) -> (video_widevine::SignedMessage, Vec<u8>) {
    let key_control_nonce: u32 = rand::random();

    let mut req = video_widevine::LicenseRequest {
        content_id: Some(content_id),
        r#type: Some(video_widevine::license_request::RequestType::New as i32),
        request_time: Some(now()),
        protocol_version: Some(video_widevine::ProtocolVersion::Version21 as i32),
        key_control_nonce: Some(key_control_nonce),
        ..Default::default()
    };

    match server_certificate {
        None => req.client_id = Some(device.client_id.clone()),
        Some(cert) => req.encrypted_client_id = Some(encrypt_client_id(cert, &device.client_id)),
    }

    let req_bytes = req.encode_to_vec();

    let signing_key = rsa::pss::SigningKey::<sha1::Sha1>::new(device.private_key.clone());
    let signature = signing_key
        .sign_with_rng(&mut rand8::thread_rng(), &req_bytes)
        .to_vec();

    let req_bytes_for_sig = req_bytes.clone();
    (
        video_widevine::SignedMessage {
            r#type: Some(video_widevine::signed_message::MessageType::LicenseRequest as i32),
            msg: Some(req_bytes),
            signature: Some(signature),
            ..Default::default()
        },
        req_bytes_for_sig,
    )
}

pub fn load_license_keys(
    message: &[u8],
    request_bytes: &[u8],
    device: &WidevineDevice,
    keys: &mut Vec<ContentKey>,
) -> Result<bool, LicenseError> {
    let response = video_widevine::SignedMessage::decode(message)?;

    if response.r#type != Some(video_widevine::signed_message::MessageType::License as i32) {
        return Err(LicenseError::WrongType);
    }

    let wrapped_key = response.session_key.ok_or(LicenseError::NoSessionKey)?;

    let padding = rsa::Oaep::new::<sha1::Sha1>();
    let session_key = device.private_key.decrypt(padding, &wrapped_key)?;
    let session_keys = derive_session_keys(request_bytes, &session_key)?;

    let license_bytes = response.msg.ok_or(LicenseError::NoLicense)?;

    let mut digester =
        hmac::Hmac::<sha2::Sha256>::new_from_slice(&session_keys.mac_server).unwrap();
    digester.update(&license_bytes);
    let expected_sig = digester.finalize().into_bytes();

    let actual_sig = response.signature.ok_or(LicenseError::NoSignature)?;
    if actual_sig != expected_sig.as_slice() {
        return Err(LicenseError::BadSignature);
    }

    let license = video_widevine::License::decode(license_bytes.as_slice())?;

    let mut added_keys = false;
    for key in license.key {
        let (Some(iv), Some(mut data)) = (key.iv, key.key) else {
            continue;
        };

        let decryptor =
            cbc::Decryptor::<aes::Aes128>::new_from_slices(&session_keys.encryption, &iv).unwrap();
        let new_size = decryptor
            .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(data.as_mut_slice())?
            .len();
        data.truncate(new_size);

        let new_key = ContentKey {
            id: key.id.unwrap_or_default(),
            data,
            key_type: key.r#type,
        };

        info!("Loaded key: {}", &new_key);
        keys.push(new_key);
        added_keys = true;
    }

    Ok(added_keys)
}

#[derive(Debug)]
struct SessionKeys {
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
