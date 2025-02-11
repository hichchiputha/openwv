use byteorder::{ReadBytesExt, BE};
use prost::Message;
use ring::rsa;
use std::io::Read;
use thiserror::Error;

use crate::video_widevine::ClientIdentification;

pub struct WidevineDevice {
    pub private_key: rsa::KeyPair,
    pub client_id: ClientIdentification,
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum WvdError {
    #[error("bad magic")]
    BadMagic,
    #[error("unsupported wvd version {0}")]
    UnsupportedVersion(u8),
    #[error("unexpected end of data")]
    IoError(#[from] std::io::Error),
    #[error("invalid private key")]
    BadKey(#[from] ring::error::KeyRejected),
    #[error("invalid Client ID protobuf")]
    BadClientIdProto(#[from] prost::DecodeError),
}

pub fn parse_wvd(wvd: &mut impl Read) -> Result<WidevineDevice, WvdError> {
    let mut magic = [0u8; 3];
    wvd.read_exact(&mut magic)?;

    if magic != *b"WVD" {
        return Err(WvdError::BadMagic);
    }

    let version = wvd.read_u8()?;
    if version != 1 && version != 2 {
        return Err(WvdError::UnsupportedVersion(version));
    }

    let _type = wvd.read_u8()?;
    let _security_level = wvd.read_u8()?;
    let _flags = wvd.read_u8()?;

    let private_key_len = wvd.read_u16::<BE>()?;
    let mut private_key_raw = vec![];
    wvd.take(private_key_len.into())
        .read_to_end(&mut private_key_raw)?;

    let client_id_len = wvd.read_u16::<BE>()?;
    let mut client_id_raw = vec![];
    wvd.take(client_id_len.into())
        .read_to_end(&mut client_id_raw)?;

    Ok(WidevineDevice {
        private_key: rsa::KeyPair::from_der(&private_key_raw)?,
        client_id: ClientIdentification::decode(client_id_raw.as_slice())?,
    })
}
