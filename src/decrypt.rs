use aes::cipher::{KeyIvInit, StreamCipher};
use thiserror::Error;

use crate::ffi::cdm;
use crate::keys::ContentKey;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DecryptError {
    #[error("no key/iv provided for ciphered scheme")]
    NoKeyIv,
    #[error("incorrect key or iv length")]
    BadKeyIvLength(#[from] aes::cipher::InvalidLength),
    #[error("integer overflow")]
    Overflow(#[from] std::num::TryFromIntError),
    #[error("no subsamples given for cenc")]
    CencNoSubsamples,
}

pub fn decrypt_buf(
    key: Option<&ContentKey>,
    iv: Option<&[u8]>,
    data: &[u8],
    mode: cdm::EncryptionScheme,
    subsamples: Option<&[cdm::SubsampleEntry]>,
) -> Result<Vec<u8>, DecryptError> {
    match mode {
        cdm::EncryptionScheme::kUnencrypted => Ok(data.to_owned()),
        cdm::EncryptionScheme::kCbcs => todo!(),
        cdm::EncryptionScheme::kCenc => decrypt_cenc(
            key.ok_or(DecryptError::NoKeyIv)?,
            iv.ok_or(DecryptError::NoKeyIv)?,
            data,
            subsamples.ok_or(DecryptError::CencNoSubsamples)?,
        ),
    }
}

fn decrypt_cenc(
    key: &ContentKey,
    iv: &[u8],
    data: &[u8],
    subsamples: &[cdm::SubsampleEntry],
) -> Result<Vec<u8>, DecryptError> {
    let mut decryptor = ctr::Ctr64BE::<aes::Aes128>::new_from_slices(key.data.as_slice(), iv)?;

    let mut out = vec![];
    let mut remaining = data;
    for subsample in subsamples {
        // Cleartext portion
        let (clear, rest) = remaining.split_at(subsample.clear_bytes.try_into()?);
        out.extend_from_slice(clear);
        remaining = rest;

        // Encrypted portion
        let (ciphered, rest) = remaining.split_at(subsample.cipher_bytes.try_into()?);
        let pos = out.len();
        out.extend_from_slice(ciphered);
        decryptor.apply_keystream(&mut out[pos..]);
        remaining = rest;
    }

    out.extend_from_slice(remaining);
    Ok(out)
}
