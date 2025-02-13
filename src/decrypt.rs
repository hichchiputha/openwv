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
    #[error("subsamples exceed data length")]
    TooShort,
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

    let mut out = data.to_owned();
    let mut remaining = out.as_mut_slice();
    for subsample in subsamples {
        let ciphered_start = usize::try_from(subsample.clear_bytes)?;
        let ciphered_end = ciphered_start + usize::try_from(subsample.cipher_bytes)?;
        let ciphered = remaining
            .get_mut(ciphered_start..ciphered_end)
            .ok_or(DecryptError::TooShort)?;

        decryptor.apply_keystream(ciphered);

        remaining = &mut remaining[ciphered_end..];
    }
    Ok(out)
}
