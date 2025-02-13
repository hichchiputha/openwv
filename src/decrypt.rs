use aes::cipher::{BlockDecryptMut, KeyIvInit, StreamCipher};
use thiserror::Error;

use crate::ffi::cdm;
use crate::keys::ContentKey;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DecryptError {
    #[error("key neede but not present")]
    NoKey,
    #[error("no iv/subsamples provided for ciphered scheme")]
    NoIvSubsamples,
    #[error("incorrect key or iv length")]
    BadKeyIvLength(#[from] aes::cipher::InvalidLength),
    #[error("integer overflow")]
    Overflow(#[from] std::num::TryFromIntError),
    #[error("subsamples exceed data length")]
    TooShort,
}

pub fn decrypt_buf(
    key: Option<&ContentKey>,
    iv: Option<&[u8]>,
    data: &[u8],
    mode: cdm::EncryptionScheme,
    subsamples: Option<&[cdm::SubsampleEntry]>,
    pattern: &cdm::Pattern,
) -> Result<Vec<u8>, DecryptError> {
    use cdm::EncryptionScheme::*;

    match (mode, key, iv, subsamples) {
        (kUnencrypted, _, _, _) => Ok(data.to_owned()),
        (_, None, _, _) => Err(DecryptError::NoKey),
        (kCenc, Some(key), Some(iv), Some(subsamples)) => {
            let mut decryptor =
                ctr::Ctr64BE::<aes::Aes128>::new_from_slices(key.data.as_slice(), iv)?;

            decrypt_subsamples(data, subsamples, |ciphered| {
                decryptor.apply_keystream(ciphered);
            })
        }
        (kCbcs, Some(key), Some(iv), Some(subsamples)) => {
            let pattern_skip = usize::try_from(pattern.skip_byte_block)?;
            let mut pattern_crypt = usize::try_from(pattern.crypt_byte_block)?;

            // https://source.chromium.org/chromium/chromium/src/+/main:media/cdm/cbcs_decryptor.cc;l=65-69;drc=2fdecb20631b358fed488a177af773d92f85d35c
            if pattern_skip == 0 && pattern_crypt == 0 {
                pattern_crypt = 1;
            }

            let mut decryptor =
                cbc::Decryptor::<aes::Aes128>::new_from_slices(key.data.as_slice(), iv)?;

            decrypt_subsamples(data, subsamples, |ciphered| {
                decrypt_pattern(ciphered, &mut decryptor, pattern_skip, pattern_crypt);
            })
        }
        _ => Err(DecryptError::NoIvSubsamples),
    }
}

fn decrypt_subsamples(
    data: &[u8],
    subsamples: &[cdm::SubsampleEntry],
    mut decrypt: impl FnMut(&mut [u8]),
) -> Result<Vec<u8>, DecryptError> {
    let mut out = data.to_owned();
    let mut remaining = out.as_mut_slice();
    for subsample in subsamples {
        let ciphered_start = usize::try_from(subsample.clear_bytes)?;
        let ciphered_end = ciphered_start + usize::try_from(subsample.cipher_bytes)?;
        let ciphered = remaining
            .get_mut(ciphered_start..ciphered_end)
            .ok_or(DecryptError::TooShort)?;

        decrypt(ciphered);

        remaining = &mut remaining[ciphered_end..];
    }
    Ok(out)
}

fn decrypt_pattern(
    data: &mut [u8],
    decryptor: &mut cbc::Decryptor<aes::Aes128>,
    pattern_skip: usize,
    pattern_crypt: usize,
) {
    let mut blocks = data.chunks_exact_mut(16);
    while blocks.len() > 0 {
        for block in blocks.by_ref().take(pattern_crypt) {
            decryptor.decrypt_block_mut(block.into());
        }

        blocks.by_ref().take(pattern_skip).for_each(drop);
    }
}
