use byteorder::{ByteOrder, BE};
use log::warn;
use thiserror::Error;
use uuid::{uuid, Uuid};

use crate::ffi::cdm::InitDataType;

const WIDEVINE_SYSTEMID: Uuid = uuid!("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed");

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum InitDataError {
    #[error("unsupported init data type")]
    UnsupportedType,
    #[error("no Widevine PSSH data in cenc init data")]
    NoValidPssh,
    #[error("unexpected end of data")]
    ShortData,
    #[error("box too large to parse")]
    Overflow(#[from] std::num::TryFromIntError),
}

pub fn init_data_to_content_id(
    init_data_type: InitDataType,
    init_data: &[u8],
) -> Result<(), InitDataError> {
    match init_data_type {
        InitDataType::kCenc => {
            let widevine_pssh_data = parse_cenc(init_data)?;
            // TODO: Wrap in protobuf
            Ok(())
        }
        InitDataType::kWebM => {
            // TODO: just wrap the whole thing
            Ok(())
        }
        InitDataType::kKeyIds => Err(InitDataError::UnsupportedType),
    }
}

fn safe_slice<I>(buf: &[u8], idx: I) -> Result<&I::Output, InitDataError>
where
    I: std::slice::SliceIndex<[u8]>,
{
    buf.get(idx).ok_or(InitDataError::ShortData)
}

/// cenc-type init data holds "one or more concatenated Protection System Specific
/// Header ('pssh') boxes", as per https://www.w3.org/TR/eme-initdata-cenc/.
fn parse_cenc(boxes: &[u8]) -> Result<&[u8], InitDataError> {
    let mut remaining = boxes;

    while !remaining.is_empty() {
        let mut box_size: u64 = BE::read_u32(safe_slice(remaining, 0..4)?).into();
        let box_type = safe_slice(remaining, 4..8)?;

        let box_payload = match box_size {
            // To end of file
            0 => safe_slice(remaining, 8..)?,
            // Extended size field
            1 => {
                box_size = BE::read_u64(safe_slice(remaining, 8..16)?);
                safe_slice(remaining, 16..box_size.try_into()?)?
            }
            _ => safe_slice(remaining, 8..box_size.try_into()?)?,
        };

        match box_type {
            b"pssh" => {
                if let Some(wv_pssh) = parse_pssh_box(box_payload)? {
                    return Ok(wv_pssh);
                }
            }
            _ => warn!(
                "Skipping unknown CENC box type: {}",
                box_type.escape_ascii()
            ),
        }

        remaining = &remaining[box_payload.len()..];
    }
    Err(InitDataError::NoValidPssh)
}

fn parse_pssh_box(data: &[u8]) -> Result<Option<&[u8]>, InitDataError> {
    let version = *safe_slice(data, 0)?;
    if version != 0 {
        warn!("Skipping PSSH box with unknown version {}", version);
        return Ok(None);
    }

    let system_id = Uuid::from_slice(safe_slice(data, 4..20)?).unwrap();
    if system_id != WIDEVINE_SYSTEMID {
        warn!(
            "Skipping PSSH box with non-Widevine system ID {}",
            system_id
        );
        return Ok(None);
    }

    let payload_size = BE::read_u32(safe_slice(data, 20..24)?);
    let payload = safe_slice(&data[24..], ..payload_size.try_into()?)?;
    Ok(Some(payload))
}

// TODO: Unit tests for parse_cenc()
