use byteorder::{BE, ByteOrder};
use log::{info, warn};
use thiserror::Error;
use uuid::{Uuid, uuid};

use crate::CdmError;
use crate::ffi::cdm::InitDataType;
use crate::video_widevine::LicenseType;
use crate::video_widevine::license_request::{ContentIdentification, content_identification};

// From https://dashif.org/identifiers/content_protection/
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

impl CdmError for InitDataError {
    fn cdm_exception(&self) -> crate::ffi::cdm::Exception {
        use crate::ffi::cdm::Exception::*;

        match self {
            Self::UnsupportedType => kExceptionNotSupportedError,
            _ => kExceptionTypeError,
        }
    }
}

pub fn init_data_to_content_id(
    init_data_type: InitDataType,
    init_data: &[u8],
) -> Result<ContentIdentification, InitDataError> {
    // Note that CencDeprecated and WebmDeprecated seem to be required here,
    // despite their names. I tried using the newer InitData message, but the
    // license server I'm testing with rejects it.
    match init_data_type {
        InitDataType::kCenc => {
            let widevine_pssh_data = parse_cenc(init_data)?;

            let proto = content_identification::CencDeprecated {
                pssh: vec![widevine_pssh_data.into()],
                license_type: Some(LicenseType::Streaming as i32),
                request_id: Some(rand::random_iter().take(16).collect()),
            };

            Ok(ContentIdentification {
                cenc_id_deprecated: Some(proto),
                ..Default::default()
            })
        }
        InitDataType::kWebM => {
            let proto = content_identification::WebmDeprecated {
                header: Some(init_data.into()),
                license_type: Some(LicenseType::Streaming as i32),
                request_id: Some(rand::random_iter().take(16).collect()),
            };

            Ok(ContentIdentification {
                webm_id_deprecated: Some(proto),
                ..Default::default()
            })
        }
        InitDataType::kKeyIds => Err(InitDataError::UnsupportedType),
    }
}

fn checked_slice<I>(buf: &[u8], idx: I) -> Result<&I::Output, InitDataError>
where
    I: std::slice::SliceIndex<[u8]>,
{
    buf.get(idx).ok_or(InitDataError::ShortData)
}

/// cenc-type init data holds "one or more concatenated Protection System Specific
/// Header ('pssh') boxes", as per <https://www.w3.org/TR/eme-initdata-cenc/>.
fn parse_cenc(boxes: &[u8]) -> Result<&[u8], InitDataError> {
    let mut remaining = boxes;

    while !remaining.is_empty() {
        let mut box_size: u64 = BE::read_u32(checked_slice(remaining, 0..4)?).into();
        let box_type = checked_slice(remaining, 4..8)?;

        let (payload_start, payload_end) = match box_size {
            // To end of file
            0 => (8, remaining.len()),
            // Extended size field
            1 => {
                box_size = BE::read_u64(checked_slice(remaining, 8..16)?);
                (16, box_size.try_into()?)
            }
            _ => (8, box_size.try_into()?),
        };
        let box_payload = checked_slice(remaining, payload_start..payload_end)?;

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

        remaining = &remaining[payload_end..];
    }
    Err(InitDataError::NoValidPssh)
}

fn parse_pssh_box(data: &[u8]) -> Result<Option<&[u8]>, InitDataError> {
    let version = *checked_slice(data, 0)?;
    if version != 0 {
        info!("Skipping PSSH box with unknown version {}", version);
        return Ok(None);
    }

    let system_id = Uuid::from_slice(checked_slice(data, 4..20)?).unwrap();
    if system_id != WIDEVINE_SYSTEMID {
        info!(
            "Skipping PSSH box with non-Widevine system ID {}",
            system_id
        );
        return Ok(None);
    }

    let payload_size = BE::read_u32(checked_slice(data, 20..24)?);
    let payload = checked_slice(&data[24..], ..payload_size.try_into()?)?;
    Ok(Some(payload))
}

// TODO: Unit tests for parse_cenc()
