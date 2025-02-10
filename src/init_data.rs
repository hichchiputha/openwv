use byteorder::{ReadBytesExt, BE};
use log::warn;
use std::io::{Cursor, Read, Seek};
use thiserror::Error;
use uuid::{uuid, Uuid};

use crate::ffi::cdm::InitDataType;

const WIDEVINE_SYSTEMID: Uuid = uuid!("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed");

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum InitDataError {
    #[error("unsupported init data type")]
    UnsupportedType,
    #[error("couldn't parse data")]
    ParseError(#[from] std::io::Error),
    #[error("box too large to parse")]
    OverflowError,
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

/// cenc-type init data holds "one or more concatenated Protection System Specific
/// Header ('pssh') boxes", as per https://www.w3.org/TR/eme-initdata-cenc/.
fn parse_cenc(boxes: &[u8]) -> Result<&[u8], InitDataError> {
    let mut c = Cursor::new(boxes);

    while c.position() as usize != boxes.len() {
        let box_start = c.position();
        let mut box_size: u64 = c.read_u32::<BE>()?.into();

        let mut box_type = [0u8; 4];
        c.read_exact(&mut box_type)?;

        // This cast will never overflow because c is an in-memory cursor.
        let payload_start = c.position() as usize;

        let box_payload: &[u8] = if box_size != 0 {
            // Extended size field
            if box_size == 1 {
                box_size = c.read_u64::<BE>()?;
            }

            let box_end = box_start
                .checked_add(box_size)
                .ok_or(InitDataError::OverflowError)?;
            let Ok(box_end_usize) = box_end.try_into() else {
                return Err(InitDataError::OverflowError);
            };

            if box_end_usize > boxes.len() {
                return Err(InitDataError::ParseError(
                    std::io::ErrorKind::UnexpectedEof.into(),
                ));
            }

            c.set_position(box_end);
            &boxes[payload_start..box_end_usize]
        } else {
            // To end of file
            c.seek(std::io::SeekFrom::End(0)).unwrap();
            &boxes[payload_start..]
        };

        match &box_type {
            b"pssh" => parse_pssh_box(box_payload),
            _ => warn!(
                "Skipping unknown CENC box type: {}",
                box_type.escape_ascii()
            ),
        }
    }
    Ok(&[])
}

fn parse_pssh_box(data: &[u8]) {}
