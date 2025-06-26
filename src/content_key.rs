use std::fmt::Display;

use crate::util::EnumPrinter;
use crate::video_widevine::license::key_container::KeyType;

pub struct ContentKey {
    pub id: Option<Vec<u8>>,
    pub data: Vec<u8>,
    pub key_type: Option<i32>,
    pub track_label: Option<String>,
}

impl Display for ContentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(id) = &self.id {
            for b in id {
                write!(f, "{b:02x}")?;
            }
            write!(f, ":")?;
        }
        for b in &self.data {
            write!(f, "{b:02x}")?;
        }

        write!(f, " [")?;
        match self.key_type {
            None => write!(f, "_"),
            Some(t) => write!(f, "{}", EnumPrinter::<KeyType>::from(t)),
        }?;
        if let Some(l) = &self.track_label {
            write!(f, ": \"{l}\"")?;
        }
        write!(f, "]")?;

        Ok(())
    }
}
