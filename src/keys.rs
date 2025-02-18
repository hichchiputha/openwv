use std::fmt::Display;

pub struct ContentKey {
    pub id: Vec<u8>,
    pub data: Vec<u8>,
    pub key_type: Option<i32>,
}

impl Display for ContentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in &self.id {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ":")?;
        for b in &self.data {
            write!(f, "{:02x}", b)?;
        }
        if let Some(t) = self.key_type {
            write!(f, " [type {}]", t)?;
        }
        Ok(())
    }
}
