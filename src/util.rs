use std::ffi::CStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const fn cstr_from_str(str: &str) -> &CStr {
    match CStr::from_bytes_with_nul(str.as_bytes()) {
        Ok(str) => str,
        Err(_) => panic!("No NUL terminator in &str"),
    }
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
        .try_into()
        .unwrap_or(i64::MAX)
}
