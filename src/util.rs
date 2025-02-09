use std::ffi::CStr;

pub const fn cstr_from_str(str: &str) -> &CStr {
    match CStr::from_bytes_with_nul(str.as_bytes()) {
        Ok(str) => str,
        Err(_) => panic!("No NUL terminator in &str"),
    }
}
