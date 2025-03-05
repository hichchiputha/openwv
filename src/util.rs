use std::ffi::CStr;
use std::io::Write;
use std::slice::from_raw_parts;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn try_init_logging() -> bool {
    let mut builder: env_logger::Builder = env_logger::Builder::new();

    builder.format(|buf, record| {
        let style = buf.default_level_style(record.level());
        writeln!(
            buf,
            "[OpenWV {style}{:<5}{style:#}] {}",
            record.level(),
            record.args()
        )
    });

    let env = env_logger::Env::new()
        .filter("OPENWV_LOG")
        .write_style("OPENWV_LOG_STYLE");

    builder
        .filter_level(log::LevelFilter::Info)
        .parse_env(env)
        .try_init()
        .is_ok()
}

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

pub unsafe fn slice_from_c<'a, T>(ptr: *const T, len: u32) -> Option<&'a [T]> {
    match ptr.is_null() {
        true => None,
        false => Some(unsafe { from_raw_parts(ptr, len.try_into().unwrap()) }),
    }
}
