use std::ffi::CStr;
use std::fmt::{Debug, Display};
use std::io::Write;
use std::marker::PhantomData;
use std::slice::from_raw_parts;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::CONFIG;

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
        .filter_level(CONFIG.log_level)
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

/// Wrapper type to print i32 enum values that are not guaranteed to fall within
/// the known set of variants.
pub struct EnumPrinter<T> {
    value: i32,
    enum_type: PhantomData<T>,
}

impl<T> From<i32> for EnumPrinter<T> {
    fn from(value: i32) -> Self {
        EnumPrinter {
            value,
            enum_type: PhantomData,
        }
    }
}

/// Print the enum variant name if known and the numeric value if not.
impl<T: TryFrom<i32> + Debug> Display for EnumPrinter<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match T::try_from(self.value) {
            Ok(v) => write!(f, "{v:?}"),
            Err(_) => write!(f, "{}", self.value),
        }
    }
}

/// Print the numeric value followed by the enum variant name if known and
/// "unknown variant" if not.
impl<T: TryFrom<i32> + Debug> Debug for EnumPrinter<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match T::try_from(self.value) {
            Ok(v) => write!(f, "{} [{:?}]", self.value, v),
            Err(_) => write!(f, "{} [unknown variant]", self.value),
        }
    }
}
