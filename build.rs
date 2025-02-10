use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
enum BuildError {
    #[error("autocxx failed in build.rs")]
    AutoCxxFailure(#[from] autocxx_build::BuilderError),
}

fn main() -> Result<(), BuildError> {
    let bindings_rs = "src/lib.rs";

    let mut autocxx =
        autocxx_build::Builder::new(bindings_rs, &[PathBuf::from_iter(["third-party", "cdm"])])
            .extra_clang_args(&["-std=c++20"])
            .build()?;
    autocxx.flag("-std=c++20").compile("cdm-api");
    println!("cargo:rerun-if-changed={}", bindings_rs);

    Ok(())
}
