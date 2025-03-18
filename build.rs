use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
enum BuildError {
    #[error("autocxx failed in build.rs")]
    AutoCxxFailure(#[from] autocxx_build::BuilderError),
    #[error("prost failed in build.rs")]
    ProstFailure(#[from] std::io::Error),
}

fn main() -> Result<(), BuildError> {
    let bindings_rs = "src/lib.rs";

    let mut autocxx = autocxx_build::Builder::new(bindings_rs, &[PathBuf::from("third-party/cdm")])
        .extra_clang_args(&["-std=c++20"])
        .build()?;
    autocxx.std("c++20").compile("cdm-api");
    println!("cargo:rerun-if-changed={}", bindings_rs);

    let no_paths: [&str; 0] = [];
    let proto_fd = "third-party/widevine_protos.pb";
    prost_build::Config::new()
        .file_descriptor_set_path(proto_fd)
        .skip_protoc_run()
        .compile_protos(&no_paths, &no_paths)?;
    println!("cargo:rerun-if-changed={}", proto_fd);

    Ok(())
}
