fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A browser build is only a client, and has no tonic transport to
    // connect with (see Cargo.toml).
    let browser = std::env::var("CARGO_CFG_TARGET_ARCH").is_ok_and(|a| a == "wasm32");
    tonic_prost_build::configure()
        .build_server(!browser)
        .build_client(true)
        .build_transport(!browser)
        .compile_protos(&["proto/raft5fs.proto"], &["proto"])?;
    Ok(())
}
