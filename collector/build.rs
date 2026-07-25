//! Generates Rust bindings from the shared protobuf schema.
//!
//! The collector consumes the same `.proto` files the Go nodes are built
//! against. Generating from source rather than vendoring a copy is what stops
//! the two sides drifting -- a schema change that breaks the collector fails
//! this build rather than failing silently at runtime on a live sensor.

use std::io::Result;
use std::path::PathBuf;

fn main() -> Result<()> {
    let proto_root = PathBuf::from("../proto");
    let files = [
        proto_root.join("honeynet/v1/envelope.proto"),
        proto_root.join("honeynet/v1/events.proto"),
    ];

    for f in &files {
        println!("cargo:rerun-if-changed={}", f.display());
    }

    // Point prost at the vendored compiler rather than whatever happens to be
    // on PATH, so the build is reproducible across developer machines and CI.
    if std::env::var_os("PROTOC").is_none() {
        if let Ok(protoc) = protoc_bin_vendored::protoc_bin_path() {
            std::env::set_var("PROTOC", protoc);
        }
    }

    let mut cfg = prost_build::Config::new();
    cfg.compile_protos(&files, &[proto_root])?;
    Ok(())
}
