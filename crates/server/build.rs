use pb_rs::{ConfigBuilder, types::FileDescriptor};
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=EMULATOR_MODE");
    let em_mode = std::env::var("EMULATOR_MODE").unwrap_or("false".to_string());
    println!("cargo::rustc-check-cfg=cfg(emulator_mode, values(\"false\", \"true\"))",);
    println!("cargo:rustc-cfg=emulator_mode=\"{}\"", em_mode);

    let out_dir = PathBuf::from("src/pb");
    let proto_dir = PathBuf::from("protobufs");
    let protos = vec![proto_dir.join("forms.proto")];

    let config_builder = ConfigBuilder::new(&protos, None, Some(&out_dir), &[proto_dir]).unwrap();
    FileDescriptor::run(&config_builder.build()).unwrap();

    println!("cargo:rerun-if-changed=protobufs/forms.proto");
}
