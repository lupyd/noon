use pb_rs::{ConfigBuilder, types::FileDescriptor};
use std::path::PathBuf;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(emulator_mode, values(\"true\"))");
    let out_dir = PathBuf::from("src/pb");
    let proto_dir = PathBuf::from("protobufs");
    let protos = vec![proto_dir.join("forms.proto")];

    let config_builder = ConfigBuilder::new(&protos, None, Some(&out_dir), &[proto_dir]).unwrap();
    FileDescriptor::run(&config_builder.build()).unwrap();

    println!("cargo:rerun-if-changed=protobufs/forms.proto");
}
