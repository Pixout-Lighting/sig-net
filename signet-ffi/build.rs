fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let include_dir = std::path::Path::new(&crate_dir).parent().unwrap().join("include");

    std::fs::create_dir_all(&include_dir).unwrap();

    let config = cbindgen::Config {
        language: cbindgen::Language::C,
        include_guard: Some("SIGNET_FFI_H".to_string()),
        cpp_compat: true,
        ..Default::default()
    };

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("cbindgen failed")
        .write_to_file(include_dir.join("signet.h"));
}
