fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let workspace_root = std::path::Path::new(&manifest_dir)
        .parent().unwrap()   // crates/
        .parent().unwrap();  // workspace root

    let include_dir = workspace_root.join("include");
    std::fs::create_dir_all(&include_dir).unwrap();

    let config = cbindgen::Config {
        language: cbindgen::Language::C,
        include_guard: Some("SIGNET_FFI_H".to_string()),
        cpp_compat: true,
        ..Default::default()
    };

    cbindgen::Builder::new()
        .with_crate(&manifest_dir)
        .with_config(config)
        .generate()
        .expect("cbindgen failed")
        .write_to_file(include_dir.join("signet.h"));
}
