fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let out = std::path::Path::new(&crate_dir).join("cabi-rust-libp2p.h");
    let mut cfg = cbindgen::Config::default();
    cfg.language = cbindgen::Language::C;
    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(cfg)
        .generate()
        .expect("cbindgen")
        .write_to_file(out);
}