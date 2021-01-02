// #[cfg(not(feature = "bindgen"))]
// fn main() {}

// #[cfg(feature = "bindgen")]
fn main() {
    use std::env;
    use std::path::PathBuf;

    const INCLUDE: &str = r#"
#include <linux/blk_types.h>
    "#;

    let outdir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let kernel_header_dir = format!("/lib/modules/5.9.0/build");
    let mut clang_args = vec![];
    let arch = "arm64";
    // clang_args.push(format!("-I."));
    clang_args.push(format!("-I{}/arch/{}/include/generated", kernel_header_dir, arch));
    clang_args.push(format!("-I{}/arch/{}/include", kernel_header_dir, arch));
    clang_args.push(format!("-I{}/include", kernel_header_dir));
    dbg!(&clang_args);

    // bindgen::Builder::default()
    bindgen::builder()
        .clang_args(clang_args)
        .header_contents("include-file.h", INCLUDE)
        .ctypes_prefix("libc")
        .derive_default(true)
        .generate_comments(true)
        .use_core()
        .whitelist_var("REQ_OP_.*|REQ_.*")
        .generate()
        .unwrap()
        .write_to_file(outdir.join("sys.rs"))
        .unwrap();
}
