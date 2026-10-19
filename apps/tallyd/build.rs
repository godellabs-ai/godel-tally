use std::{env, fs, path::Path};

#[allow(clippy::unnecessary_debug_formatting)] // Generate an escaped Rust string literal.
fn collect(dir: &Path, root: &Path, entries: &mut Vec<String>) {
    let mut paths: Vec<_> = fs::read_dir(dir)
        .expect("read exported UI")
        .map(|entry| entry.expect("read UI entry").path())
        .collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            collect(&path, root, entries);
        } else {
            let name = path
                .strip_prefix(root)
                .unwrap()
                .to_str()
                .unwrap()
                .replace('\\', "/");
            entries.push(format!(
                "({name:?}, include_bytes!({:?})),",
                path.canonicalize().unwrap()
            ));
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let mut entries = Vec::new();
    if env::var_os("CARGO_FEATURE_EMBEDDED_UI").is_some() {
        let root = Path::new("../web/out");
        assert!(
            root.join("index.html").is_file(),
            "Build the UI first: make web-install web-build"
        );
        println!("cargo:rerun-if-changed=../web/out");
        collect(root, root, &mut entries);
    }
    fs::write(
        Path::new(&env::var_os("OUT_DIR").unwrap()).join("ui.rs"),
        format!(
            "static ASSETS: &[(&str, &[u8])] = &[{}];",
            entries.join("\n")
        ),
    )
    .unwrap();
}
