use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const HELPERS: &[&str] = &[
    "openvpn",
    "wg",
    "wg-quick",
    "awg",
    "awg-quick",
    "xray",
    "tun2socks",
    "sslocal",
    "swanctl",
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=AMN_HELPER_DIR");
    println!("cargo:rerun-if-env-changed=AMN_REQUIRE_HELPERS");
    println!("cargo:rerun-if-env-changed=PATH");

    let output = profile_directory().join("libexec").join("amn");
    fs::create_dir_all(&output).unwrap_or_else(|error| {
        panic!("create helper output directory {}: {error}", output.display())
    });

    let helper_directory = env::var_os("AMN_HELPER_DIR").map(PathBuf::from);
    if let Some(directory) = &helper_directory {
        println!("cargo:rerun-if-changed={}", directory.display());
    }

    let mut missing = Vec::new();
    for helper in HELPERS {
        let Some(source) = find_helper(helper, helper_directory.as_deref()) else {
            missing.push(*helper);
            continue;
        };
        let destination = output.join(helper);
        fs::copy(&source, &destination).unwrap_or_else(|error| {
            panic!(
                "copy protocol helper {} to {}: {error}",
                source.display(),
                destination.display()
            )
        });
        make_executable(&destination);
    }

    if !missing.is_empty() {
        let message = format!("missing protocol helpers: {}", missing.join(", "));
        if env::var_os("AMN_REQUIRE_HELPERS").is_some_and(|value| value == "1") {
            panic!("{message}; set AMN_HELPER_DIR or add helpers to PATH");
        }
        println!("cargo:warning={message}");
    }
}

fn profile_directory() -> PathBuf {
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo did not set OUT_DIR"));
    output
        .ancestors()
        .nth(3)
        .expect("OUT_DIR does not use Cargo's target profile layout")
        .to_path_buf()
}

fn find_helper(name: &str, helper_directory: Option<&Path>) -> Option<PathBuf> {
    let path_directories = env::var_os("PATH")
        .map(|path| env::split_paths(&path).collect::<Vec<_>>())
        .unwrap_or_default();
    helper_directory
        .into_iter()
        .map(|directory| directory.join(name))
        .chain(path_directories.into_iter().map(|directory| directory.join(name)))
        .find(|candidate| candidate.is_file())
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|error| panic!("set executable permissions on {}: {error}", path.display()));
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}
