use std::{
    env,
    ffi::OsStr,
    fs,
    io::Read,
    path::{
        Path,
        PathBuf,
    },
    process::Command,
};

#[derive(Clone, Copy)]
enum RecipeArtifact {
    OpenVpn,
    Tun2Socks,
    AmneziaWg,
    GeoIp,
    GeoSite,
}

trait BundledArtifact {
    fn source_name(self) -> &'static str;
    fn package_path(self) -> &'static str;
    fn destination_name(self) -> &'static str;
    fn executable(self) -> bool;
    fn next(self) -> Option<Self>
    where
        Self: Sized;
}

impl BundledArtifact for RecipeArtifact {
    fn source_name(self) -> &'static str {
        match self {
            Self::OpenVpn => "openvpn",
            Self::Tun2Socks => "tun2socks",
            Self::AmneziaWg => "amneziawg-go",
            Self::GeoIp => "geoip.dat",
            Self::GeoSite => "geosite.dat",
        }
    }

    fn package_path(self) -> &'static str {
        match self {
            Self::OpenVpn => "openvpn/2.7.0/Release/x86_64/openvpn",
            Self::Tun2Socks => "tun2socks/2.6.0/x86_64/tun2socks",
            Self::AmneziaWg => "awg-go/3.1.20260814/x86_64/amneziawg-go",
            Self::GeoIp => "v2ray-rules-dat/202603162227/geoip.dat",
            Self::GeoSite => "v2ray-rules-dat/202603162227/geosite.dat",
        }
    }

    fn destination_name(self) -> &'static str {
        self.source_name()
    }

    fn executable(self) -> bool {
        matches!(self, Self::OpenVpn | Self::Tun2Socks | Self::AmneziaWg)
    }

    fn next(self) -> Option<Self> {
        match self {
            Self::OpenVpn => Some(Self::Tun2Socks),
            Self::Tun2Socks => Some(Self::AmneziaWg),
            Self::AmneziaWg => Some(Self::GeoIp),
            Self::GeoIp => Some(Self::GeoSite),
            Self::GeoSite => None,
        }
    }
}

#[derive(Clone, Copy)]
enum RecipeInput {
    OpenVpn,
    Tun2Socks,
    AmneziaWg,
    Go,
    V2RayRules,
    XRayBindings,
    LibSsh,
    OpenSsl,
    LibCapNg,
}

impl RecipeInput {
    fn directory(self) -> &'static str {
        match self {
            Self::OpenVpn => "openvpn",
            Self::Tun2Socks => "tun2socks",
            Self::AmneziaWg => "awg-go",
            Self::Go => "go",
            Self::V2RayRules => "v2ray-rules-dat",
            Self::XRayBindings => "amnezia-xray-bindings",
            Self::LibSsh => "libssh",
            Self::OpenSsl => "openssl",
            Self::LibCapNg => "libcap-ng",
        }
    }

    fn next(self) -> Option<Self> {
        match self {
            Self::OpenVpn => Some(Self::Tun2Socks),
            Self::Tun2Socks => Some(Self::AmneziaWg),
            Self::AmneziaWg => Some(Self::Go),
            Self::Go => Some(Self::V2RayRules),
            Self::V2RayRules => Some(Self::XRayBindings),
            Self::XRayBindings => Some(Self::LibSsh),
            Self::LibSsh => Some(Self::OpenSsl),
            Self::OpenSsl => Some(Self::LibCapNg),
            Self::LibCapNg => None,
        }
    }
}

const AMNEZIA_REMOTE: &str =
    "https://artifactory.amnezia.org/artifactory/api/conan/client-prebuilts";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/core/amnezia_xray_runner.c");
    println!("cargo:rerun-if-changed=amnezia-client/conanfile.py");
    println!("cargo:rerun-if-changed=amnezia-client/recipes");

    let manifest = PathBuf::from(required_env("CARGO_MANIFEST_DIR"));
    let source = manifest.join("amnezia-client");
    let recipes = source.join("recipes");
    require_file(&source.join("conanfile.py"));
    require_directory(&recipes);
    for recipe in std::iter::successors(Some(RecipeInput::OpenVpn), |recipe| recipe.next()) {
        require_file(&recipes.join(recipe.directory()).join("conanfile.py"));
    }
    if required_env("CARGO_CFG_TARGET_OS") != "linux"
        || required_env("CARGO_CFG_TARGET_ARCH") != "x86_64"
    {
        panic!("recipe bundle currently supports only native Linux x86_64 builds");
    }
    let conan = require_program("conan", "Conan 2");
    let _compiler = require_program("cc", "C compiler");
    let _cmake = require_program("cmake", "CMake");
    let _ninja = require_program("ninja", "Ninja");
    if required_env("TARGET") == "x86_64-unknown-linux-musl" {
        let _musl_compiler = require_program("musl-gcc", "musl C compiler");
    }
    run(&conan, ["--version"], &manifest);
    run(&conan, ["profile", "path", "default"], &manifest);
    let remotes = run_capture(&conan, ["remote", "list"], &manifest);
    let expected_remote = format!("amnezia: {AMNEZIA_REMOTE}");
    if !remotes
        .lines()
        .any(|line| line.starts_with(&expected_remote))
    {
        panic!("required Conan remote is missing or has the wrong URL: {expected_remote}");
    }
    export_recipes(&conan, &recipes);

    let conan_output = PathBuf::from(required_env("OUT_DIR")).join("conan");
    let deploy = conan_output.join("deploy");
    if conan_output.exists() {
        fs::remove_dir_all(&conan_output).unwrap_or_else(|error| {
            panic!(
                "remove stale Conan output {}: {error}",
                conan_output.display()
            );
        });
    }
    fs::create_dir_all(&conan_output).unwrap_or_else(|error| {
        panic!("create Conan output {}: {error}", conan_output.display());
    });

    let install_arguments = vec![
        "install".into(),
        source.as_os_str().to_owned(),
        format!("--output-folder={}", conan_output.display()).into(),
        "--build=missing".into(),
        "--deployer=full_deploy".into(),
        format!("--deployer-folder={}", deploy.display()).into(),
    ];
    run_os(&conan, &install_arguments, &manifest);

    let bundle = profile_directory().join("libexec").join("amn");
    if bundle.exists() {
        fs::remove_dir_all(&bundle).unwrap_or_else(|error| {
            panic!("remove stale bundle {}: {error}", bundle.display());
        });
    }
    fs::create_dir_all(&bundle).unwrap_or_else(|error| {
        panic!("create bundle {}: {error}", bundle.display());
    });
    let deployed_packages = deploy.join("full_deploy").join("host");
    let xray_package = deployed_packages.join("amnezia-xray-bindings/1.3.0/x86_64");
    let xray_library = xray_package.join("lib/libamnezia_xray.a");
    let xray_header = xray_package.join("include/amnezia_xray.h");
    validate_artifact(&xray_library, false);
    require_file(&xray_header);
    let xray_runner_source = manifest.join("src/core/amnezia_xray_runner.c");
    require_file(&xray_runner_source);
    let xray_runner = bundle.join("amnezia-xray-runner");
    let compiler = require_program("cc", "C compiler");
    run_os(
        &compiler,
        &[
            xray_runner_source.into_os_string(),
            xray_library.into_os_string(),
            format!("-I{}", xray_package.join("include").display()).into(),
            "-Wall".into(),
            "-Wextra".into(),
            "-Werror".into(),
            "-pthread".into(),
            "-ldl".into(),
            "-lm".into(),
            "-lresolv".into(),
            "-o".into(),
            xray_runner.as_os_str().to_owned(),
        ],
        &manifest,
    );
    validate_artifact(&xray_runner, true);

    for artifact_kind in
        std::iter::successors(Some(RecipeArtifact::OpenVpn), |artifact| artifact.next())
    {
        let artifact = deployed_packages.join(artifact_kind.package_path());
        validate_artifact(&artifact, artifact_kind.executable());
        let destination = bundle.join(artifact_kind.destination_name());
        fs::copy(&artifact, &destination).unwrap_or_else(|error| {
            panic!(
                "copy {} to {}: {error}",
                artifact.display(),
                destination.display()
            );
        });
        if artifact_kind.executable() {
            make_executable(&destination);
        }
    }
}

fn export_recipes(conan: &Path, recipes: &Path) {
    let mut recipe_directories = fs::read_dir(recipes)
        .unwrap_or_else(|error| panic!("read recipes directory {}: {error}", recipes.display()))
        .map(|entry| {
            entry
                .unwrap_or_else(|error| panic!("read recipe entry: {error}"))
                .path()
        })
        .filter(|path| path.join("conanfile.py").is_file())
        .collect::<Vec<_>>();
    recipe_directories.sort();
    if recipe_directories.is_empty() {
        panic!("no Conan recipes found in {}", recipes.display());
    }
    for recipe in recipe_directories {
        if recipe.file_name() == Some(OsStr::new("go")) {
            run_os(
                conan,
                &[
                    "export".into(),
                    recipe.as_os_str().to_owned(),
                    "--version".into(),
                    "1.26.0".into(),
                ],
                recipes,
            );
            run_os(
                conan,
                &[
                    "export".into(),
                    recipe.as_os_str().to_owned(),
                    "--version".into(),
                    "1.23.12".into(),
                ],
                recipes,
            );
        } else {
            run_os(
                conan,
                &["export".into(), recipe.as_os_str().to_owned()],
                recipes,
            );
        }
    }
}

fn run_capture<const N: usize>(program: &Path, arguments: [&str; N], directory: &Path) -> String {
    let output = Command::new(program)
        .args(arguments)
        .current_dir(directory)
        .output()
        .unwrap_or_else(|error| panic!("run {}: {error}", program.display()));
    if !output.status.success() {
        panic!("{} failed with {}", program.display(), output.status);
    }
    String::from_utf8(output.stdout).unwrap_or_else(|error| {
        panic!("{} produced non-UTF-8 output: {error}", program.display());
    })
}

fn run<const N: usize>(program: &Path, arguments: [&str; N], directory: &Path) {
    let arguments = arguments.into_iter().map(Into::into).collect::<Vec<_>>();
    run_os(program, &arguments, directory);
}

fn run_os(program: &Path, arguments: &[std::ffi::OsString], directory: &Path) {
    let status = Command::new(program)
        .args(arguments)
        .current_dir(directory)
        .status()
        .unwrap_or_else(|error| panic!("run {}: {error}", program.display()));
    if !status.success() {
        panic!("{} failed with {status}", program.display());
    }
}

fn required_env(name: &str) -> String {
    env::var(name)
        .unwrap_or_else(|_| panic!("required build environment variable is missing: {name}"))
}

fn require_file(path: &Path) {
    if !path.is_file() {
        panic!("required build input does not exist: {}", path.display());
    }
}

fn require_directory(path: &Path) {
    if !path.is_dir() {
        panic!("required build input does not exist: {}", path.display());
    }
}

fn require_program(name: &str, description: &str) -> PathBuf {
    find_program(name).unwrap_or_else(|| {
        panic!("required recipe build dependency not found: {description} ({name})");
    })
}

fn find_program(name: &str) -> Option<PathBuf> {
    env::var_os("PATH")
        .map(|path| env::split_paths(&path).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
}

fn validate_artifact(path: &Path, executable: bool) {
    let metadata = fs::metadata(path).unwrap_or_else(|error| {
        panic!(
            "required recipe output does not exist: {}: {error}",
            path.display()
        );
    });
    if !metadata.is_file() || metadata.len() == 0 {
        panic!(
            "required recipe output is not a nonempty regular file: {}",
            path.display()
        );
    }
    if executable {
        let mut file = fs::File::open(path).unwrap_or_else(|error| {
            panic!("open recipe executable {}: {error}", path.display());
        });
        let mut magic = [0_u8; 4];
        file.read_exact(&mut magic).unwrap_or_else(|error| {
            panic!("read recipe executable {}: {error}", path.display());
        });
        if magic != *b"\x7fELF" {
            panic!(
                "recipe executable is not a Linux ELF file: {}",
                path.display()
            );
        }
    }
}

fn profile_directory() -> PathBuf {
    let output = PathBuf::from(required_env("OUT_DIR"));
    let build_directory = output
        .ancestors()
        .find(|ancestor| ancestor.file_name() == Some(OsStr::new("build")))
        .unwrap_or_else(|| panic!("OUT_DIR does not use Cargo's target profile layout"));
    build_directory
        .parent()
        .unwrap_or_else(|| panic!("Cargo build directory has no profile parent"))
        .to_path_buf()
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap_or_else(|error| {
        panic!("set executable permissions on {}: {error}", path.display())
    });
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}
