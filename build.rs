use std::{
    env,
    ffi::OsStr,
    fs,
    io::Read,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
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
            Self::XRayBindings => Some(Self::OpenSsl),
            Self::OpenSsl => Some(Self::LibCapNg),
            Self::LibCapNg => None,
        }
    }
}

const AMNEZIA_REMOTE: &str =
    "https://artifactory.amnezia.org/artifactory/api/conan/client-prebuilts";
const BUNDLE_ARTIFACTS: &[&str] = &[
    "wg",
    "wg-quick",
    "wireguard-go",
    "awg",
    "awg-quick",
    "openvpn",
    "tun2socks",
    "amneziawg-go",
    "amnezia-xray-runner",
    "amn-dns",
    "geoip.dat",
    "geosite.dat",
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/core/amnezia_xray_runner.go");
    println!("cargo:rerun-if-changed=src/core/amn_dns.rs");
    println!("cargo:rerun-if-changed=thirdparty/amnezia-client/recipes");
    println!("cargo:rerun-if-changed=thirdparty/wireguard-tools/src");
    println!("cargo:rerun-if-changed=thirdparty/amneziawg-tools/src");
    println!("cargo:rerun-if-changed=thirdparty/wireguard-go");

    let manifest = PathBuf::from(required_env("CARGO_MANIFEST_DIR"));
    let source = manifest.join("thirdparty/amnezia-client");
    let recipes = source.join("recipes");
    require_directory(&recipes);
    require_directory(&manifest.join("thirdparty/wireguard-tools/src"));
    require_directory(&manifest.join("thirdparty/amneziawg-tools/src"));
    require_file(&manifest.join("thirdparty/wireguard-go/go.mod"));
    for recipe in std::iter::successors(Some(RecipeInput::OpenVpn), |recipe| recipe.next()) {
        require_file(&recipes.join(recipe.directory()).join("conanfile.py"));
    }
    if required_env("CARGO_CFG_TARGET_OS") != "linux"
        || required_env("CARGO_CFG_TARGET_ARCH") != "x86_64"
    {
        panic!("recipe bundle currently supports only native Linux x86_64 builds");
    }
    let profile = profile_directory();
    let bundle = profile.join("libexec").join("amn");
    let cache = profile.join(".amn-bundle-cache");
    let source_fingerprint = source_fingerprint(&manifest);
    if cached_bundle_is_current(&bundle, &cache, source_fingerprint) {
        return;
    }
    let _ = fs::remove_file(&cache);

    let conan = require_program("conan", "Conan 2");
    let _compiler = require_program("cc", "C compiler");
    let _cmake = require_program("cmake", "CMake");
    let _ninja = require_program("ninja", "Ninja");
    let make = require_program("make", "Make");
    let go = require_program("go", "Go compiler");
    let musl_compiler = require_program("musl-gcc", "musl C compiler");
    let readelf = require_program("readelf", "ELF inspection tool");
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
    let client_conanfile = conan_output.join("conanfile.txt");
    fs::write(
        &client_conanfile,
        "[requires]\nopenvpn/2.7.0\ntun2socks/2.6.0\nawg-go/3.1.20260814\nv2ray-rules-dat/202603162227\n",
    )
    .unwrap_or_else(|error| {
        panic!(
            "write client-only Conan manifest {}: {error}",
            client_conanfile.display()
        )
    });

    let install_arguments = vec![
        "install".into(),
        client_conanfile.as_os_str().to_owned(),
        format!("--output-folder={}", conan_output.display()).into(),
        "--build=openvpn/*".into(),
        "--build=tun2socks/*".into(),
        "--build=awg-go/*".into(),
        "--deployer=full_deploy".into(),
        format!("--deployer-folder={}", deploy.display()).into(),
    ];
    run_os(&conan, &install_arguments, &manifest);

    if bundle.exists() {
        fs::remove_dir_all(&bundle).unwrap_or_else(|error| {
            panic!("remove stale bundle {}: {error}", bundle.display());
        });
    }
    fs::create_dir_all(&bundle).unwrap_or_else(|error| {
        panic!("create bundle {}: {error}", bundle.display());
    });
    let deployed_packages = deploy.join("full_deploy").join("host");
    build_xray_runner(
        XrayBuildTools {
            conan: &conan,
            go: &go,
            readelf: &readelf,
        },
        &recipes.join("amnezia-xray-bindings"),
        &manifest.join("src/core/amnezia_xray_runner.go"),
        &conan_output.join("amnezia-xray-runner"),
        &bundle,
    );
    build_static_rust_helper(
        &musl_compiler,
        &readelf,
        &manifest.join("src/core/amn_dns.rs"),
        &bundle.join("amn-dns"),
    );

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
    build_quick_tools(
        &make,
        &manifest.join("thirdparty/wireguard-tools/src"),
        &conan_output.join("wireguard-tools"),
        &bundle,
        "wg",
        "wg-quick",
    );
    build_quick_tools(
        &make,
        &manifest.join("thirdparty/amneziawg-tools/src"),
        &conan_output.join("amneziawg-tools"),
        &bundle,
        "awg",
        "awg-quick",
    );
    build_wireguard_go(
        &go,
        &manifest.join("thirdparty/wireguard-go"),
        &conan_output.join("wireguard-go"),
        &bundle,
    );
    write_bundle_cache(&bundle, &cache, source_fingerprint);
}

struct XrayBuildTools<'a> {
    conan: &'a Path,
    go: &'a Path,
    readelf: &'a Path,
}

fn build_xray_runner(
    tools: XrayBuildTools<'_>,
    recipe: &Path,
    runner_source: &Path,
    build: &Path,
    bundle: &Path,
) {
    require_file(runner_source);
    copy_directory(recipe, build);
    run(tools.conan, ["source", "."], build);
    fs::copy(runner_source, build.join("main.go")).unwrap_or_else(|error| {
        panic!(
            "copy XRay runner source {}: {error}",
            runner_source.display()
        )
    });
    let runner = bundle.join("amnezia-xray-runner");
    let go_cache = build.join("go-cache");
    let go_path = build.join("go-path");
    fs::create_dir_all(&go_cache)
        .unwrap_or_else(|error| panic!("create Go cache {}: {error}", go_cache.display()));
    fs::create_dir_all(&go_path)
        .unwrap_or_else(|error| panic!("create Go path {}: {error}", go_path.display()));
    let status = Command::new(tools.go)
        .args([
            "build",
            "-mod=readonly",
            "-trimpath",
            "-ldflags=-s -w",
            "-o",
        ])
        .arg(&runner)
        .env("CGO_ENABLED", "0")
        .env("GOOS", "linux")
        .env("GOARCH", "amd64")
        .env("GOTOOLCHAIN", "local")
        .env("GOCACHE", &go_cache)
        .env("GOPATH", &go_path)
        .current_dir(build)
        .status()
        .unwrap_or_else(|error| panic!("run {}: {error}", tools.go.display()));
    if !status.success() {
        panic!("{} failed with {status}", tools.go.display());
    }
    validate_artifact(&runner, true);
    validate_static_elf(tools.readelf, &runner, build);
}

fn build_static_rust_helper(
    musl_compiler: &Path,
    readelf: &Path,
    source: &Path,
    output: &Path,
) {
    require_file(source);
    let compiler = PathBuf::from(required_env("RUSTC"));
    run_os(
        &compiler,
        &[
            source.as_os_str().to_owned(),
            "--edition=2024".into(),
            "--target".into(),
            "x86_64-unknown-linux-musl".into(),
            "-D".into(),
            "warnings".into(),
            "-C".into(),
            "opt-level=2".into(),
            "-C".into(),
            format!("linker={}", musl_compiler.display()).into(),
            "-o".into(),
            output.as_os_str().to_owned(),
        ],
        output.parent().unwrap_or_else(|| Path::new(".")),
    );
    validate_artifact(output, true);
    validate_static_elf(
        readelf,
        output,
        output.parent().unwrap_or_else(|| Path::new(".")),
    );
}

fn validate_static_elf(readelf: &Path, executable: &Path, directory: &Path) {
    let program_headers = run_capture_os(
        readelf,
        &[
            "--program-headers".into(),
            executable.as_os_str().to_owned(),
        ],
        directory,
    );
    if program_headers.lines().any(|line| line.contains(" INTERP ")) {
        panic!(
            "bundled executable is dynamically linked: {}",
            executable.display()
        );
    }
    let versions = run_capture_os(
        readelf,
        &["--version-info".into(), executable.as_os_str().to_owned()],
        directory,
    );
    if versions.contains("GLIBC_") {
        panic!(
            "bundled executable depends on glibc: {}",
            executable.display()
        );
    }
}

fn build_wireguard_go(go: &Path, source: &Path, build: &Path, bundle: &Path) {
    copy_directory(source, build);
    let output = build.join("wireguard-go");
    let status = Command::new(go)
        .args(["build", "-trimpath", "-buildvcs=false", "-o"])
        .arg(&output)
        .env("GOTOOLCHAIN", "local")
        .current_dir(build)
        .status()
        .unwrap_or_else(|error| panic!("run {}: {error}", go.display()));
    if !status.success() {
        panic!("{} failed with {status}", go.display());
    }
    validate_artifact(&output, true);
    let destination = bundle.join("wireguard-go");
    fs::copy(&output, &destination).unwrap_or_else(|error| {
        panic!(
            "copy {} to {}: {error}",
            output.display(),
            destination.display()
        )
    });
    make_executable(&destination);
}

fn build_quick_tools(
    make: &Path,
    source: &Path,
    build: &Path,
    bundle: &Path,
    program: &str,
    quick_program: &str,
) {
    copy_directory(source, build);
    run_os(
        make,
        &[
            "WITH_BASHCOMPLETION=no".into(),
            "WITH_SYSTEMDUNITS=no".into(),
            "WITH_WGQUICK=yes".into(),
            "RUNSTATEDIR=/run".into(),
        ],
        build,
    );
    let executable = build.join("wg");
    validate_artifact(&executable, true);
    let destination = bundle.join(program);
    fs::copy(&executable, &destination).unwrap_or_else(|error| {
        panic!(
            "copy {} to {}: {error}",
            executable.display(),
            destination.display()
        )
    });
    make_executable(&destination);

    let quick = build.join("wg-quick/linux.bash");
    require_file(&quick);
    let destination = bundle.join(quick_program);
    stage_quick_dns_helper(&quick, &destination);
    make_executable(&destination);
}

fn stage_quick_dns_helper(source: &Path, destination: &Path) {
    const INSERTION: &str = "# ~~ function override insertion point ~~";
    const OVERRIDES: &str = r#"set_dns() {
    [[ ${#DNS[@]} -gt 0 || ${#DNS_SEARCH[@]} -gt 0 ]] || return 0
    cmd amn-dns set "$INTERFACE" "${DNS[@]}" --search "${DNS_SEARCH[@]}"
    HAVE_SET_DNS=1
}

unset_dns() {
    [[ ${#DNS[@]} -gt 0 || ${#DNS_SEARCH[@]} -gt 0 ]] || return 0
    cmd amn-dns unset "$INTERFACE"
}
"#;
    let script = fs::read_to_string(source)
        .unwrap_or_else(|error| panic!("read quick tool {}: {error}", source.display()));
    if script.matches(INSERTION).count() != 1 || script.matches("unset_dns || true").count() != 1 {
        panic!("quick tool DNS integration point changed: {}", source.display());
    }
    let script = script
        .replace(INSERTION, OVERRIDES)
        .replace("unset_dns || true", "unset_dns");
    fs::write(destination, script).unwrap_or_else(|error| {
        panic!(
            "write DNS-integrated quick tool {}: {error}",
            destination.display()
        )
    });
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir_all(destination)
        .unwrap_or_else(|error| panic!("create {}: {error}", destination.display()));
    for entry in fs::read_dir(source)
        .unwrap_or_else(|error| panic!("read {}: {error}", source.display()))
    {
        let entry = entry.unwrap_or_else(|error| panic!("read {} entry: {error}", source.display()));
        if entry.file_name() == OsStr::new(".git") {
            continue;
        }
        let source = entry.path();
        let destination = destination.join(entry.file_name());
        let file_type = entry
            .file_type()
            .unwrap_or_else(|error| panic!("inspect {}: {error}", source.display()));
        if file_type.is_dir() {
            copy_directory(&source, &destination);
        } else if file_type.is_file() {
            fs::copy(&source, &destination).unwrap_or_else(|error| {
                panic!(
                    "copy build input {} to {}: {error}",
                    source.display(),
                    destination.display()
                )
            });
        } else if file_type.is_symlink() {
            copy_symlink(&source, &destination);
        } else {
            panic!("build input is not a regular file, directory, or symbolic link: {}", source.display());
        }
    }
}

#[cfg(unix)]
fn copy_symlink(source: &Path, destination: &Path) {
    use std::os::unix::fs::symlink;

    let target = fs::read_link(source)
        .unwrap_or_else(|error| panic!("read symbolic link {}: {error}", source.display()));
    if target.is_absolute() {
        panic!("build input symbolic link is absolute: {}", source.display());
    }
    symlink(&target, destination).unwrap_or_else(|error| {
        panic!(
            "copy symbolic link {} to {}: {error}",
            source.display(),
            destination.display()
        )
    });
}

#[cfg(not(unix))]
fn copy_symlink(source: &Path, _destination: &Path) {
    panic!("symbolic build input is unsupported: {}", source.display());
}

fn export_recipes(conan: &Path, recipes: &Path) {
    for recipe_kind in
        std::iter::successors(Some(RecipeInput::OpenVpn), |recipe| recipe.next())
    {
        let recipe = recipes.join(recipe_kind.directory());
        if matches!(recipe_kind, RecipeInput::Go) {
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
    let arguments = arguments.into_iter().map(Into::into).collect::<Vec<_>>();
    run_capture_os(program, &arguments, directory)
}

fn run_capture_os(
    program: &Path,
    arguments: &[std::ffi::OsString],
    directory: &Path,
) -> String {
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

fn source_fingerprint(manifest: &Path) -> u64 {
    let mut fingerprint = Fingerprint::new();
    fingerprint.update(required_env("TARGET").as_bytes());
    fingerprint.update(required_env("HOST").as_bytes());
    for input in [
        "build.rs",
        "src/core/amnezia_xray_runner.go",
        "src/core/amn_dns.rs",
        "thirdparty/amnezia-client/recipes",
        "thirdparty/wireguard-tools/src",
        "thirdparty/amneziawg-tools/src",
        "thirdparty/wireguard-go",
    ] {
        fingerprint.update(input.as_bytes());
        fingerprint_path(&manifest.join(input), &manifest.join(input), &mut fingerprint);
    }
    fingerprint.finish()
}

fn cached_bundle_is_current(bundle: &Path, cache: &Path, source_fingerprint: u64) -> bool {
    if !BUNDLE_ARTIFACTS.iter().all(|artifact| {
        fs::symlink_metadata(bundle.join(artifact))
            .map(|metadata| metadata.is_file() && metadata.len() > 0)
            .unwrap_or(false)
    }) {
        return false;
    }
    let cache = match fs::read_to_string(cache) {
        Ok(cache) => cache,
        Err(_) => return false,
    };
    let expected = format!(
        "source={source_fingerprint:016x}\nbundle={:016x}\n",
        bundle_fingerprint(bundle)
    );
    cache == expected
}

fn write_bundle_cache(bundle: &Path, cache: &Path, source_fingerprint: u64) {
    let contents = format!(
        "source={source_fingerprint:016x}\nbundle={:016x}\n",
        bundle_fingerprint(bundle)
    );
    fs::write(cache, contents)
        .unwrap_or_else(|error| panic!("write bundle cache {}: {error}", cache.display()));
}

fn bundle_fingerprint(bundle: &Path) -> u64 {
    let mut fingerprint = Fingerprint::new();
    fingerprint_path(bundle, bundle, &mut fingerprint);
    fingerprint.finish()
}

fn fingerprint_path(root: &Path, path: &Path, fingerprint: &mut Fingerprint) {
    let relative = path
        .strip_prefix(root)
        .unwrap_or_else(|_| panic!("fingerprint path is outside its root: {}", path.display()));
    fingerprint.update(relative.as_os_str().as_bytes());
    let metadata = fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("inspect build input {}: {error}", path.display()));
    fingerprint.update(&metadata.permissions().mode().to_le_bytes());
    if metadata.is_dir() {
        fingerprint.update(b"directory");
        let mut entries = fs::read_dir(path)
            .unwrap_or_else(|error| panic!("read build input {}: {error}", path.display()))
            .map(|entry| {
                entry.unwrap_or_else(|error| panic!("read {} entry: {error}", path.display()))
            })
            .filter(|entry| entry.file_name() != OsStr::new(".git"))
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            fingerprint_path(root, &entry.path(), fingerprint);
        }
    } else if metadata.is_file() {
        fingerprint.update(b"file");
        let mut file = fs::File::open(path)
            .unwrap_or_else(|error| panic!("open build input {}: {error}", path.display()));
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("read build input {}: {error}", path.display()));
            if read == 0 {
                break;
            }
            fingerprint.update(&buffer[..read]);
        }
    } else if metadata.file_type().is_symlink() {
        fingerprint.update(b"symlink");
        let target = fs::read_link(path)
            .unwrap_or_else(|error| panic!("read build input link {}: {error}", path.display()));
        fingerprint.update(target.as_os_str().as_bytes());
    } else {
        panic!("unsupported build input type: {}", path.display());
    }
}

struct Fingerprint(u64);

impl Fingerprint {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;

    fn new() -> Self {
        Self(Self::OFFSET)
    }

    fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(Self::PRIME);
        }
        self.0 ^= 0xff;
        self.0 = self.0.wrapping_mul(Self::PRIME);
    }

    fn finish(self) -> u64 {
        self.0
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
