use std::env;
use std::path::PathBuf;
#[cfg(unix)]
use std::process::{Command, Stdio};

use bindgen;
use pkg_config;
use unwrap::unwrap;
use vcpkg;
#[cfg(windows)]
use zip;

const VERSION: &'static str = "1.0.18";

#[cfg(target_env = "msvc")]
const SODIUM_LINK_NAME: &str = "libsodium";
#[cfg(not(target_env = "msvc"))]
const SODIUM_LINK_NAME: &str = "sodium";

fn main() {
    build_libsodium();
}

fn generate_bindings(include_dirs: &[PathBuf]) {
    println!("Invoking bindgen with search paths {:?}", include_dirs);

    let mut builder = bindgen::Builder::default().header("sodium_wrapper.h");
    for p in include_dirs {
        builder = builder.clang_arg(format!("-I{}", p.display()));
    }
    let bindings = builder.generate().expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings.rs");
}

fn build_libsodium() {
    println!("cargo:rerun-if-env-changed=SODIUM_LIB_DIR");
    println!("cargo:rerun-if-env-changed=SODIUM_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=SODIUM_STATIC");
    println!("cargo:rerun-if-env-changed=SODIUM_BUILD_STATIC");

    if probe_libsodium_vcpkg() {
        return;
    }

    let is_static = match env::var_os("SODIUM_STATIC") {
        Some(_) => {
            println!("cargo:rustc-link-lib=static={}", SODIUM_LINK_NAME);
            true
        }
        None => {
            println!("cargo:rustc-link-lib=dylib={}", SODIUM_LINK_NAME);
            false
        }
    };
    // Use library provided by environ
    if let Ok(lib_dir) = env::var("SODIUM_LIB_DIR") {
        let kind = if is_static { "static" } else { "native" };
        println!("cargo:rustc-link-search={}={}", kind, lib_dir);

        match env::var("SODIUM_INCLUDE_DIR") {
            Err(..) => panic!("You have to provide SODIUM_LIB_DIR and SODIUM_INCLUDE_DIR together"),
            Ok(include_dir) => {
                generate_bindings(&vec![PathBuf::from(include_dir)]);
            }
        }

        return;
    }

    // Build from source
    if let Some(..) = env::var_os("SODIUM_BUILD_STATIC") {
        println!("Building libsodium {} from source", VERSION);

        build();

        let mut include_dir = PathBuf::from(unwrap!(env::var("OUT_DIR")));
        include_dir.push("include");
        generate_bindings(&vec![include_dir]);
    } else {
        // Uses system-wide libsodium
        // For windows, check vcpkg first
        if cfg!(windows) {
            match vcpkg::find_package("libsodium") {
                Ok(lib) => {
                    generate_bindings(&lib.include_paths);
                }
                Err(..) => {
                    println!("cargo:warning=Failed to find \"libsodium\" in vcpkg, falling back to pkg-config");
                }
            }
        }

        // Uses pkg-config
        match pkg_config::find_library("libsodium") {
            Ok(lib) => {
                generate_bindings(&lib.include_paths);
            }
            Err(..) => panic!(
                "Missing libsodium library in your system, try to use SODIUM_BUILD_STATIC=yes to build it from source"
            ),
        }
    }
}

#[cfg(windows)]
fn probe_libsodium_vcpkg() -> bool {
    vcpkg::probe_package("libsodium").is_ok()
}

#[cfg(not(windows))]
fn probe_libsodium_vcpkg() -> bool {
    false
}

fn get_install_dir() -> PathBuf {
    PathBuf::from(unwrap!(env::var("OUT_DIR")))
}

#[cfg(windows)]
fn check_powershell_version() {
    let mut check_ps_version_cmd = ::std::process::Command::new("powershell");
    let check_ps_version_output = check_ps_version_cmd
        .arg("-Command")
        .arg("If ($PSVersionTable.PSVersion.Major -lt 4) { exit 1 }")
        .output()
        .unwrap_or_else(|error| {
            panic!("Failed to run powershell command: {}", error);
        });
    if !check_ps_version_output.status.success() {
        panic!(
            "\n{:?}\n{}\n{}\nYou must have Powershell v4.0 or greater installed.\n\n",
            check_ps_version_cmd,
            String::from_utf8_lossy(&check_ps_version_output.stdout),
            String::from_utf8_lossy(&check_ps_version_output.stderr)
        );
    }
}

#[cfg(windows)]
fn download_compressed_file() -> PathBuf {
    use std::process::Command;

    let basename = format!("libsodium-{}", VERSION);
    let zip_filename = if cfg!(target_env = "msvc") {
        format!("{}-msvc.zip", basename)
    } else {
        format!("{}-mingw.tar.gz", basename)
    };
    let url = format!(
        "https://download.libsodium.org/libsodium/releases/{}",
        zip_filename
    );

    println!("Downloading {} from {}", zip_filename, url);

    let mut zip_path = get_install_dir();
    zip_path.push(&zip_filename);
    let command = format!(
        "([Net.ServicePointManager]::SecurityProtocol = 'Tls12') -and ((New-Object System.Net.WebClient).DownloadFile(\"{}\", \"{}\"))",
        url, zip_path.display()
    );
    let mut download_cmd = Command::new("powershell");
    download_cmd.arg("-Command").arg(&command);
    println!("Running command: {:?}", download_cmd);
    let download_output = download_cmd.output().unwrap_or_else(|error| {
        panic!("Failed to run powershell download command: {}", error);
    });
    if download_output.status.success() {
        println!(
            "Finished donwload {}, saved to {}",
            zip_filename,
            zip_path.display()
        );
        return zip_path;
    }

    let fallback_url = format!(
        "https://raw.githubusercontent.com/maidsafe/QA/master/appveyor/{}",
        zip_filename
    );
    println!(
        "cargo:warning=Failed to download libsodium from {}. Falling back to MaidSafe mirror at {}",
        url, fallback_url
    );

    let command = format!(
        "([Net.ServicePointManager]::SecurityProtocol = 'Tls12') -and ((New-Object System.Net.WebClient).DownloadFile(\"{}\", \"{}\"))",
        fallback_url, zip_path.display()
    );
    let mut download_cmd = Command::new("powershell");
    download_cmd.arg("-Command").arg(&command);
    println!("Running command: {:?}", download_cmd);
    let download_output = download_cmd.output().unwrap_or_else(|error| {
        panic!("Failed to run powershell download command: {}", error);
    });
    if !download_output.status.success() {
        panic!(
            "\n{:?}\n{}\n{}\n",
            download_cmd,
            String::from_utf8_lossy(&download_output.stdout),
            String::from_utf8_lossy(&download_output.stderr)
        );
    }

    println!(
        "Finished donwload {}, saved to {}",
        zip_filename,
        zip_path.display()
    );
    zip_path
}

#[cfg(unix)]
fn download_compressed_file() -> PathBuf {
    use curl::easy::Easy;
    use std::fs::File;
    use std::io::Write;

    let zip_filename = format!("libsodium-{}.tar.gz", VERSION);
    let url = format!(
        "https://download.libsodium.org/libsodium/releases/{}",
        zip_filename
    );

    println!("Downloading {} from {}", zip_filename, url);

    let mut gz_path = get_install_dir();
    gz_path.push(&zip_filename);

    // Download to .tar.gz
    let mut zf = unwrap!(File::create(&gz_path));

    let mut easy = Easy::new();
    unwrap!(easy.url(&url));
    unwrap!(easy.write_function(move |data| {
        let n = unwrap!(zf.write(data));
        Ok(n)
    }));
    unwrap!(easy.perform());

    println!(
        "Finished download {}, saved to {}",
        zip_filename,
        gz_path.display()
    );

    gz_path
}

#[cfg(all(windows, target_env = "msvc"))]
fn build() {
    use std::fs::{self, File};
    use std::io::{self, Read, Write};
    use std::path::Path;
    use zip::ZipArchive;

    check_powershell_version();

    // Download zip file
    let install_dir = get_install_dir();
    let lib_install_dir = install_dir.join("lib");
    let include_install_dir = install_dir.join("include");

    // Create out/lib & out/include
    unwrap!(fs::create_dir_all(&lib_install_dir));
    unwrap!(fs::create_dir_all(&include_install_dir));

    // Download pre-built library
    let zip_path = download_compressed_file();

    // Unpack the zip file
    let zip_file = unwrap!(File::open(&zip_path));
    let mut zip_archive = unwrap!(ZipArchive::new(zip_file));

    // Extract just the appropriate version of libsodium.lib and headers to the install path.  For
    // now, only handle MSVC 2015.
    let arch_path = if cfg!(target_pointer_width = "32") {
        Path::new("libsodium/Win32")
    } else if cfg!(target_pointer_width = "64") {
        Path::new("libsodium/x64")
    } else {
        panic!("target_pointer_width not 32 or 64")
    };

    // The library path inside the archive
    let unpacked_lib = arch_path.join("Release/v140/static/libsodium.lib");

    println!("Searching for lib {}", unpacked_lib.display());

    // Include path prefix
    let unpacked_include = Path::new("libsodium/include");

    println!("Searching for headers from {}", unpacked_include.display());

    fn copy_file<R: Read, W: Write>(r: &mut R, w: &mut W) -> io::Result<()> {
        let mut buf = [0u8; 10240];
        loop {
            let n = r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            w.write_all(&buf[..n])?;
        }
        Ok(())
    }

    for i in 0..zip_archive.len() {
        let mut entry = unwrap!(zip_archive.by_index(i));
        let entry_name = entry.name();
        let entry_path = Path::new(entry_name);

        // 1. Deal with library
        if entry_path == unpacked_lib {
            // Write to lib_install_dir
            let lib_file_path = lib_install_dir.join("libsodium.lib");
            let mut lib_file = unwrap!(File::create(&lib_file_path));
            unwrap!(copy_file(&mut entry, &mut lib_file));

            println!("Unpacked lib to {}", lib_file_path.display());
        }
        // 2. include path
        else if entry_path.starts_with(unpacked_include) {
            // Copy them into include_install_dir
            let relative_path = unwrap!(entry_path.strip_prefix(&unpacked_include));
            let include_file_path = include_install_dir.join(&relative_path);
            if entry.is_dir() {
                let _ = fs::create_dir(&include_file_path);
            } else {
                let mut include_file = unwrap!(File::create(&include_file_path));
                unwrap!(copy_file(&mut entry, &mut include_file));
            }

            println!("Unpacked header to {}", include_file_path.display());
        }
    }

    // Clean up
    let _ = fs::remove_file(zip_path);

    println!("cargo:rustc-link-lib=static=libsodium");
    println!(
        "cargo:rustc-link-search=native={}",
        lib_install_dir.display()
    );
    println!("cargo:include={}", include_install_dir.display());
}

#[cfg(all(windows, not(target_env = "msvc")))]
fn build() {
    use flate2::read::GzDecoder;
    use std::fs::{self, File};
    use std::path::Path;
    use tar::Archive;

    check_powershell_version();

    // Download gz tarball
    let install_dir = get_install_dir();
    let lib_install_dir = install_dir.join("lib");
    let include_install_dir = install_dir.join("include");

    // Create out/lib & out/include
    unwrap!(fs::create_dir_all(&lib_install_dir));
    unwrap!(fs::create_dir_all(&include_install_dir));

    // Download pre-built library
    let gz_path = download_compressed_file();

    // Unpack the tarball
    let gz_archive = unwrap!(File::open(&gz_path));
    let gz_decoder = GzDecoder::new(gz_archive);
    let mut archive = Archive::new(gz_decoder);

    // Extract just the appropriate version of libsodium.a and headers to the install path
    let arch_path = if cfg!(target_pointer_width = "32") {
        Path::new("libsodium-win32")
    } else if cfg!(target_pointer_width = "64") {
        Path::new("libsodium-win64")
    } else {
        panic!("target_pointer_width not 32 or 64")
    };

    let unpacked_lib = arch_path.join("lib\\libsodium.a");
    println!("Searching for lib {}", unpacked_lib.display());

    let unpacked_include = arch_path.join("include");
    println!("Searching for headers from {}", unpacked_include.display());

    for entry_result in unwrap!(archive.entries()) {
        let mut entry = unwrap!(entry_result);
        let entry_path = unwrap!(entry.path()).to_path_buf();

        // 1. Include path
        if entry_path.starts_with(&unpacked_include) {
            let relative_path = unwrap!(entry_path.strip_prefix(&unpacked_include));
            let install_path = include_install_dir.join(&relative_path);
            unwrap!(entry.unpack(install_path));

            println!("Unpacked header to {}", install_path.display());
        }
        // 2. Lib path
        else if entry_path == unpacked_lib {
            let install_path = lib_install_dir.join("libsodium.a");
            unwrap!(entry.unpack(install_path));

            println!("Unpacked lib to {}", install_path.display());
        }
    }

    // Clean up
    let _ = fs::remove_file(gz_path);

    println!("cargo:rustc-link-lib=static=sodium");
    println!(
        "cargo:rustc-link-search=native={}",
        lib_install_dir.display()
    );
    println!("cargo:include={}", include_install_dir.display());
}

#[cfg(unix)]
fn build() {
    use flate2::read::GzDecoder;
    use std::fs::{self, File};
    use std::path::Path;
    use tar::Archive;

    let gz_path = download_compressed_file();

    // Unpack the tarball
    let gz_archive = unwrap!(File::open(&gz_path));
    let gz_decoder = GzDecoder::new(gz_archive);
    let mut archive = Archive::new(gz_decoder);

    // Build one by ourselves
    let output_dir = unwrap!(env::var("OUT_DIR"));

    let dst = Path::new(&output_dir[..]);

    // Unpack to ${OUTPUT_DIR}/libsodium-VERSION
    unwrap!(archive.unpack(&dst));

    let root = dst.join(format!("libsodium-{}", VERSION));

    println!("Finished unpack to {}", root.display());

    let target = unwrap!(env::var("TARGET"));

    let include_dir = dst.join("include");

    let _ = fs::remove_dir_all(&include_dir);
    let _ = fs::remove_dir_all(&dst.join("lib"));

    let build_dir = dst.join("build");
    let _ = fs::remove_dir_all(&build_dir);
    fs::create_dir(&build_dir).unwrap();

    let mut configure_cmd = Command::new("sh");
    configure_cmd.arg("-c");

    let cmd_path = format!("{}", root.join("configure").display());
    let dst_path = format!("{}", dst.display());
    let mut ccmd = format!(
        "{} --prefix={} --disable-shared --enable-static=yes",
        cmd_path, dst_path
    );
    if target.contains("android") {
        ccmd += " --disable-soname-versions";
    }
    configure_cmd.arg(&ccmd);
    run(configure_cmd.current_dir(&build_dir));

    run(Command::new(make())
        .arg(&format!("-j{}", env::var("NUM_JOBS").unwrap()))
        .current_dir(&build_dir));

    run(Command::new(make())
        .arg(&format!("-j{}", env::var("NUM_JOBS").unwrap()))
        .arg("install")
        .current_dir(&build_dir));

    println!("cargo:rustc-link-lib=static=sodium");
    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:include={}", include_dir.display());
    println!("cargo:root={}", dst.display());

    fn make() -> &'static str {
        if cfg!(target_os = "freebsd") {
            "gmake"
        } else {
            "make"
        }
    }

    fn run(cmd: &mut Command) {
        println!("Run command: {:?}", cmd);
        assert!(unwrap!(cmd
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status())
        .success());
    }
}
