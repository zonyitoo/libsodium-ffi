extern crate cc;
extern crate pkg_config;

use std::fs;
use std::process::{Command, Stdio};
use std::env;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=SODIUM_LIB_DIR");
    println!("cargo:rerun-if-env-changed=SODIUM_STATIC");
    println!("cargo:rerun-if-env-changed=SODIUM_BUILD_STATIC");

    // Use library provided by environ
    if let Ok(lib_dir) = env::var("SODIUM_LIB_DIR") {
        println!("cargo:rustc-link-search=native={}", lib_dir);

        let mode = match env::var_os("SODIUM_STATIC") {
            Some(_) => "static",
            None => "dylib",
        };
        println!("cargo:rustc-link-lib={0}=sodium", mode);
        return;
    }

    if let None = env::var_os("SODIUM_BUILD_STATIC") {
        // Uses system-wide libsodium
        match pkg_config::find_library("libsodium") {
            Ok(..) => return,
            Err(..) => panic!(
                "Missing libsodium library in your system, \
                 try to use SODIUM_BUILD_STATIC=yes to build it from source"
            ),
        }
    }

    build();
}

#[cfg(all(windows, not(target_env = "gnu")))]
fn build() {
    let platform = if cfg!(target_pointer_width = "32") {
        "x32"
    } else {
        "x64"
    };

    let cargo_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_dir = env::var("OUT_DIR").unwrap();

    let src = Path::new(&cargo_dir[..]);
    let dst = Path::new(&output_dir[..]);
    let solution_dir = src.join("libsodium");
    println!("Solution Dir: {}", solution_dir.display());

    let _ = fs::remove_dir_all(&dst);

    let target = env::var("TARGET").expect("TARGET not found in environment");

    let mut cmd =
        cc::windows_registry::find(&target[..], "msbuild.exe").expect("Failed to find MSBuild.exe");
    cmd.arg(&format!("/m:{}", env::var("NUM_JOBS").unwrap()))
        .arg("/verbosity:minimal")
        .arg("/p:Configuration=Release")
        .arg(&format!("/p:OutDir={}\\", dst.display()))
        .arg(&format!(
            "/p:IntDir={}\\",
            dst.join("Intermediate").display()
        ))
        .arg(&format!("/p:Platform={}", platform))
        .current_dir(&solution_dir)
        .arg("libsodium.vcxproj");

    run(&mut cmd);

    println!("cargo:rustc-link-lib=static=libsodium");
    println!("cargo:rustc-link-search=native={}", dst.display());
    println!("cargo:root={}", dst.display());
}

#[cfg(any(unix, all(windows, target_env = "gnu")))]
fn build() {
    // Build one by ourselves
    let cargo_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_dir = env::var("OUT_DIR").unwrap();

    let src = Path::new(&cargo_dir[..]);
    let dst = Path::new(&output_dir[..]);
    let target = env::var("TARGET").unwrap();

    let root = src.join("libsodium");

    let mut autogen_cmd = Command::new("sh");
    autogen_cmd.arg("-c");

    let mut ccmd = format!("{}", root.join("autogen.sh").display());
    if cfg!(windows) {
        ccmd = ccmd.replace("\\", "/");
    }
    autogen_cmd.arg(&ccmd);
    run(autogen_cmd.current_dir(&root));

    let _ = fs::remove_dir_all(&dst.join("include"));
    let _ = fs::remove_dir_all(&dst.join("lib"));

    let build_dir = dst.join("build");
    let _ = fs::remove_dir_all(&build_dir);
    fs::create_dir(&build_dir).unwrap();

    let mut configure_cmd = Command::new("sh");
    configure_cmd.arg("-c");

    let mut cmd_path = format!("{}", root.join("configure").display());
    if cfg!(windows) {
        cmd_path = cmd_path.replace("\\", "/");
    }

    let mut dst_path = format!("{}", dst.display());
    if cfg!(windows) {
        dst_path = dst_path.replace("\\", "/");
    }

    let mut ccmd = format!(
        "{} --prefix={} --disable-shared --enable-static=yes",
        cmd_path,
        dst_path
    );
    if target.contains("android") {
        ccmd += " --disable-soname-versions";
    }
    configure_cmd.arg(&ccmd);
    run(configure_cmd.current_dir(&build_dir));

    run(
        Command::new(make())
            .arg(&format!("-j{}", env::var("NUM_JOBS").unwrap()))
            .current_dir(&build_dir),
    );

    run(
        Command::new(make())
            .arg(&format!("-j{}", env::var("NUM_JOBS").unwrap()))
            .arg("install")
            .current_dir(&build_dir),
    );

    println!("cargo:rustc-link-lib=static=sodium");
    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:root={}", dst.display());

    fn make() -> &'static str {
        if cfg!(target_os = "freebsd") {
            "gmake"
        } else {
            "make"
        }
    }
}

fn run(cmd: &mut Command) {
    println!("running: {:?}", cmd);
    assert!(
        cmd.stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .unwrap()
            .success()
    );
}
