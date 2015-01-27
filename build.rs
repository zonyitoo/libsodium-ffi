
extern crate "pkg-config" as pkg_config;

use std::io::{self, fs, Command};
use std::os;
use std::io::fs::PathExtensions;
use std::io::process::InheritFd;

fn main() {
    match pkg_config::find_library("libsodium") {
        Ok(()) => return,
        Err(..) => {}
    }

    let src = Path::new(os::getenv("CARGO_MANIFEST_DIR").unwrap());
    let dst = Path::new(os::getenv("OUT_DIR").unwrap());
    let target = os::getenv("TARGET").unwrap();

    let root = src.join("libsodium");

    run(Command::new("sh")
            .arg("-c")
            .arg(root.join("autogen.sh"))
            .cwd(&root));

    let _ = fs::rmdir_recursive(&dst.join("include"));
    let _ = fs::rmdir_recursive(&dst.join("lib"));
    let _ = fs::rmdir_recursive(&dst.join("build"));
    fs::mkdir(&dst.join("build"), io::USER_DIR).unwrap();

    let mut config_opts = Vec::new();
    config_opts.push(format!("{:?}", root.join("configure")));
    config_opts.push(format!("--prefix={:?}", dst));
    config_opts.push("--disable-shared".to_string());
    config_opts.push("--enable-static=yes".to_string());

    if target.contains("android") {
        config_opts.push("--disable-soname-versions".to_string());
    }

    run(Command::new("sh")
            .arg("-c")
            .arg(config_opts.connect(" "))
            .cwd(&dst.join("build")));

    run(Command::new(make())
            .arg(format!("-j{}", os::getenv("NUM_JOBS").unwrap()))
            .cwd(&dst.join("build")));

    run(Command::new(make())
            .arg(format!("-j{}", os::getenv("NUM_JOBS").unwrap()))
            .arg("install")
            .cwd(&dst.join("build")));

    println!("cargo:rustc-flags=-L {}/lib -l sodium:static", dst.display());
    println!("cargo:root={}", dst.display());
    println!("cargo:include={}/include", dst.display());
}

fn make() -> &'static str {
    if cfg!(target_os = "freebsd") {"gmake"} else {"make"}
}

fn run(cmd: &mut Command) {
    println!("running: {:?}", cmd);
    assert!(cmd.stdout(InheritFd(1))
               .stderr(InheritFd(2))
               .status()
               .unwrap()
               .success());
}
