extern crate pkg_config;

use std::fs;
use std::process::{Command, Stdio};
use std::env;
use std::path::Path;

fn main() {
    match pkg_config::find_library("libsodium") {
        Ok(..) => return,
        Err(..) => {}
    }

    let cargo_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_dir = env::var("OUT_DIR").unwrap();

    let src = Path::new(&cargo_dir[..]);
    let dst = Path::new(&output_dir[..]);
    let target = env::var("TARGET").unwrap();

    let root = src.join("libsodium");

    run(Command::new("sh")
            .arg("-c")
            .arg(&root.join("autogen.sh"))
            .current_dir(&root));

    let _ = fs::remove_dir_all(&dst.join("include"));
    let _ = fs::remove_dir_all(&dst.join("lib"));
    let _ = fs::remove_dir_all(&dst.join("build"));
    fs::create_dir(&dst.join("build")).unwrap();

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
            .arg(&config_opts.connect(" "))
            .current_dir(&dst.join("build")));

    run(Command::new(make())
            .arg(&format!("-j{}", env::var("NUM_JOBS").unwrap()))
            .current_dir(&dst.join("build")));

    run(Command::new(make())
            .arg(&format!("-j{}", env::var("NUM_JOBS").unwrap()))
            .arg("install")
            .current_dir(&dst.join("build")));

    println!("cargo:rustc-flags=-L {}/lib -l sodium", dst.display());
    println!("cargo:root={}", dst.display());
    println!("cargo:include={}/include", dst.display());
}

fn make() -> &'static str {
    if cfg!(target_os = "freebsd") {"gmake"} else {"make"}
}

fn run(cmd: &mut Command) {
    println!("running: {:?}", cmd);
    assert!(cmd.stdout(Stdio::inherit())
               .stderr(Stdio::inherit())
               .status()
               .unwrap()
               .success());
}
