## libsodium-ffi

[![Build Status](https://travis-ci.org/zonyitoo/libsodium-ffi.svg?branch=master)](https://travis-ci.org/zonyitoo/libsodium-ffi)
[![Build status](https://ci.appveyor.com/api/projects/status/em09bc2uktyvnf3h?svg=true)](https://ci.appveyor.com/project/zonyitoo/libsodium-ffi)

Rust native binding to [libsodium](https://github.com/jedisct1/libsodium)

```toml
# Cargo.toml
[dependencies]
libsodium-ffi = "0.1"
```

## Usage

Environement variables

- `SODIUM_LIB_DIR=/path/to/libsodium` for telling cargo where to find libsodium

- `SODIUM_STATIC=yes` for telling cargo to static-link libsodium

- `SODIUM_BUILD_STATIC=yes` force build from source instead of trying to find libsodium in system-wide

## Thanks

- `build.rs` is partially borrowed from [rust_sodium](https://github.com/maidsafe/rust_sodium/tree/master/rust_sodium-sys) project.
