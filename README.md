## libsodium-sys

[![Build Status](https://travis-ci.org/zonyitoo/libsodium-sys.svg)](https://travis-ci.org/zonyitoo/libsodium-sys)

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
