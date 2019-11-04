#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)] //  warn long double -> u128 is not FFI-safe

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
