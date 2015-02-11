#![feature(libc)]

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

extern crate libc;

use libc::{size_t, c_uchar, c_int, c_ulonglong, c_char, c_void,
           uint32_t, uint64_t, uint8_t, int32_t, int64_t, uint16_t};

pub const crypto_aead_chacha20poly1305_KEYBYTES: size_t = 32;
pub const crypto_aead_chacha20poly1305_NSECBYTES: size_t = 0;
pub const crypto_aead_chacha20poly1305_NPUBBYTES: size_t = 8;
pub const crypto_aead_chacha20poly1305_ABYTES: size_t = 16;

// sodium/crypto_auth_hmacsha256.h
pub const crypto_auth_hmacsha256_BYTES: size_t = 32;
pub const crypto_auth_hmacsha256_KEYBYTES: size_t = 32;

// sodium/crypto_auth.h
pub const crypto_auth_BYTES: size_t = crypto_auth_hmacsha512256_BYTES;
pub const crypto_auth_KEYBYTES: size_t = crypto_auth_hmacsha512256_KEYBYTES;
pub const crypto_auth_PRIMITIVE: &'static str = "hmacsha512256";

// sodium/crypto_auth_hmacsha512.h
pub const crypto_auth_hmacsha512_BYTES: size_t = 64;
pub const crypto_auth_hmacsha512_KEYBYTES: size_t = 32;

// sodium/crypto_auth_hmacsha512256.h
pub const crypto_auth_hmacsha512256_BYTES: size_t = 32;
pub const crypto_auth_hmacsha512256_KEYBYTES: size_t = 32;

// sodium/crypto_box.h
pub const crypto_box_SEEDBYTES: size_t = crypto_box_curve25519xsalsa20poly1305_SEEDBYTES;
pub const crypto_box_PUBLICKEYBYTES: size_t = crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES;
pub const crypto_box_SECRETKEYBYTES: size_t = crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES;
pub const crypto_box_NONCEBYTES: size_t = crypto_box_curve25519xsalsa20poly1305_NONCEBYTES;
pub const crypto_box_MACBYTES: size_t = crypto_box_curve25519xsalsa20poly1305_MACBYTES;
pub const crypto_box_PRIMITIVE: &'static str = "curve25519xsalsa20poly1305";

// sodium/crypto_box_curve25519xsalsa20poly1305.h
pub const crypto_box_curve25519xsalsa20poly1305_SEEDBYTES: size_t = 32;
pub const crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES: size_t = 32;
pub const crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES: size_t = 32;
pub const crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES: size_t = 32;
pub const crypto_box_curve25519xsalsa20poly1305_NONCEBYTES: size_t = 24;
pub const crypto_box_curve25519xsalsa20poly1305_ZEROBYTES: size_t = 32;
pub const crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES: size_t = 16;
pub const crypto_box_curve25519xsalsa20poly1305_MACBYTES: size_t = crypto_box_curve25519xsalsa20poly1305_ZEROBYTES
                                                            - crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES;


// sodium/crypto_core_hsalsa20.h
pub const crypto_core_hsalsa20_OUTPUTBYTES: size_t = 32;
pub const crypto_core_hsalsa20_INPUTBYTES: size_t = 16;
pub const crypto_core_hsalsa20_KEYBYTES: size_t = 32;
pub const crypto_core_hsalsa20_CONSTBYTES: size_t = 16;

// sodium/crypto_core_salsa20.h
pub const crypto_core_salsa20_OUTPUTBYTES: size_t = 64;
pub const crypto_core_salsa20_INPUTBYTES: size_t = 16;
pub const crypto_core_salsa20_KEYBYTES: size_t = 32;
pub const crypto_core_salsa20_CONSTBYTES: size_t = 16;

// sodium/crypto_core_salsa2012.h
pub const crypto_core_salsa2012_OUTPUTBYTES: size_t = 64;
pub const crypto_core_salsa2012_INPUTBYTES: size_t = 16;
pub const crypto_core_salsa2012_KEYBYTES: size_t = 32;
pub const crypto_core_salsa2012_CONSTBYTES: size_t = 16;

// sodium/crypto_core_salsa208.h
pub const crypto_core_salsa208_OUTPUTBYTES: size_t = 64;
pub const crypto_core_salsa208_INPUTBYTES: size_t = 16;
pub const crypto_core_salsa208_KEYBYTES: size_t = 32;
pub const crypto_core_salsa208_CONSTBYTES: size_t = 16;

// sodium/crypto_generichash.h
pub const crypto_generichash_BYTES_MIN: size_t = crypto_generichash_blake2b_BYTES_MIN;
pub const crypto_generichash_BYTES_MAX: size_t = crypto_generichash_blake2b_BYTES_MAX;
pub const crypto_generichash_BYTES: size_t = crypto_generichash_blake2b_BYTES;
pub const crypto_generichash_KEYBYTES_MIN: size_t = crypto_generichash_blake2b_KEYBYTES_MIN;
pub const crypto_generichash_KEYBYTES_MAX: size_t = crypto_generichash_blake2b_KEYBYTES_MAX;
pub const crypto_generichash_KEYBYTES: size_t = crypto_generichash_blake2b_KEYBYTES;
pub const crypto_generichash_PRIMITIVE: &'static str = "blake2b";

// sodium/crypto_generichash_blake2b.h
pub const crypto_generichash_blake2b_BYTES_MIN: size_t = 16;
pub const crypto_generichash_blake2b_BYTES_MAX: size_t = 64;
pub const crypto_generichash_blake2b_BYTES: size_t = 32;
pub const crypto_generichash_blake2b_KEYBYTES_MIN: size_t = 16;
pub const crypto_generichash_blake2b_KEYBYTES_MAX: size_t = 64;
pub const crypto_generichash_blake2b_KEYBYTES: size_t = 32;
pub const crypto_generichash_blake2b_SALTBYTES: size_t = 16;
pub const crypto_generichash_blake2b_PERSONALBYTES: size_t = 16;

// sodium/crypto_hash_sha512.h
pub const crypto_hash_sha512_BYTES: size_t = 64;

// sodium/crypto_hash_sha256.h
pub const crypto_hash_sha256_BYTES: size_t = 32;

// sodium/crypto_hash.h
pub const crypto_hash_BYTES: size_t = crypto_hash_sha512_BYTES;
pub const crypto_hash_PRIMITIVE: &'static str = "sha512";

// sodium/crypto_onetimeauth.h
pub const crypto_onetimeauth_BYTES: size_t = crypto_onetimeauth_poly1305_BYTES;
pub const crypto_onetimeauth_KEYBYTES: size_t = crypto_onetimeauth_poly1305_KEYBYTES;
pub const crypto_onetimeauth_PRIMITIVE: &'static str = "poly1305";

// sodium/crypto_onetimeauth_poly1305.h
pub const crypto_onetimeauth_poly1305_BYTES: size_t = 16;
pub const crypto_onetimeauth_poly1305_KEYBYTES: size_t = 32;

// sodium/crypto_pwhash_scryptsalsa208sha256.h
pub const crypto_pwhash_scryptsalsa208sha256_SALTBYTES: size_t = 32;
pub const crypto_pwhash_scryptsalsa208sha256_STRBYTES: size_t = 102;
pub const crypto_pwhash_scryptsalsa208sha256_STRPREFIX: &'static str = "$7$";
pub const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE: size_t = 524288;
pub const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE: size_t = 16777216;
pub const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE: size_t = 33554432;
pub const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE: size_t = 1073741824;

// sodium/crypto_scalarmult.h
pub const crypto_scalarmult_BYTES: size_t = crypto_scalarmult_curve25519_BYTES;
pub const crypto_scalarmult_SCALARBYTES: size_t = crypto_scalarmult_curve25519_SCALARBYTES;
pub const crypto_scalarmult_PRIMITIVE: &'static str = "curve25519";

// sodium/crypto_scalarmult_curve25519.h
pub const crypto_scalarmult_curve25519_BYTES: size_t = 32;
pub const crypto_scalarmult_curve25519_SCALARBYTES: size_t = 32;

// sodium/crypto_secretbox.h
pub const crypto_secretbox_KEYBYTES: size_t = crypto_secretbox_xsalsa20poly1305_KEYBYTES;
pub const crypto_secretbox_NONCEBYTES: size_t = crypto_secretbox_xsalsa20poly1305_NONCEBYTES;
pub const crypto_secretbox_MACBYTES: size_t = crypto_secretbox_xsalsa20poly1305_MACBYTES;
pub const crypto_secretbox_PRIMITIVE: &'static str = "xsalsa20poly1305";
pub const crypto_secretbox_ZEROBYTES: size_t = crypto_secretbox_xsalsa20poly1305_ZEROBYTES;
pub const crypto_secretbox_BOXZEROBYTES: size_t = crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES;

// sodium/crypto_secretbox_xsalsa20poly1305.h
pub const crypto_secretbox_xsalsa20poly1305_KEYBYTES: size_t = 32;
pub const crypto_secretbox_xsalsa20poly1305_NONCEBYTES: size_t = 24;
pub const crypto_secretbox_xsalsa20poly1305_ZEROBYTES: size_t = 32;
pub const crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES: size_t = 16;
pub const crypto_secretbox_xsalsa20poly1305_MACBYTES: size_t = crypto_secretbox_xsalsa20poly1305_ZEROBYTES
                                                                - crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES;

// sodium/crypto_shorthash.h
pub const crypto_shorthash_BYTES: size_t = crypto_shorthash_siphash24_BYTES;
pub const crypto_shorthash_KEYBYTES: size_t = crypto_shorthash_siphash24_KEYBYTES;
pub const crypto_shorthash_PRIMITIVE: &'static str = "siphash24";

// sodium/crypto_shorthash_siphash24.h
pub const crypto_shorthash_siphash24_BYTES: size_t = 8;
pub const crypto_shorthash_siphash24_KEYBYTES: size_t = 16;

// sodium/crypto_sign.h
pub const crypto_sign_BYTES: size_t = crypto_sign_ed25519_BYTES;
pub const crypto_sign_SEEDBYTES: size_t = crypto_sign_ed25519_SEEDBYTES;
pub const crypto_sign_PUBLICKEYBYTES: size_t = crypto_sign_ed25519_PUBLICKEYBYTES;
pub const crypto_sign_SECRETKEYBYTES: size_t = crypto_sign_ed25519_SECRETKEYBYTES;
pub const crypto_sign_PRIMITIVE: &'static str = "ed25519";

// sodium/crypto_sign_ed25519.h
pub const crypto_sign_ed25519_BYTES: size_t = 64;
pub const crypto_sign_ed25519_SEEDBYTES: size_t = 32;
pub const crypto_sign_ed25519_PUBLICKEYBYTES: size_t = 32;
pub const crypto_sign_ed25519_SECRETKEYBYTES: size_t = 32 + 32;

// sodium/crypto_sign_edwards25519sha512batch.h
pub const crypto_sign_edwards25519sha512batch_BYTES: size_t = 64;
pub const crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES: size_t = 32;
pub const crypto_sign_edwards25519sha512batch_SECRETKEYBYTES: size_t = 32 + 32;

// sodium/crypto_stream.h
pub const crypto_stream_KEYBYTES: size_t = crypto_stream_xsalsa20_KEYBYTES;
pub const crypto_stream_NONCEBYTES: size_t = crypto_stream_xsalsa20_NONCEBYTES;
pub const crypto_stream_PRIMITIVE: &'static str = "xsalsa20";

// sodium/crypto_stream_aes128ctr.h
pub const crypto_stream_aes128ctr_KEYBYTES: size_t = 16;
pub const crypto_stream_aes128ctr_NONCEBYTES: size_t = 16;
pub const crypto_stream_aes128ctr_BEFORENMBYTES: size_t = 1408;

// sodium/crypto_stream_chacha20.h
pub const crypto_stream_chacha20_KEYBYTES: size_t = 32;
pub const crypto_stream_chacha20_NONCEBYTES: size_t = 8;

// sodium/crypto_stream_salsa20.h
pub const crypto_stream_salsa20_KEYBYTES: size_t = 32;
pub const crypto_stream_salsa20_NONCEBYTES: size_t = 8;

// sodium/crypto_stream_salsa2012.h
pub const crypto_stream_salsa2012_KEYBYTES: size_t = 32;
pub const crypto_stream_salsa2012_NONCEBYTES: size_t = 8;

// sodium/crypto_stream_salsa208.h
pub const crypto_stream_salsa208_KEYBYTES: size_t = 32;
pub const crypto_stream_salsa208_NONCEBYTES: size_t = 8;

// sodium/crypto_stream_xsalsa20.h
pub const crypto_stream_xsalsa20_KEYBYTES: size_t = 32;
pub const crypto_stream_xsalsa20_NONCEBYTES: size_t = 24;

// sodium/crypto_verify_16.h
pub const crypto_verify_16_BYTES: size_t = 16;

// sodium/crypto_verify_32.h
pub const crypto_verify_32_BYTES: size_t = 32;

// sodium/crypto_verify_64.h
pub const crypto_verify_64_BYTES: size_t = 64;

#[link(name = "sodium")]
extern {
    // sodium/core.h
    pub fn sodium_init() -> c_int;

    // sodium/crypto_aead_chacha20poly1305.h
    pub fn crypto_aead_chacha20poly1305_keybytes() -> size_t;
    pub fn crypto_aead_chacha20poly1305_nsecbytes() -> size_t;
    pub fn crypto_aead_chacha20poly1305_npubbytes() -> size_t;
    pub fn crypto_aead_chacha20poly1305_abytes() -> size_t;
    pub fn crypto_aead_chacha20poly1305_encrypt(c: *mut c_uchar,
                                                clen: *mut c_ulonglong,
                                                m: *const c_uchar,
                                                mlen: c_ulonglong,
                                                ad: *const c_uchar,
                                                adlen: c_ulonglong,
                                                nsec: *const c_uchar,
                                                npub: *const c_uchar,
                                                k: *const c_uchar) -> c_int;
    pub fn crypto_aead_chacha20poly1305_decrypt(m: *mut c_uchar,
                                                mlen: *mut c_ulonglong,
                                                nsec: *mut c_uchar,
                                                c: *const c_uchar,
                                                clen: c_ulonglong,
                                                ad: *const c_uchar,
                                                adlen: c_ulonglong,
                                                npub: *const c_uchar,
                                                k: *const c_uchar) -> c_int;

    // sodium/crypto_auth.h
    pub fn crypto_auth_bytes() -> size_t;
    pub fn crypto_auth_keybytes() -> size_t;
    pub fn crypto_auth_primitive() -> *const c_char;
    pub fn crypto_auth(out: *mut c_uchar, in_: *const c_uchar,
                       inlen: c_ulonglong, k: *const c_uchar) -> c_int;
    pub fn crypto_auth_verify(h: *const c_uchar, in_: *const c_uchar,
                              inlen: c_ulonglong, k: *const c_uchar) -> c_int;

    // sodium/crypto_auth_hmacsha256.h
    pub fn crypto_auth_hmacsha256_statebytes() -> size_t;
    pub fn crypto_auth_hmacsha256_bytes() -> size_t;
    pub fn crypto_auth_hmacsha256_keybytes() -> size_t;
    pub fn crypto_auth_hmacsha256(out: *mut c_uchar,
                                  in_: *const c_uchar,
                                  inlen: c_ulonglong,
                                  k: *const c_uchar) -> c_int;
    pub fn crypto_auth_hmacsha256_verify(h: *const c_uchar,
                                         in_: *const c_uchar,
                                         inlen: c_ulonglong,
                                         k: *const c_uchar) -> c_int;
    pub fn crypto_auth_hmacsha256_init(state: *mut crypto_auth_hmacsha256_state,
                                       key: *const c_uchar,
                                       keylen: size_t) -> c_int;
    pub fn crypto_auth_hmacsha256_update(state: *mut crypto_auth_hmacsha256_state,
                                         in_: *const c_uchar,
                                         inlen: c_ulonglong) -> c_int;
    pub fn crypto_auth_hmacsha256_final(state: *mut crypto_auth_hmacsha256_state,
                                        out: *mut c_uchar) -> c_int;

    // sodium/crypto_auth_hmacsha512.h
    pub fn crypto_auth_hmacsha512_statebytes() -> size_t;
    pub fn crypto_auth_hmacsha512_bytes() -> size_t;
    pub fn crypto_auth_hmacsha512_keybytes() -> size_t;
    pub fn crypto_auth_hmacsha512(out: *mut c_uchar,
                                  in_: *const c_uchar,
                                  inlen: c_ulonglong,
                                  k: *const c_uchar) -> c_int;
    pub fn crypto_auth_hmacsha512_verify(h: *const c_uchar,
                                         in_: *const c_uchar,
                                         inlen: c_ulonglong,
                                         k: *const c_uchar) -> c_int;
    pub fn crypto_auth_hmacsha512_init(state: *mut crypto_auth_hmacsha512_state,
                                       key: *const c_uchar,
                                       keylen: size_t) -> c_int;
    pub fn crypto_auth_hmacsha512_update(state: *mut crypto_auth_hmacsha512_state,
                                         in_: *const c_uchar,
                                         inlen: c_ulonglong) -> c_int;
    pub fn crypto_auth_hmacsha512_final(state: *mut crypto_auth_hmacsha512_state,
                                        out: *mut c_uchar) -> c_int;

    // sodium/crypto_auth_hmacsha512256.h
    pub fn crypto_auth_hmacsha512256_statebytes() -> size_t;
    pub fn crypto_auth_hmacsha512256_bytes() -> size_t;
    pub fn crypto_auth_hmacsha512256_keybytes() -> size_t;
    pub fn crypto_auth_hmacsha512256(out: *mut c_uchar, in_: *const c_uchar,
                                     inlen: c_ulonglong, k: *const c_uchar) -> c_int;
    pub fn crypto_auth_hmacsha512256_verify(h: *const c_uchar,
                                            in_: *const c_uchar,
                                            inlen: c_ulonglong,
                                            k: *const c_uchar);
    pub fn crypto_auth_hmacsha512256_init(state: *mut crypto_auth_hmacsha512256_state,
                                          key: *const c_uchar,
                                          keylen: size_t) -> c_int;
    pub fn crypto_auth_hmacsha512256_update(state: *mut crypto_auth_hmacsha512256_state,
                                            in_: *const c_uchar,
                                            inlen: c_ulonglong) -> c_int;
    pub fn crypto_auth_hmacsha512256_final(state: *mut crypto_auth_hmacsha512256_state,
                                           out: *mut c_uchar) -> c_int;

    // sodium/crypto_box.h
    pub fn crypto_box_seedbytes() -> size_t;
    pub fn crypto_box_publickeybytes() -> size_t;
    pub fn crypto_box_secretkeybytes() -> size_t;
    pub fn crypto_box_noncebytes() -> size_t;
    pub fn crypto_box_macbytes() -> size_t;
    pub fn crypto_box_primitive() -> *const c_char;
    pub fn crypto_box_seed_keypair(pk: *mut c_uchar, sk: *mut c_uchar,
                                   seed: *const c_uchar) -> c_int;
    pub fn crypto_box_keypair(pk: *mut c_uchar, sk: *mut c_uchar) -> c_int;
    pub fn crypto_box_easy(c: *mut c_uchar, m: *const c_uchar,
                           mlen: c_ulonglong, n: *const c_uchar,
                           pk: *const c_uchar, sk: *const c_uchar) -> c_int;
    pub fn crypto_box_open_easy(m: *mut c_uchar, c: *const c_uchar,
                                clen: c_ulonglong, n: *const c_uchar,
                                pk: *const c_uchar, sk: *const c_uchar) -> c_int;
    pub fn crypto_box_detached(c: *mut c_uchar, mac: *mut c_uchar,
                               m: *const c_uchar, mlen: c_ulonglong,
                               n: *const c_uchar, pk: *const c_uchar,
                               sk: *const c_uchar) -> c_int;
    pub fn crypto_box_open_detached(m: *mut c_uchar, c: *const c_uchar,
                                    mac: *const c_uchar,
                                    clen: c_ulonglong,
                                    n: *const c_uchar,
                                    pk: *const c_uchar,
                                    sk: *const c_uchar) -> c_int;
    pub fn crypto_box_beforenmbytes() -> size_t;
    pub fn crypto_box_beforenm(k: *mut c_uchar, pk: *const c_uchar,
                               sk: *const c_uchar) -> c_int;
    pub fn crypto_box_easy_afternm(c: *mut c_uchar, m: *const c_uchar,
                                   mlen: c_ulonglong, n: *const c_uchar,
                                   k: *const c_uchar) -> c_int;
    pub fn crypto_box_open_easy_afternm(m: *mut c_uchar, c: *const c_uchar,
                                        clen: c_ulonglong, n: *const c_uchar,
                                        k: *const c_uchar) -> c_int;
    pub fn crypto_box_detached_afternm(c: *mut c_uchar, mac: *mut c_uchar,
                                       m: *const c_uchar, mlen: c_ulonglong,
                                       n: *const c_uchar, k: c_uchar) -> c_int;
    pub fn crypto_box_open_detached_afternm(m: *mut c_uchar, c: *const c_uchar,
                                            mac: *const c_uchar,
                                            clen: c_ulonglong, n: *const c_uchar,
                                            k: *const c_uchar) -> c_int;
    pub fn crypto_box_zerobytes() -> size_t;
    pub fn crypto_box_boxzerobytes() -> size_t;
    pub fn crypto_box(c: *mut c_uchar, m: *const c_uchar,
                      mlen: c_ulonglong, n: *const c_uchar,
                      pk: *const c_uchar, sk: *const c_uchar) -> c_int;
    pub fn crypto_box_open(m: *mut c_uchar, c: *const c_uchar,
                           clen: c_ulonglong, n: *const c_uchar,
                           pk: *const c_uchar, sk: *const c_uchar) -> c_int;
    pub fn crypto_box_afternm(c: *mut c_uchar, m: *const c_uchar,
                              mlen: c_ulonglong, n: *const c_uchar,
                              k: *const c_uchar) -> c_int;
    pub fn crypto_box_open_afternm(m: *mut c_uchar, c: *const c_uchar,
                                   clen: c_ulonglong, n: *const c_uchar,
                                   k: *const c_uchar) -> c_int;

    // sodium/crypto_box_curve25519xsalsa20poly1305.h
    pub fn crypto_box_curve25519xsalsa20poly1305_seedbytes() -> size_t;
    pub fn crypto_box_curve25519xsalsa20poly1305_publickeybytes() -> size_t;
    pub fn crypto_box_curve25519xsalsa20poly1305_secretkeybytes() -> size_t;
    pub fn crypto_box_curve25519xsalsa20poly1305_beforenmbytes() -> size_t;
    pub fn crypto_box_curve25519xsalsa20poly1305_noncebytes() -> size_t;
    pub fn crypto_box_curve25519xsalsa20poly1305_zerobytes() -> size_t;
    pub fn crypto_box_curve25519xsalsa20poly1305_boxzerobytes() -> size_t;
    pub fn crypto_box_curve25519xsalsa20poly1305_macbytes() -> size_t;
    pub fn crypto_box_curve25519xsalsa20poly1305(c: *mut c_uchar,
                                                 m: *const c_uchar,
                                                 mlen: c_ulonglong,
                                                 n: *const c_uchar,
                                                 pk: *const c_uchar,
                                                 sk: *const c_uchar) -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305_open(m: *mut c_uchar,
                                                      c: *const c_uchar,
                                                      clen: c_ulonglong,
                                                      n: *const c_uchar,
                                                      pk: *const c_uchar,
                                                      sk: *const c_uchar) -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305_seed_keypair(pk: *mut c_uchar,
                                                              sk: *mut c_uchar,
                                                              seed: *const c_uchar) -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305_keypair(pk: *mut c_uchar,
                                                         sk: *mut c_uchar) -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305_beforenm(k: *mut c_uchar,
                                                          pk: *const c_uchar,
                                                          sk: *const c_uchar) -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305_afternm(c: *mut c_uchar,
                                                         m: *const c_uchar,
                                                         mlen: c_ulonglong,
                                                         n: *const c_uchar,
                                                         k: *const c_uchar) -> c_int;
    pub fn crypto_box_curve25519xsalsa20poly1305_open_afternm(m: *mut c_uchar,
                                                              c: *const c_uchar,
                                                              clen: c_ulonglong,
                                                              n: *const c_uchar,
                                                              k: *const c_uchar) -> c_int;

    // sodium/crypto_core_hsalsa20.h
    pub fn crypto_core_hsalsa20_outputbytes() -> size_t;
    pub fn crypto_core_hsalsa20_inputbytes() -> size_t;
    pub fn crypto_core_hsalsa20_keybytes() -> size_t;
    pub fn crypto_core_hsalsa20_constbytes() -> size_t;
    pub fn crypto_core_hsalsa20(out: *mut c_uchar, in_: *const c_uchar,
                                k: *const c_uchar, c: *const c_uchar) -> c_int;

    // sodium/crypto_core_salsa20.h
    pub fn crypto_core_salsa20_outputbytes() -> size_t;
    pub fn crypto_core_salsa20_inputbytes() -> size_t;
    pub fn crypto_core_salsa20_keybytes() -> size_t;
    pub fn crypto_core_salsa20_constbytes() -> size_t;
    pub fn crypto_core_salsa20(out: *mut c_uchar, in_: *const c_uchar,
                               k: *const c_uchar, c: *const c_uchar) -> c_int;

    // sodium/crypto_core_salsa2012.h
    pub fn crypto_core_salsa2012_outputbytes() -> size_t;
    pub fn crypto_core_salsa2012_inputbytes() -> size_t;
    pub fn crypto_core_salsa2012_keybytes() -> size_t;
    pub fn crypto_core_salsa2012_constbytes() -> size_t;
    pub fn crypto_core_salsa2012(out: *mut c_uchar, in_: *const c_uchar,
                                 k: *const c_uchar, c: *const c_uchar) -> c_int;

    // sodium/crypto_core_salsa208.h
    pub fn crypto_core_salsa208_outputbytes() -> size_t;
    pub fn crypto_core_salsa208_inputbytes() -> size_t;
    pub fn crypto_core_salsa208_keybytes() -> size_t;
    pub fn crypto_core_salsa208_constbytes() -> size_t;
    pub fn crypto_core_salsa208(out: *mut c_uchar, in_: *const c_uchar,
                                k: *const c_uchar, c: *const c_uchar) -> c_int;

    // sodium/crypto_generichash.h
    pub fn crypto_generichash_bytes_min() -> size_t;
    pub fn crypto_generichash_bytes_max() -> size_t;
    pub fn crypto_generichash_bytes() -> size_t;
    pub fn crypto_generichash_keybytes_min() -> size_t;
    pub fn crypto_generichash_keybytes() -> size_t;
    pub fn crypto_generichash_primitive() -> *const c_char;
    pub fn crypto_generichash_statebytes() -> size_t;
    pub fn crypto_generichash(out: *mut c_uchar, outlen: size_t,
                              in_: *const c_uchar, inlen: c_ulonglong,
                              key: *const c_uchar, keylen: size_t) -> c_int;
    pub fn crypto_generichash_init(state: *mut crypto_generichash_state,
                                   key: *const c_uchar,
                                   keylen: size_t, outlen: size_t) -> c_int;
    pub fn crypto_generichash_update(state: *mut crypto_generichash_state,
                                     in_: *const c_uchar,
                                     inlen: c_ulonglong) -> c_int;
    pub fn crypto_generichash_final(state: *mut crypto_generichash_state,
                                    out: *mut c_uchar, outlen: size_t) -> c_int;

    // sodium/crypto_generichash_blake2b.h
    pub fn crypto_generichash_blake2b_bytes_min() -> size_t;
    pub fn crypto_generichash_blake2b_bytes_max() -> size_t;
    pub fn crypto_generichash_blake2b_bytes() -> size_t;
    pub fn crypto_generichash_blake2b_keybytes_min() -> size_t;
    pub fn crypto_generichash_blake2b_keybytes_max() -> size_t;
    pub fn crypto_generichash_blake2b_keybytes() -> size_t;
    pub fn crypto_generichash_blake2b_saltbytes() -> size_t;
    pub fn crypto_generichash_blake2b_personalbytes() -> size_t;
    pub fn crypto_generichash_blake2b(out: *mut c_uchar, outlen: size_t,
                                      in_: *const c_uchar, inlen: c_ulonglong,
                                      key: *const c_uchar, keylen: size_t) -> c_int;
    pub fn crypto_generichash_blake2b_salt_personal(out: *mut c_uchar, outlen: size_t,
                                                    in_: *const c_uchar,
                                                    inlen: c_ulonglong,
                                                    key: *const c_uchar,
                                                    keylen: size_t,
                                                    salt: *const c_uchar,
                                                    personal: *const c_uchar) -> c_int;
    pub fn crypto_generichash_blake2b_update(state: *mut crypto_generichash_blake2b_state,
                                             in_: *const c_uchar,
                                             inlen: c_ulonglong) -> c_int;
    pub fn crypto_generichash_blake2b_final(state: *mut crypto_generichash_blake2b_state,
                                            out: *mut c_uchar,
                                            outlen: size_t) -> c_int;

    // sodium/crypto_hash.h
    pub fn crypto_hash_bytes() -> size_t;
    pub fn crypto_hash(out: *mut c_uchar, in_: *const c_uchar,
                       inlen: c_ulonglong) -> c_int;
    pub fn crypto_hash_primitive() -> *const c_char;

    // sodium/crypto_hash_sha256.h
    pub fn crypto_hash_sha256_statebytes() -> size_t;
    pub fn crypto_hash_sha256_bytes() -> size_t;
    pub fn crypto_hash_sha256(out: *mut c_uchar, in_: *const c_uchar,
                              inlen: c_ulonglong) -> c_int;
    pub fn crypto_hash_sha256_init(state: *mut crypto_hash_sha256_state) -> c_int;
    pub fn crypto_hash_sha256_update(state: *mut crypto_hash_sha256_state,
                                     in_: *const c_uchar,
                                     inlen: c_ulonglong) -> c_int;
    pub fn crypto_hash_sha256_final(state: *mut crypto_hash_sha256_state,
                                    out: *mut c_uchar) -> c_int;

    // sodium/crypto_hash_sha512.h
    pub fn crypto_hash_sha512_statebytes() -> size_t;
    pub fn crypto_hash_sha512_bytes() -> size_t;
    pub fn crypto_hash_sha512(out: *mut c_uchar, in_: *const c_uchar,
                              inlen: c_ulonglong) -> c_int;
    pub fn crypto_hash_sha512_init(state: *mut crypto_hash_sha512_state) -> c_int;
    pub fn crypto_hash_sha512_update(state: *mut crypto_hash_sha512_state,
                                     in_: *const c_uchar,
                                     inlen: c_ulonglong) -> c_int;
    pub fn crypto_hash_sha512_final(state: *mut crypto_hash_sha256_state,
                                    out: *mut c_uchar) -> c_int;

    // sodium/crypto_onetimeauth.h
    pub fn crypto_onetimeauth_statebytes() -> size_t;
    pub fn crypto_onetimeauth_bytes() -> size_t;
    pub fn crypto_onetimeauth_keybytes() -> size_t;
    pub fn crypto_onetimeauth_primitive() -> *const c_char;
    pub fn crypto_onetimeauth(out: *mut c_uchar, in_: *const c_uchar,
                              inlen: c_ulonglong, k: *const c_uchar) -> c_int;
    pub fn crypto_onetimeauth_verify(h: *const c_uchar, in_: *const c_uchar,
                                     inlen: c_ulonglong, k: *const c_uchar) -> c_int;
    pub fn crypto_onetimeauth_init(state: *mut crypto_onetimeauth_state,
                                   key: *const c_uchar) -> c_int;
    pub fn crypto_onetimeauth_update(state: *mut crypto_onetimeauth_state,
                                     in_: *const c_uchar,
                                     inlen: c_ulonglong) -> c_int;
    pub fn crypto_onetimeauth_final(state: *mut crypto_onetimeauth_state,
                                    out: *mut c_uchar) -> c_int;

    // sodium/crypto_onetimeauth_poly1305.h
    pub fn crypto_onetimeauth_poly1305_bytes() -> size_t;
    pub fn crypto_onetimeauth_poly1305_keybytes() -> size_t;
    pub fn crypto_onetimeauth_poly1305_implementation_name() -> *const c_char;
    pub fn crypto_onetimeauth_poly1305_set_implementation(impl_: *mut crypto_onetimeauth_poly1305_implementation)
        -> c_int;
    pub fn crypto_onetimeauth_pick_best_implementation() -> *mut crypto_onetimeauth_poly1305_implementation;
    pub fn crypto_onetimeauth_poly1305(out: *mut c_uchar,
                                       in_: *const c_uchar,
                                       inlen: c_ulonglong,
                                       k: *const c_uchar) -> c_int;
    pub fn crypto_onetimeauth_poly1305_verify(h: *const c_uchar,
                                              in_: *const c_uchar,
                                              inlen: c_ulonglong,
                                              k: *const c_uchar) -> c_int;
    pub fn crypto_onetimeauth_poly1305_init(state: *mut crypto_onetimeauth_poly1305_state,
                                            key: *const c_uchar) -> c_int;
    pub fn crypto_onetimeauth_poly1305_update(state: *mut crypto_onetimeauth_poly1305_state,
                                              in_: *const c_uchar,
                                              inlen: c_ulonglong) -> c_int;
    pub fn crypto_onetimeauth_poly1305_final(state: *mut crypto_onetimeauth_poly1305_state,
                                             out: *mut c_uchar) -> c_int;

    // sodium/crypto_pwhash_scryptsalsa208sha256.h
    pub fn crypto_pwhash_scryptsalsa208sha256_saltbytes() -> size_t;
    pub fn crypto_pwhash_scryptsalsa208sha256_strbytes() -> size_t;
    pub fn crypto_pwhash_scryptsalsa208sha256_strprefix() -> *const c_char;
    pub fn crypto_pwhash_scryptsalsa208sha256_opslimit_interactive() -> size_t;
    pub fn crypto_pwhash_scryptsalsa208sha256_memlimit_interactive() -> size_t;
    pub fn crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive() -> size_t;
    pub fn crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive() -> size_t;
    pub fn crypto_pwhash_scryptsalsa208sha256(out: *mut c_char,
                                              outlen: c_ulonglong,
                                              passwd: *const c_char,
                                              passwdlen: c_ulonglong,
                                              salt: *const c_uchar,
                                              opslimit: c_ulonglong,
                                              memlimit: size_t) -> c_int;
    pub fn crypto_pwhash_scryptsalsa208sha256_str(out: *mut c_char,
                                                  passwd: *const c_char,
                                                  passwdlen: c_ulonglong,
                                                  opslimit: c_ulonglong,
                                                  memlimit: size_t) -> c_int;
    pub fn crypto_pwhash_scryptsalsa208sha256_str_verify(str_: *const c_char,
                                                         passwd: *const c_char,
                                                         passwdlen: c_ulonglong) -> c_int;
    pub fn crypto_pwhash_scryptsalsa208sha256_ll(passwd: *const uint8_t, passwdlen: size_t,
                                                 salt: *const uint8_t, saltlen: size_t,
                                                 N: uint64_t, r: uint32_t, p: uint32_t,
                                                 buf: *mut uint8_t, buflen: size_t) -> c_int;

    // sodium/crypto_scalarmult.h
    pub fn crypto_scalarmult_bytes() -> size_t;
    pub fn crypto_scalarmult_scalarbytes() -> size_t;
    pub fn crypto_scalarmult_primitive() -> *const c_char;
    pub fn crypto_scalarmult_base(q: *mut c_uchar, n: *const c_uchar) -> c_int;
    pub fn crypto_scalarmult(q: *mut c_uchar, n: *const c_uchar,
                             p: *const c_uchar) -> c_int;

    // sodium/crypto_scalarmult_curve25519.h
    pub fn crypto_scalarmult_curve25519_bytes() -> size_t;
    pub fn crypto_scalarmult_curve25519_scalarbytes() -> size_t;
    pub fn crypto_scalarmult_curve25519_primitive() -> *const c_char;
    pub fn crypto_scalarmult_curve25519_base(q: *mut c_uchar, n: *const c_uchar) -> c_int;
    pub fn crypto_scalarmult_curve25519(q: *mut c_uchar, n: *const c_uchar,
                                        p: *const c_uchar) -> c_int;

    // sodium/crypto_secretbox_xsalsa20poly1305.h
    pub fn crypto_secretbox_xsalsa20poly1305_keybytes() -> size_t;
    pub fn crypto_secretbox_xsalsa20poly1305_noncebytes() -> size_t;
    pub fn crypto_secretbox_xsalsa20poly1305_zerobytes() -> size_t;
    pub fn crypto_secretbox_xsalsa20poly1305_boxzerobytes() -> size_t;
    pub fn crypto_secretbox_xsalsa20poly1305_macbytes() -> size_t;
    pub fn crypto_secretbox_xsalsa20poly1305(c: *mut c_uchar,
                                             m: *const c_uchar,
                                             mlen: c_ulonglong,
                                             n: *const c_uchar,
                                             k: *const c_uchar) -> c_int;
    pub fn crypto_secretbox_xsalsa20poly1305_open(m: *mut c_uchar,
                                                  c: *const c_uchar,
                                                  clen: c_ulonglong,
                                                  n: *const c_uchar,
                                                  k: *const c_uchar) -> c_int;

    // sodium/crypto_secretbox.h
    pub fn crypto_secretbox_keybytes() -> size_t;
    pub fn crypto_secretbox_noncebytes() -> size_t;
    pub fn crypto_secretbox_zerobytes() -> size_t;
    pub fn crypto_secretbox_boxzerobytes() -> size_t;
    pub fn crypto_secretbox_macbytes() -> size_t;
    pub fn crypto_secretbox_primitive() -> *const c_char;
    pub fn crypto_secretbox_easy(c: *mut c_uchar, m: *const c_uchar,
                                 mlen: c_ulonglong, n: *const c_uchar,
                                 k: *const c_uchar) -> c_int;
    pub fn crypto_secretbox_open_easy(m: *mut c_uchar, c: *const c_uchar,
                                      clen: c_ulonglong, n: *const c_uchar,
                                      k: *const c_uchar) -> c_int;
    pub fn crypto_secretbox_detached(c: *mut c_uchar, mac: *mut c_uchar,
                                     m: *const c_uchar,
                                     mlen: c_ulonglong,
                                     n: *const c_uchar,
                                     k: *const c_uchar) -> c_int;
    pub fn crypto_secretbox_open_detached(m: *mut c_uchar,
                                          c: *const c_uchar,
                                          mac: *const c_uchar,
                                          clen: c_ulonglong,
                                          n: *const c_uchar,
                                          k: *const c_uchar) -> c_int;
    pub fn crypto_secretbox(c: *mut c_uchar,
                            m: *const c_uchar,
                            mlen: c_ulonglong,
                            n: *const c_uchar,
                            k: *const c_uchar) -> c_int;
    pub fn crypto_secretbox_open(m: *mut c_uchar,
                                 c: *const c_uchar,
                                 clen: c_ulonglong,
                                 n: *const c_uchar,
                                 k: *const c_uchar) -> c_int;

    // sodium/crypto_shorthash.h
    pub fn crypto_shorthash_bytes() -> size_t;
    pub fn crypto_shorthash_keybytes() -> size_t;
    pub fn crypto_shorthash_primitive() -> *const c_char;
    pub fn crypto_shorthash(out: *mut c_uchar, in_: *const c_uchar,
                            inlen: c_ulonglong, k: *const c_uchar) -> c_int;

    // sodium/crypto_shorthash_siphash24.h
    pub fn crypto_shorthash_siphash24_bytes() -> size_t;
    pub fn crypto_shorthash_siphash24_keybytes() -> size_t;
    pub fn crypto_shorthash_siphash24(out: *mut c_uchar, in_: *const c_uchar,
                                      inlen: c_ulonglong, k: *const c_uchar) -> c_int;

    // sodium/crypto_sign.h
    pub fn crypto_sign_bytes() -> size_t;
    pub fn crypto_sign_seedbytes() -> size_t;
    pub fn crypto_sign_publickeybytes() -> size_t;
    pub fn crypto_sign_secretkeybytes() -> size_t;
    pub fn crypto_sign_primitive() -> *const c_char;
    pub fn crypto_sign_seed_keypair(pk: *mut c_uchar, sk: *mut c_uchar,
                                    seed: *const c_uchar) -> c_int;
    pub fn crypto_sign_keypair(pk: *mut c_uchar, sk: *mut c_uchar) -> c_int;
    pub fn crypto_sign(sm: *mut c_uchar, smlen_p: *mut c_ulonglong,
                       m: *const c_uchar, mlen: c_ulonglong,
                       sk: *const c_uchar) -> c_int;
    pub fn crypto_sign_open(m: *mut c_uchar, mlen_p: *mut c_ulonglong,
                            sm: *const c_uchar, smlen: c_ulonglong,
                            pk: *const c_uchar) -> c_int;
    pub fn crypto_sign_detached(sig: *mut c_uchar, siglen_p: *mut c_ulonglong,
                                m: *const c_uchar, mlen: c_ulonglong,
                                sk: *const c_uchar) -> c_int;
    pub fn crypto_sign_verify_detached(sig: *const c_uchar,
                                       m: *const c_uchar,
                                       mlen: c_ulonglong,
                                       pk: *const c_uchar) -> c_int;

    // sodium/crypto_sign_ed25519.h
    pub fn crypto_sign_ed25519_bytes() -> size_t;
    pub fn crypto_sign_ed25519_seedbytes() -> size_t;
    pub fn crypto_sign_ed25519_publickeybytes() -> size_t;
    pub fn crypto_sign_ed25519_secretkeybytes() -> size_t;
    pub fn crypto_sign_ed25519_seed_keypair(pk: *mut c_uchar, sk: *mut c_uchar,
                                    seed: *const c_uchar) -> c_int;
    pub fn crypto_sign_ed25519_keypair(pk: *mut c_uchar, sk: *mut c_uchar) -> c_int;
    pub fn crypto_sign_ed25519(sm: *mut c_uchar, smlen_p: *mut c_ulonglong,
                       m: *const c_uchar, mlen: c_ulonglong,
                       sk: *const c_uchar) -> c_int;
    pub fn crypto_sign_ed25519_open(m: *mut c_uchar, mlen_p: *mut c_ulonglong,
                            sm: *const c_uchar, smlen: c_ulonglong,
                            pk: *const c_uchar) -> c_int;
    pub fn crypto_sign_ed25519_detached(sig: *mut c_uchar, siglen_p: *mut c_ulonglong,
                                m: *const c_uchar, mlen: c_ulonglong,
                                sk: *const c_uchar) -> c_int;
    pub fn crypto_sign_ed25519_verify_detached(sig: *const c_uchar,
                                       m: *const c_uchar,
                                       mlen: c_ulonglong,
                                       pk: *const c_uchar) -> c_int;
    pub fn crypto_sign_ed25519_pk_to_curve25519(curve25519_pk: *mut c_uchar,
                                                ed25519_pk: *const c_uchar) -> c_int;
    pub fn crypto_sign_ed25519_sk_to_curve25519(curve25519_sk: *mut c_uchar,
                                                ed25519_sk: *const c_uchar) -> c_int;
    pub fn crypto_sign_ed25519_sk_to_seed(seed: *mut c_uchar,
                                          sk: *const c_uchar) -> c_int;
    pub fn crypto_sign_ed25519_sk_to_pk(pk: *mut c_uchar, sk: *const c_uchar) -> c_int;

    // sodium/crypto_sign_edwards25519sha512batch.h
    pub fn crypto_sign_edwards25519sha512batch_bytes() -> size_t;
    pub fn crypto_sign_edwards25519sha512batch_publickeybytes() -> size_t;
    pub fn crypto_sign_edwards25519sha512batch_secretkeybytes() -> size_t;
    pub fn crypto_sign_edwards25519sha512batch(sm: *mut c_uchar,
                                               smlen_p: *mut c_ulonglong,
                                               m: *const c_uchar,
                                               mlen: c_ulonglong,
                                               sk: *const c_uchar) -> c_int;
    pub fn crypto_sign_edwards25519sha512batch_open(m: *mut c_uchar,
                                                    mlen_p: *mut c_ulonglong,
                                                    sm: *const c_uchar,
                                                    smlen: c_ulonglong,
                                                    pk: *const c_uchar) -> c_int;
    pub fn crypto_sign_edwards25519sha512batch_keypair(pk: *mut c_uchar,
                                                       sk: *mut c_uchar) -> c_int;

    // sodium/crypto_stream.h
    pub fn crypto_stream_keybytes() -> size_t;
    pub fn crypto_stream_noncebytes() -> size_t;
    pub fn crypto_stream_primitive() -> *const c_char;
    pub fn crypto_stream(c: *mut c_char, clen: c_ulonglong,
                         n: *const c_uchar, k: *const c_uchar) -> c_int;
    pub fn crypto_stream_xor(c: *mut c_char, m: *const c_uchar,
                             mlen: c_ulonglong, n: *const c_uchar,
                             k: *const c_uchar) -> c_int;

    // sodium/crypto_stream_aes128ctr.h
    pub fn crypto_stream_aes128ctr_keybytes() -> size_t;
    pub fn crypto_stream_aes128ctr_noncebytes() -> size_t;
    pub fn crypto_stream_aes128ctr_beforenmbytes() -> size_t;
    pub fn crypto_stream_aes128ctr(out: *mut c_uchar, outlen: c_ulonglong,
                                   n: *const c_uchar, k: *const c_uchar) -> c_int;
    pub fn crypto_stream_aes128ctr_xor(out: *mut c_uchar, in_: *const c_uchar,
                                       inlen: c_ulonglong, n: *const c_uchar,
                                       k: *const c_uchar) -> c_int;
    pub fn crypto_stream_aes128ctr_beforenm(c: *mut c_uchar, k: *const c_uchar) -> c_int;
    pub fn crypto_stream_aes128ctr_afternm(out: *mut c_uchar, len: c_ulonglong,
                                           nounce: *const c_uchar, c: *const c_uchar) -> c_int;
    pub fn crypto_stream_aes128ctr_xor_afternm(out: *mut c_uchar, in_: *const c_uchar,
                                               len: c_ulonglong, nounce: *const c_uchar,
                                               c: *const c_uchar) -> c_int;

    // sodium/crypto_stream_chacha20.h
    pub fn crypto_stream_chacha20_keybytes() -> size_t;
    pub fn crypto_stream_chacha20_noncebytes() -> size_t;
    pub fn crypto_stream_chacha20(c: *mut c_char, clen: c_ulonglong,
                                  n: *const c_uchar, k: *const c_uchar) -> c_int;
    pub fn crypto_stream_chacha20_xor(c: *mut c_uchar, m: *const c_uchar,
                                      mlen: c_ulonglong, n: *const c_uchar,
                                      k: *const c_uchar) -> c_int;
    pub fn crypto_stream_chacha20_xor_ic(c: *mut c_char, m: *const c_uchar,
                                         mlen: c_ulonglong,
                                         n: *const c_uchar, ic: uint64_t,
                                         k: *const c_uchar) -> c_int;

    // sodium/crypto_stream_salsa20.h
    pub fn crypto_stream_salsa20_keybytes() -> size_t;
    pub fn crypto_stream_salsa20_noncebytes() -> size_t;
    pub fn crypto_stream_salsa20(c: *mut c_char, clen: c_ulonglong,
                                 n: *const c_uchar, k: *const c_uchar) -> c_int;
    pub fn crypto_stream_salsa20_xor(c: *mut c_uchar, m: *const c_uchar,
                                     mlen: c_ulonglong, n: *const c_uchar,
                                     k: *const c_uchar) -> c_int;
    pub fn crypto_stream_salsa20_xor_ic(c: *mut c_char, m: *const c_uchar,
                                        mlen: c_ulonglong,
                                        n: *const c_uchar, ic: uint64_t,
                                        k: *const c_uchar) -> c_int;

    // sodium/crypto_stream_salsa2012.h
    pub fn crypto_stream_salsa2012_keybytes() -> size_t;
    pub fn crypto_stream_salsa2012_noncebytes() -> size_t;
    pub fn crypto_stream_salsa2012(c: *mut c_char, clen: c_ulonglong,
                                   n: *const c_uchar, k: *const c_uchar) -> c_int;
    pub fn crypto_stream_salsa2012_xor(c: *mut c_uchar, m: *const c_uchar,
                                       mlen: c_ulonglong, n: *const c_uchar,
                                       k: *const c_uchar) -> c_int;

    // sodium/crypto_stream_salsa208.h
    pub fn crypto_stream_salsa208_keybytes() -> size_t;
    pub fn crypto_stream_salsa208_noncebytes() -> size_t;
    pub fn crypto_stream_salsa208(c: *mut c_char, clen: c_ulonglong,
                                  n: *const c_uchar, k: *const c_uchar) -> c_int;
    pub fn crypto_stream_salsa208_xor(c: *mut c_uchar, m: *const c_uchar,
                                      mlen: c_ulonglong, n: *const c_uchar,
                                      k: *const c_uchar) -> c_int;

    // sodium/crypto_stream_xsalsa20.h
    pub fn crypto_stream_xsalsa20_keybytes() -> size_t;
    pub fn crypto_stream_xsalsa20_noncebytes() -> size_t;
    pub fn crypto_stream_xsalsa20(c: *mut c_char, clen: c_ulonglong,
                                  n: *const c_uchar, k: *const c_uchar) -> c_int;
    pub fn crypto_stream_xsalsa20_xor(c: *mut c_uchar, m: *const c_uchar,
                                      mlen: c_ulonglong, n: *const c_uchar,
                                      k: *const c_uchar) -> c_int;

    // sodium/crypto_verify_16.h
    pub fn crypto_verify_16_bytes() -> size_t;
    pub fn crypto_verify_16(x: *const c_uchar, y: *const c_uchar) -> c_int;

    // sodium/crypto_verify_32.h
    pub fn crypto_verify_32_bytes() -> size_t;
    pub fn crypto_verify_32(x: *const c_uchar, y: *const c_uchar) -> c_int;

    // sodium/crypto_verify_64.h
    pub fn crypto_verify_64_bytes() -> size_t;
    pub fn crypto_verify_64(x: *const c_uchar, y: *const c_uchar) -> c_int;

    // sodium/randombytes.h
    pub fn randombytes_buf(buf: *mut c_void, size: size_t);
    pub fn randombytes_random() -> uint32_t;
    pub fn randombytes_uniform(upper_bound: uint32_t) -> uint32_t;
    pub fn randombytes_stir();
    pub fn randombytes_close() -> c_int;
    pub fn randombytes_set_implementation(impl_: *mut randombytes_implementation) -> c_int;
    pub fn randombytes_implementation_name() -> *const c_char;
    pub fn randombytes(buf: *mut c_void, buf_len: c_ulonglong);

    // sodium/randombytes_salsa20_random.h
    pub fn randombytes_salsa20_implementation_name() -> *const c_char;
    pub fn randombytes_salsa20_random() -> uint32_t;
    pub fn randombytes_salsa20_random_stir();
    pub fn randombytes_salsa20_random_uniform(upper_bound: uint32_t) -> uint32_t;
    pub fn randombytes_salsa20_random_buf(buf: *mut c_void, size: size_t);
    pub fn randombytes_salsa20_random_close() -> c_int;
    pub static randombytes_salsa20_implementation: randombytes_implementation;

    // sodium/randombytes_sysrandom.h
    pub fn randombytes_sysrandom_implementation_name() -> *const c_char;
    pub fn randombytes_sysrandom() -> uint32_t;
    pub fn randombytes_sysrandom_stir();
    pub fn randombytes_sysrandom_uniform(upper_bound: uint32_t) -> uint32_t;
    pub fn randombytes_sysrandom_buf(buf: *mut c_void, size: size_t);
    pub fn randombytes_sysrandom_close() -> c_int;
    pub static randombytes_sysrandom_implementation: randombytes_implementation;

    // sodium/version.h
    pub fn sodium_version_string() -> *const c_char;
    pub fn sodium_library_version_major() -> c_int;
    pub fn sodium_library_version_minor() -> c_int;
}

// sodium/crypto_hash_sha256.h
#[repr(C)]
#[derive(Copy)]
pub struct crypto_hash_sha256_state {
    pub state: [uint32_t; 8],
    pub count: [uint32_t; 2],
    pub buf: [c_uchar; 64],
}

// sodium/crypto_auth_hmacsha256.h
#[repr(C)]
#[derive(Copy)]
pub struct crypto_auth_hmacsha256_state {
    pub ictx: crypto_hash_sha256_state,
    pub octx: crypto_hash_sha256_state,
}

// sodium/crypto_hash_sha512.h
#[repr(C)]
#[derive(Copy)]
pub struct crypto_hash_sha512_state {
    pub state: [uint64_t; 8],
    pub count: [uint64_t; 2],
    pub buf: [c_uchar; 128],
}

// sodium/crypto_auth_hmacsha512.h
#[repr(C)]
#[derive(Copy)]
pub struct crypto_auth_hmacsha512_state {
    pub ictx: crypto_hash_sha512_state,
    pub octx: crypto_hash_sha512_state,
}

// sodium/crypto_auth_hmacsha512256.h
pub type crypto_auth_hmacsha512256_state = crypto_auth_hmacsha512_state;

// sodium/crypto_generichash_blake2b.h
#[repr(C)]
#[packed]
#[derive(Copy)]
pub struct crypto_generichash_blake2b_state {
    pub h: [uint64_t; 8],
    pub t: [uint64_t; 2],
    pub f: [uint64_t; 2],
    pub buf: [uint8_t; 2 * 128],
    pub buflen: size_t,
    pub last_node: uint8_t,
}

// sodium/crypto_generichash.h
pub type crypto_generichash_state = crypto_generichash_blake2b_state;

// sodium/crypto_int32.h
pub type crypto_int32 = int32_t;

// sodium/crypto_int64.h
pub type crypto_int64 = int64_t;

// sodium/crypto_uint16.h
pub type crypto_uint16 = uint16_t;

// sodium/crypto_uint32.h
pub type crypto_uint32 = uint32_t;

// sodium/crypto_uint64.h
pub type crypto_uint64 = uint64_t;

// sodium/crypto_uint8.h
pub type crypto_uint8 = uint8_t;

// sodium/crypto_onetimeauth_poly1305.h
#[repr(C)]
#[derive(Copy)]
pub struct crypto_onetimeauth_poly1305_state {
    pub aligner: c_ulonglong,
    pub opaque: [c_uchar; 136],
}

// sodium/crypto_onetimeauth.h
pub type crypto_onetimeauth_state = crypto_onetimeauth_poly1305_state;

// sodium/crypto_onetimeauth_poly1305.h
#[repr(C)]
#[derive(Copy)]
#[allow(raw_pointer_derive)]
pub struct crypto_onetimeauth_poly1305_implementation {
    pub implementation_name: extern fn() -> *const c_char,
    pub onetimeauth: extern fn(out: *mut c_uchar,
                               in_: *const c_uchar,
                               inlen: c_ulonglong,
                               k: *const c_uchar) -> c_int,
    pub onetimeauth_verify: extern fn(h: *const c_uchar,
                                      in_: *const c_uchar,
                                      inlen: c_ulonglong,
                                      k: *const c_uchar) -> c_int,
    pub onetimeauth_init: extern fn(state: *mut crypto_onetimeauth_poly1305_state,
                                    key: *const c_uchar) -> c_int,
    pub onetimeauth_update: extern fn(state: *mut crypto_onetimeauth_poly1305_state,
                                      in_: *const c_uchar,
                                      inlen: c_ulonglong) -> c_int,
    pub onetimeauth_final: extern fn(state: *mut crypto_onetimeauth_poly1305_state,
                                     out: *mut c_uchar) -> c_int,
}

// sodium/randombytes.h
#[repr(C)]
#[derive(Copy)]
#[allow(raw_pointer_derive)]
pub struct randombytes_implementation {
    pub implementation_name: extern fn() -> *const c_char,
    pub random: extern fn() -> uint32_t,
    pub stir: extern fn(),
    pub uniform: extern fn(upper_bound: uint32_t) -> uint32_t,
    pub buf: extern fn(buf: *mut c_void, size: size_t),
    pub close: extern fn() -> c_int,
}

#[test]
fn test_it_work() {
    unsafe {
        sodium_init();
    }
}
