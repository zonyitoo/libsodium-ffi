#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use std::mem;
use std::ptr;

use std::os::raw::{c_uchar, c_int, c_ulonglong, c_char, c_void};

pub const crypto_aead_chacha20poly1305_KEYBYTES: usize = 32;
pub const crypto_aead_chacha20poly1305_NSECBYTES: usize = 0;
pub const crypto_aead_chacha20poly1305_NPUBBYTES: usize = 8;
pub const crypto_aead_chacha20poly1305_ABYTES: usize = 16;

// sodium/crypto_auth_hmacsha256.h
pub const crypto_auth_hmacsha256_BYTES: usize = 32;
pub const crypto_auth_hmacsha256_KEYBYTES: usize = 32;

// sodium/crypto_auth.h
pub const crypto_auth_BYTES: usize = crypto_auth_hmacsha512256_BYTES;
pub const crypto_auth_KEYBYTES: usize = crypto_auth_hmacsha512256_KEYBYTES;
pub const crypto_auth_PRIMITIVE: &'static str = "hmacsha512256";

// sodium/crypto_auth_hmacsha512.h
pub const crypto_auth_hmacsha512_BYTES: usize = 64;
pub const crypto_auth_hmacsha512_KEYBYTES: usize = 32;

// sodium/crypto_auth_hmacsha512256.h
pub const crypto_auth_hmacsha512256_BYTES: usize = 32;
pub const crypto_auth_hmacsha512256_KEYBYTES: usize = 32;

// sodium/crypto_box.h
pub const crypto_box_SEEDBYTES: usize = crypto_box_curve25519xsalsa20poly1305_SEEDBYTES;
pub const crypto_box_PUBLICKEYBYTES: usize = crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES;
pub const crypto_box_SECRETKEYBYTES: usize = crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES;
pub const crypto_box_NONCEBYTES: usize = crypto_box_curve25519xsalsa20poly1305_NONCEBYTES;
pub const crypto_box_MACBYTES: usize = crypto_box_curve25519xsalsa20poly1305_MACBYTES;
pub const crypto_box_PRIMITIVE: &'static str = "curve25519xsalsa20poly1305";
pub const crypto_box_SEALBYTES: usize = crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES;

// sodium/crypto_box_curve25519xsalsa20poly1305.h
pub const crypto_box_curve25519xsalsa20poly1305_SEEDBYTES: usize = 32;
pub const crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES: usize = 32;
pub const crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES: usize = 32;
pub const crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES: usize = 32;
pub const crypto_box_curve25519xsalsa20poly1305_NONCEBYTES: usize = 24;
pub const crypto_box_curve25519xsalsa20poly1305_ZEROBYTES: usize = 32;
pub const crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES: usize = 16;
pub const crypto_box_curve25519xsalsa20poly1305_MACBYTES: usize = crypto_box_curve25519xsalsa20poly1305_ZEROBYTES
                                                            - crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES;


// sodium/crypto_core_hsalsa20.h
pub const crypto_core_hsalsa20_OUTPUTBYTES: usize = 32;
pub const crypto_core_hsalsa20_INPUTBYTES: usize = 16;
pub const crypto_core_hsalsa20_KEYBYTES: usize = 32;
pub const crypto_core_hsalsa20_CONSTBYTES: usize = 16;

// sodium/crypto_core_salsa20.h
pub const crypto_core_salsa20_OUTPUTBYTES: usize = 64;
pub const crypto_core_salsa20_INPUTBYTES: usize = 16;
pub const crypto_core_salsa20_KEYBYTES: usize = 32;
pub const crypto_core_salsa20_CONSTBYTES: usize = 16;

// sodium/crypto_core_salsa2012.h
pub const crypto_core_salsa2012_OUTPUTBYTES: usize = 64;
pub const crypto_core_salsa2012_INPUTBYTES: usize = 16;
pub const crypto_core_salsa2012_KEYBYTES: usize = 32;
pub const crypto_core_salsa2012_CONSTBYTES: usize = 16;

// sodium/crypto_core_salsa208.h
pub const crypto_core_salsa208_OUTPUTBYTES: usize = 64;
pub const crypto_core_salsa208_INPUTBYTES: usize = 16;
pub const crypto_core_salsa208_KEYBYTES: usize = 32;
pub const crypto_core_salsa208_CONSTBYTES: usize = 16;

// sodium/crypto_generichash.h
pub const crypto_generichash_BYTES_MIN: usize = crypto_generichash_blake2b_BYTES_MIN;
pub const crypto_generichash_BYTES_MAX: usize = crypto_generichash_blake2b_BYTES_MAX;
pub const crypto_generichash_BYTES: usize = crypto_generichash_blake2b_BYTES;
pub const crypto_generichash_KEYBYTES_MIN: usize = crypto_generichash_blake2b_KEYBYTES_MIN;
pub const crypto_generichash_KEYBYTES_MAX: usize = crypto_generichash_blake2b_KEYBYTES_MAX;
pub const crypto_generichash_KEYBYTES: usize = crypto_generichash_blake2b_KEYBYTES;
pub const crypto_generichash_PRIMITIVE: &'static str = "blake2b";

// sodium/crypto_generichash_blake2b.h
pub const crypto_generichash_blake2b_BYTES_MIN: usize = 16;
pub const crypto_generichash_blake2b_BYTES_MAX: usize = 64;
pub const crypto_generichash_blake2b_BYTES: usize = 32;
pub const crypto_generichash_blake2b_KEYBYTES_MIN: usize = 16;
pub const crypto_generichash_blake2b_KEYBYTES_MAX: usize = 64;
pub const crypto_generichash_blake2b_KEYBYTES: usize = 32;
pub const crypto_generichash_blake2b_SALTBYTES: usize = 16;
pub const crypto_generichash_blake2b_PERSONALBYTES: usize = 16;

// sodium/crypto_hash_sha512.h
pub const crypto_hash_sha512_BYTES: usize = 64;

// sodium/crypto_hash_sha256.h
pub const crypto_hash_sha256_BYTES: usize = 32;

// sodium/crypto_hash.h
pub const crypto_hash_BYTES: usize = crypto_hash_sha512_BYTES;
pub const crypto_hash_PRIMITIVE: &'static str = "sha512";

// sodium/crypto_onetimeauth.h
pub const crypto_onetimeauth_BYTES: usize = crypto_onetimeauth_poly1305_BYTES;
pub const crypto_onetimeauth_KEYBYTES: usize = crypto_onetimeauth_poly1305_KEYBYTES;
pub const crypto_onetimeauth_PRIMITIVE: &'static str = "poly1305";

// sodium/crypto_onetimeauth_poly1305.h
pub const crypto_onetimeauth_poly1305_BYTES: usize = 16;
pub const crypto_onetimeauth_poly1305_KEYBYTES: usize = 32;

// sodium/crypto_pwhash_scryptsalsa208sha256.h
pub const crypto_pwhash_scryptsalsa208sha256_SALTBYTES: usize = 32;
pub const crypto_pwhash_scryptsalsa208sha256_STRBYTES: usize = 102;
pub const crypto_pwhash_scryptsalsa208sha256_STRPREFIX: &'static str = "$7$";
pub const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE: usize = 524288;
pub const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE: usize = 16777216;
pub const crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE: usize = 33554432;
pub const crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE: usize = 1073741824;

// sodium/crypto_scalarmult.h
pub const crypto_scalarmult_BYTES: usize = crypto_scalarmult_curve25519_BYTES;
pub const crypto_scalarmult_SCALARBYTES: usize = crypto_scalarmult_curve25519_SCALARBYTES;
pub const crypto_scalarmult_PRIMITIVE: &'static str = "curve25519";

// sodium/crypto_scalarmult_curve25519.h
pub const crypto_scalarmult_curve25519_BYTES: usize = 32;
pub const crypto_scalarmult_curve25519_SCALARBYTES: usize = 32;

// sodium/crypto_secretbox.h
pub const crypto_secretbox_KEYBYTES: usize = crypto_secretbox_xsalsa20poly1305_KEYBYTES;
pub const crypto_secretbox_NONCEBYTES: usize = crypto_secretbox_xsalsa20poly1305_NONCEBYTES;
pub const crypto_secretbox_MACBYTES: usize = crypto_secretbox_xsalsa20poly1305_MACBYTES;
pub const crypto_secretbox_PRIMITIVE: &'static str = "xsalsa20poly1305";
pub const crypto_secretbox_ZEROBYTES: usize = crypto_secretbox_xsalsa20poly1305_ZEROBYTES;
pub const crypto_secretbox_BOXZEROBYTES: usize = crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES;

// sodium/crypto_secretbox_xsalsa20poly1305.h
pub const crypto_secretbox_xsalsa20poly1305_KEYBYTES: usize = 32;
pub const crypto_secretbox_xsalsa20poly1305_NONCEBYTES: usize = 24;
pub const crypto_secretbox_xsalsa20poly1305_ZEROBYTES: usize = 32;
pub const crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES: usize = 16;
pub const crypto_secretbox_xsalsa20poly1305_MACBYTES: usize = crypto_secretbox_xsalsa20poly1305_ZEROBYTES
                                                                - crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES;

// sodium/crypto_shorthash.h
pub const crypto_shorthash_BYTES: usize = crypto_shorthash_siphash24_BYTES;
pub const crypto_shorthash_KEYBYTES: usize = crypto_shorthash_siphash24_KEYBYTES;
pub const crypto_shorthash_PRIMITIVE: &'static str = "siphash24";

// sodium/crypto_shorthash_siphash24.h
pub const crypto_shorthash_siphash24_BYTES: usize = 8;
pub const crypto_shorthash_siphash24_KEYBYTES: usize = 16;

// sodium/crypto_sign.h
pub const crypto_sign_BYTES: usize = crypto_sign_ed25519_BYTES;
pub const crypto_sign_SEEDBYTES: usize = crypto_sign_ed25519_SEEDBYTES;
pub const crypto_sign_PUBLICKEYBYTES: usize = crypto_sign_ed25519_PUBLICKEYBYTES;
pub const crypto_sign_SECRETKEYBYTES: usize = crypto_sign_ed25519_SECRETKEYBYTES;
pub const crypto_sign_PRIMITIVE: &'static str = "ed25519";

// sodium/crypto_sign_ed25519.h
pub const crypto_sign_ed25519_BYTES: usize = 64;
pub const crypto_sign_ed25519_SEEDBYTES: usize = 32;
pub const crypto_sign_ed25519_PUBLICKEYBYTES: usize = 32;
pub const crypto_sign_ed25519_SECRETKEYBYTES: usize = 32 + 32;

// sodium/crypto_sign_edwards25519sha512batch.h
pub const crypto_sign_edwards25519sha512batch_BYTES: usize = 64;
pub const crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES: usize = 32;
pub const crypto_sign_edwards25519sha512batch_SECRETKEYBYTES: usize = 32 + 32;

// sodium/crypto_stream.h
pub const crypto_stream_KEYBYTES: usize = crypto_stream_xsalsa20_KEYBYTES;
pub const crypto_stream_NONCEBYTES: usize = crypto_stream_xsalsa20_NONCEBYTES;
pub const crypto_stream_PRIMITIVE: &'static str = "xsalsa20";

// sodium/crypto_stream_chacha20.h
pub const crypto_stream_chacha20_KEYBYTES: usize = 32;
pub const crypto_stream_chacha20_NONCEBYTES: usize = 8;

// sodium/crypto_stream_salsa20.h
pub const crypto_stream_salsa20_KEYBYTES: usize = 32;
pub const crypto_stream_salsa20_NONCEBYTES: usize = 8;

// sodium/crypto_stream_salsa2012.h
pub const crypto_stream_salsa2012_KEYBYTES: usize = 32;
pub const crypto_stream_salsa2012_NONCEBYTES: usize = 8;

// sodium/crypto_stream_salsa208.h
pub const crypto_stream_salsa208_KEYBYTES: usize = 32;
pub const crypto_stream_salsa208_NONCEBYTES: usize = 8;

// sodium/crypto_stream_xsalsa20.h
pub const crypto_stream_xsalsa20_KEYBYTES: usize = 32;
pub const crypto_stream_xsalsa20_NONCEBYTES: usize = 24;

// sodium/crypto_verify_16.h
pub const crypto_verify_16_BYTES: usize = 16;

// sodium/crypto_verify_32.h
pub const crypto_verify_32_BYTES: usize = 32;

// sodium/crypto_verify_64.h
pub const crypto_verify_64_BYTES: usize = 64;

extern {
    // sodium/core.h
    pub fn sodium_init() -> c_int;

    // sodium/crypto_aead_chacha20poly1305.h
    pub fn crypto_aead_chacha20poly1305_keybytes() -> usize;
    pub fn crypto_aead_chacha20poly1305_nsecbytes() -> usize;
    pub fn crypto_aead_chacha20poly1305_npubbytes() -> usize;
    pub fn crypto_aead_chacha20poly1305_abytes() -> usize;
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
    pub fn crypto_auth_bytes() -> usize;
    pub fn crypto_auth_keybytes() -> usize;
    pub fn crypto_auth_primitive() -> *const c_char;
    pub fn crypto_auth(out: *mut c_uchar, in_: *const c_uchar,
                       inlen: c_ulonglong, k: *const c_uchar) -> c_int;
    pub fn crypto_auth_verify(h: *const c_uchar, in_: *const c_uchar,
                              inlen: c_ulonglong, k: *const c_uchar) -> c_int;

    // sodium/crypto_auth_hmacsha256.h
    pub fn crypto_auth_hmacsha256_statebytes() -> usize;
    pub fn crypto_auth_hmacsha256_bytes() -> usize;
    pub fn crypto_auth_hmacsha256_keybytes() -> usize;
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
                                       keylen: usize) -> c_int;
    pub fn crypto_auth_hmacsha256_update(state: *mut crypto_auth_hmacsha256_state,
                                         in_: *const c_uchar,
                                         inlen: c_ulonglong) -> c_int;
    pub fn crypto_auth_hmacsha256_final(state: *mut crypto_auth_hmacsha256_state,
                                        out: *mut c_uchar) -> c_int;

    // sodium/crypto_auth_hmacsha512.h
    pub fn crypto_auth_hmacsha512_statebytes() -> usize;
    pub fn crypto_auth_hmacsha512_bytes() -> usize;
    pub fn crypto_auth_hmacsha512_keybytes() -> usize;
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
                                       keylen: usize) -> c_int;
    pub fn crypto_auth_hmacsha512_update(state: *mut crypto_auth_hmacsha512_state,
                                         in_: *const c_uchar,
                                         inlen: c_ulonglong) -> c_int;
    pub fn crypto_auth_hmacsha512_final(state: *mut crypto_auth_hmacsha512_state,
                                        out: *mut c_uchar) -> c_int;

    // sodium/crypto_auth_hmacsha512256.h
    pub fn crypto_auth_hmacsha512256_statebytes() -> usize;
    pub fn crypto_auth_hmacsha512256_bytes() -> usize;
    pub fn crypto_auth_hmacsha512256_keybytes() -> usize;
    pub fn crypto_auth_hmacsha512256(out: *mut c_uchar, in_: *const c_uchar,
                                     inlen: c_ulonglong, k: *const c_uchar) -> c_int;
    pub fn crypto_auth_hmacsha512256_verify(h: *const c_uchar,
                                            in_: *const c_uchar,
                                            inlen: c_ulonglong,
                                            k: *const c_uchar);
    pub fn crypto_auth_hmacsha512256_init(state: *mut crypto_auth_hmacsha512256_state,
                                          key: *const c_uchar,
                                          keylen: usize) -> c_int;
    pub fn crypto_auth_hmacsha512256_update(state: *mut crypto_auth_hmacsha512256_state,
                                            in_: *const c_uchar,
                                            inlen: c_ulonglong) -> c_int;
    pub fn crypto_auth_hmacsha512256_final(state: *mut crypto_auth_hmacsha512256_state,
                                           out: *mut c_uchar) -> c_int;

    // sodium/crypto_box.h
    pub fn crypto_box_seedbytes() -> usize;
    pub fn crypto_box_publickeybytes() -> usize;
    pub fn crypto_box_secretkeybytes() -> usize;
    pub fn crypto_box_noncebytes() -> usize;
    pub fn crypto_box_macbytes() -> usize;
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
    pub fn crypto_box_beforenmbytes() -> usize;
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
    pub fn crypto_box_sealbytes() -> usize;
    pub fn crypto_box_seal(out: *mut c_uchar,
                           in_: *const c_uchar,
                           inlen: c_ulonglong,
                           pk: *const c_uchar) -> c_int;
    pub fn crypto_box_seal_open(out: *mut c_uchar,
                                in_: *const c_uchar,
                                inlen: c_ulonglong,
                                pk: *const c_uchar) -> c_int;
    pub fn crypto_box_zerobytes() -> usize;
    pub fn crypto_box_boxzerobytes() -> usize;
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
    pub fn crypto_box_curve25519xsalsa20poly1305_seedbytes() -> usize;
    pub fn crypto_box_curve25519xsalsa20poly1305_publickeybytes() -> usize;
    pub fn crypto_box_curve25519xsalsa20poly1305_secretkeybytes() -> usize;
    pub fn crypto_box_curve25519xsalsa20poly1305_beforenmbytes() -> usize;
    pub fn crypto_box_curve25519xsalsa20poly1305_noncebytes() -> usize;
    pub fn crypto_box_curve25519xsalsa20poly1305_zerobytes() -> usize;
    pub fn crypto_box_curve25519xsalsa20poly1305_boxzerobytes() -> usize;
    pub fn crypto_box_curve25519xsalsa20poly1305_macbytes() -> usize;
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
    pub fn crypto_core_hsalsa20_outputbytes() -> usize;
    pub fn crypto_core_hsalsa20_inputbytes() -> usize;
    pub fn crypto_core_hsalsa20_keybytes() -> usize;
    pub fn crypto_core_hsalsa20_constbytes() -> usize;
    pub fn crypto_core_hsalsa20(out: *mut c_uchar, in_: *const c_uchar,
                                k: *const c_uchar, c: *const c_uchar) -> c_int;

    // sodium/crypto_core_salsa20.h
    pub fn crypto_core_salsa20_outputbytes() -> usize;
    pub fn crypto_core_salsa20_inputbytes() -> usize;
    pub fn crypto_core_salsa20_keybytes() -> usize;
    pub fn crypto_core_salsa20_constbytes() -> usize;
    pub fn crypto_core_salsa20(out: *mut c_uchar, in_: *const c_uchar,
                               k: *const c_uchar, c: *const c_uchar) -> c_int;

    // sodium/crypto_core_salsa2012.h
    pub fn crypto_core_salsa2012_outputbytes() -> usize;
    pub fn crypto_core_salsa2012_inputbytes() -> usize;
    pub fn crypto_core_salsa2012_keybytes() -> usize;
    pub fn crypto_core_salsa2012_constbytes() -> usize;
    pub fn crypto_core_salsa2012(out: *mut c_uchar, in_: *const c_uchar,
                                 k: *const c_uchar, c: *const c_uchar) -> c_int;

    // sodium/crypto_core_salsa208.h
    pub fn crypto_core_salsa208_outputbytes() -> usize;
    pub fn crypto_core_salsa208_inputbytes() -> usize;
    pub fn crypto_core_salsa208_keybytes() -> usize;
    pub fn crypto_core_salsa208_constbytes() -> usize;
    pub fn crypto_core_salsa208(out: *mut c_uchar, in_: *const c_uchar,
                                k: *const c_uchar, c: *const c_uchar) -> c_int;

    // sodium/crypto_generichash.h
    pub fn crypto_generichash_bytes_min() -> usize;
    pub fn crypto_generichash_bytes_max() -> usize;
    pub fn crypto_generichash_bytes() -> usize;
    pub fn crypto_generichash_keybytes_min() -> usize;
    pub fn crypto_generichash_keybytes() -> usize;
    pub fn crypto_generichash_primitive() -> *const c_char;
    pub fn crypto_generichash_statebytes() -> usize;
    pub fn crypto_generichash(out: *mut c_uchar, outlen: usize,
                              in_: *const c_uchar, inlen: c_ulonglong,
                              key: *const c_uchar, keylen: usize) -> c_int;
    pub fn crypto_generichash_init(state: *mut crypto_generichash_state,
                                   key: *const c_uchar,
                                   keylen: usize, outlen: usize) -> c_int;
    pub fn crypto_generichash_update(state: *mut crypto_generichash_state,
                                     in_: *const c_uchar,
                                     inlen: c_ulonglong) -> c_int;
    pub fn crypto_generichash_final(state: *mut crypto_generichash_state,
                                    out: *mut c_uchar, outlen: usize) -> c_int;

    // sodium/crypto_generichash_blake2b.h
    pub fn crypto_generichash_blake2b_bytes_min() -> usize;
    pub fn crypto_generichash_blake2b_bytes_max() -> usize;
    pub fn crypto_generichash_blake2b_bytes() -> usize;
    pub fn crypto_generichash_blake2b_keybytes_min() -> usize;
    pub fn crypto_generichash_blake2b_keybytes_max() -> usize;
    pub fn crypto_generichash_blake2b_keybytes() -> usize;
    pub fn crypto_generichash_blake2b_saltbytes() -> usize;
    pub fn crypto_generichash_blake2b_personalbytes() -> usize;
    pub fn crypto_generichash_blake2b(out: *mut c_uchar, outlen: usize,
                                      in_: *const c_uchar, inlen: c_ulonglong,
                                      key: *const c_uchar, keylen: usize) -> c_int;
    pub fn crypto_generichash_blake2b_salt_personal(out: *mut c_uchar, outlen: usize,
                                                    in_: *const c_uchar,
                                                    inlen: c_ulonglong,
                                                    key: *const c_uchar,
                                                    keylen: usize,
                                                    salt: *const c_uchar,
                                                    personal: *const c_uchar) -> c_int;
    pub fn crypto_generichash_blake2b_update(state: *mut crypto_generichash_blake2b_state,
                                             in_: *const c_uchar,
                                             inlen: c_ulonglong) -> c_int;
    pub fn crypto_generichash_blake2b_final(state: *mut crypto_generichash_blake2b_state,
                                            out: *mut c_uchar,
                                            outlen: usize) -> c_int;

    // sodium/crypto_hash.h
    pub fn crypto_hash_bytes() -> usize;
    pub fn crypto_hash(out: *mut c_uchar, in_: *const c_uchar,
                       inlen: c_ulonglong) -> c_int;
    pub fn crypto_hash_primitive() -> *const c_char;

    // sodium/crypto_hash_sha256.h
    pub fn crypto_hash_sha256_statebytes() -> usize;
    pub fn crypto_hash_sha256_bytes() -> usize;
    pub fn crypto_hash_sha256(out: *mut c_uchar, in_: *const c_uchar,
                              inlen: c_ulonglong) -> c_int;
    pub fn crypto_hash_sha256_init(state: *mut crypto_hash_sha256_state) -> c_int;
    pub fn crypto_hash_sha256_update(state: *mut crypto_hash_sha256_state,
                                     in_: *const c_uchar,
                                     inlen: c_ulonglong) -> c_int;
    pub fn crypto_hash_sha256_final(state: *mut crypto_hash_sha256_state,
                                    out: *mut c_uchar) -> c_int;

    // sodium/crypto_hash_sha512.h
    pub fn crypto_hash_sha512_statebytes() -> usize;
    pub fn crypto_hash_sha512_bytes() -> usize;
    pub fn crypto_hash_sha512(out: *mut c_uchar, in_: *const c_uchar,
                              inlen: c_ulonglong) -> c_int;
    pub fn crypto_hash_sha512_init(state: *mut crypto_hash_sha512_state) -> c_int;
    pub fn crypto_hash_sha512_update(state: *mut crypto_hash_sha512_state,
                                     in_: *const c_uchar,
                                     inlen: c_ulonglong) -> c_int;
    pub fn crypto_hash_sha512_final(state: *mut crypto_hash_sha256_state,
                                    out: *mut c_uchar) -> c_int;

    // sodium/crypto_onetimeauth.h
    pub fn crypto_onetimeauth_statebytes() -> usize;
    pub fn crypto_onetimeauth_bytes() -> usize;
    pub fn crypto_onetimeauth_keybytes() -> usize;
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
    pub fn crypto_onetimeauth_poly1305_bytes() -> usize;
    pub fn crypto_onetimeauth_poly1305_keybytes() -> usize;
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
    pub fn crypto_pwhash_scryptsalsa208sha256_bytes_min() -> usize;
    pub fn crypto_pwhash_scryptsalsa208sha256_bytes_max() -> usize;
    pub fn crypto_pwhash_scryptsalsa208sha256_passwd_min() -> usize;
    pub fn crypto_pwhash_scryptsalsa208sha256_passwd_max() -> usize;
    pub fn crypto_pwhash_scryptsalsa208sha256_saltbytes() -> usize;
    pub fn crypto_pwhash_scryptsalsa208sha256_strbytes() -> usize;
    pub fn crypto_pwhash_scryptsalsa208sha256_strprefix() -> *const c_char;
    pub fn crypto_pwhash_scryptsalsa208sha256_opslimit_interactive() -> usize;
    pub fn crypto_pwhash_scryptsalsa208sha256_memlimit_interactive() -> usize;
    pub fn crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive() -> usize;
    pub fn crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive() -> usize;
    pub fn crypto_pwhash_scryptsalsa208sha256_opslimit_min() -> usize;
    pub fn crypto_pwhash_scryptsalsa208sha256_opslimit_max() -> usize;
    pub fn crypto_pwhash_scryptsalsa208sha256_memlimit_min() -> usize;
    pub fn crypto_pwhash_scryptsalsa208sha256_memlimit_max() -> usize;
    pub fn crypto_pwhash_scryptsalsa208sha256(out: *mut c_char,
                                              outlen: c_ulonglong,
                                              passwd: *const c_char,
                                              passwdlen: c_ulonglong,
                                              salt: *const c_uchar,
                                              opslimit: c_ulonglong,
                                              memlimit: usize) -> c_int;
    pub fn crypto_pwhash_scryptsalsa208sha256_str(out: *mut c_char,
                                                  passwd: *const c_char,
                                                  passwdlen: c_ulonglong,
                                                  opslimit: c_ulonglong,
                                                  memlimit: usize) -> c_int;
    pub fn crypto_pwhash_scryptsalsa208sha256_str_verify(str_: *const c_char,
                                                         passwd: *const c_char,
                                                         passwdlen: c_ulonglong) -> c_int;
    pub fn crypto_pwhash_scryptsalsa208sha256_ll(passwd: *const u8, passwdlen: usize,
                                                 salt: *const u8, saltlen: usize,
                                                 N: u64, r: u32, p: u32,
                                                 buf: *mut u8, buflen: usize) -> c_int;

    // sodium/crypto_scalarmult.h
    pub fn crypto_scalarmult_bytes() -> usize;
    pub fn crypto_scalarmult_scalarbytes() -> usize;
    pub fn crypto_scalarmult_primitive() -> *const c_char;
    pub fn crypto_scalarmult_base(q: *mut c_uchar, n: *const c_uchar) -> c_int;
    pub fn crypto_scalarmult(q: *mut c_uchar, n: *const c_uchar,
                             p: *const c_uchar) -> c_int;

    // sodium/crypto_scalarmult_curve25519.h
    pub fn crypto_scalarmult_curve25519_bytes() -> usize;
    pub fn crypto_scalarmult_curve25519_scalarbytes() -> usize;
    pub fn crypto_scalarmult_curve25519_primitive() -> *const c_char;
    pub fn crypto_scalarmult_curve25519_base(q: *mut c_uchar, n: *const c_uchar) -> c_int;
    pub fn crypto_scalarmult_curve25519(q: *mut c_uchar, n: *const c_uchar,
                                        p: *const c_uchar) -> c_int;

    // sodium/crypto_secretbox_xsalsa20poly1305.h
    pub fn crypto_secretbox_xsalsa20poly1305_keybytes() -> usize;
    pub fn crypto_secretbox_xsalsa20poly1305_noncebytes() -> usize;
    pub fn crypto_secretbox_xsalsa20poly1305_zerobytes() -> usize;
    pub fn crypto_secretbox_xsalsa20poly1305_boxzerobytes() -> usize;
    pub fn crypto_secretbox_xsalsa20poly1305_macbytes() -> usize;
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
    pub fn crypto_secretbox_keybytes() -> usize;
    pub fn crypto_secretbox_noncebytes() -> usize;
    pub fn crypto_secretbox_zerobytes() -> usize;
    pub fn crypto_secretbox_boxzerobytes() -> usize;
    pub fn crypto_secretbox_macbytes() -> usize;
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
    pub fn crypto_shorthash_bytes() -> usize;
    pub fn crypto_shorthash_keybytes() -> usize;
    pub fn crypto_shorthash_primitive() -> *const c_char;
    pub fn crypto_shorthash(out: *mut c_uchar, in_: *const c_uchar,
                            inlen: c_ulonglong, k: *const c_uchar) -> c_int;

    // sodium/crypto_shorthash_siphash24.h
    pub fn crypto_shorthash_siphash24_bytes() -> usize;
    pub fn crypto_shorthash_siphash24_keybytes() -> usize;
    pub fn crypto_shorthash_siphash24(out: *mut c_uchar, in_: *const c_uchar,
                                      inlen: c_ulonglong, k: *const c_uchar) -> c_int;

    // sodium/crypto_sign.h
    pub fn crypto_sign_bytes() -> usize;
    pub fn crypto_sign_seedbytes() -> usize;
    pub fn crypto_sign_publickeybytes() -> usize;
    pub fn crypto_sign_secretkeybytes() -> usize;
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
    pub fn crypto_sign_ed25519_bytes() -> usize;
    pub fn crypto_sign_ed25519_seedbytes() -> usize;
    pub fn crypto_sign_ed25519_publickeybytes() -> usize;
    pub fn crypto_sign_ed25519_secretkeybytes() -> usize;
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
    pub fn crypto_sign_edwards25519sha512batch_bytes() -> usize;
    pub fn crypto_sign_edwards25519sha512batch_publickeybytes() -> usize;
    pub fn crypto_sign_edwards25519sha512batch_secretkeybytes() -> usize;
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
    pub fn crypto_stream_keybytes() -> usize;
    pub fn crypto_stream_noncebytes() -> usize;
    pub fn crypto_stream_primitive() -> *const c_char;
    pub fn crypto_stream(c: *mut c_uchar, clen: c_ulonglong,
                         n: *const c_uchar, k: *const c_uchar) -> c_int;
    pub fn crypto_stream_xor(c: *mut c_uchar, m: *const c_uchar,
                             mlen: c_ulonglong, n: *const c_uchar,
                             k: *const c_uchar) -> c_int;

    // sodium/crypto_stream_chacha20.h
    pub fn crypto_stream_chacha20_keybytes() -> usize;
    pub fn crypto_stream_chacha20_noncebytes() -> usize;
    pub fn crypto_stream_chacha20(c: *mut c_uchar, clen: c_ulonglong,
                                  n: *const c_uchar, k: *const c_uchar) -> c_int;
    pub fn crypto_stream_chacha20_xor(c: *mut c_uchar, m: *const c_uchar,
                                      mlen: c_ulonglong, n: *const c_uchar,
                                      k: *const c_uchar) -> c_int;
    pub fn crypto_stream_chacha20_xor_ic(c: *mut c_uchar, m: *const c_uchar,
                                         mlen: c_ulonglong,
                                         n: *const c_uchar, ic: u64,
                                         k: *const c_uchar) -> c_int;

    pub fn crypto_stream_chacha20_ietf_xor_ic(c: *mut c_uchar, m: *const c_uchar,
                                              mlen: c_ulonglong,
                                              n: *const c_uchar, ic: u32,
                                              k: *const c_uchar) -> c_int;

    // sodium/crypto_stream_salsa20.h
    pub fn crypto_stream_salsa20_keybytes() -> usize;
    pub fn crypto_stream_salsa20_noncebytes() -> usize;
    pub fn crypto_stream_salsa20(c: *mut c_uchar, clen: c_ulonglong,
                                 n: *const c_uchar, k: *const c_uchar) -> c_int;
    pub fn crypto_stream_salsa20_xor(c: *mut c_uchar, m: *const c_uchar,
                                     mlen: c_ulonglong, n: *const c_uchar,
                                     k: *const c_uchar) -> c_int;
    pub fn crypto_stream_salsa20_xor_ic(c: *mut c_uchar, m: *const c_uchar,
                                        mlen: c_ulonglong,
                                        n: *const c_uchar, ic: u64,
                                        k: *const c_uchar) -> c_int;

    // sodium/crypto_stream_salsa2012.h
    pub fn crypto_stream_salsa2012_keybytes() -> usize;
    pub fn crypto_stream_salsa2012_noncebytes() -> usize;
    pub fn crypto_stream_salsa2012(c: *mut c_uchar, clen: c_ulonglong,
                                   n: *const c_uchar, k: *const c_uchar) -> c_int;
    pub fn crypto_stream_salsa2012_xor(c: *mut c_uchar, m: *const c_uchar,
                                       mlen: c_ulonglong, n: *const c_uchar,
                                       k: *const c_uchar) -> c_int;

    // sodium/crypto_stream_salsa208.h
    pub fn crypto_stream_salsa208_keybytes() -> usize;
    pub fn crypto_stream_salsa208_noncebytes() -> usize;
    pub fn crypto_stream_salsa208(c: *mut c_uchar, clen: c_ulonglong,
                                  n: *const c_uchar, k: *const c_uchar) -> c_int;
    pub fn crypto_stream_salsa208_xor(c: *mut c_uchar, m: *const c_uchar,
                                      mlen: c_ulonglong, n: *const c_uchar,
                                      k: *const c_uchar) -> c_int;

    // sodium/crypto_stream_xsalsa20.h
    pub fn crypto_stream_xsalsa20_keybytes() -> usize;
    pub fn crypto_stream_xsalsa20_noncebytes() -> usize;
    pub fn crypto_stream_xsalsa20(c: *mut c_uchar, clen: c_ulonglong,
                                  n: *const c_uchar, k: *const c_uchar) -> c_int;
    pub fn crypto_stream_xsalsa20_xor(c: *mut c_uchar, m: *const c_uchar,
                                      mlen: c_ulonglong, n: *const c_uchar,
                                      k: *const c_uchar) -> c_int;
    pub fn crypto_stream_xsalsa20_xor_ic(c: *mut c_uchar, m: *const c_uchar,
                                         mlen: c_ulonglong,
                                         n: *const c_uchar, ic: u64,
                                         k: *const c_uchar) -> c_int;

    // sodium/crypto_verify_16.h
    pub fn crypto_verify_16_bytes() -> usize;
    pub fn crypto_verify_16(x: *const c_uchar, y: *const c_uchar) -> c_int;

    // sodium/crypto_verify_32.h
    pub fn crypto_verify_32_bytes() -> usize;
    pub fn crypto_verify_32(x: *const c_uchar, y: *const c_uchar) -> c_int;

    // sodium/crypto_verify_64.h
    pub fn crypto_verify_64_bytes() -> usize;
    pub fn crypto_verify_64(x: *const c_uchar, y: *const c_uchar) -> c_int;

    // sodium/randombytes.h
    pub fn randombytes_buf(buf: *mut c_void, size: usize);
    pub fn randombytes_random() -> u32;
    pub fn randombytes_uniform(upper_bound: u32) -> u32;
    pub fn randombytes_stir();
    pub fn randombytes_close() -> c_int;
    pub fn randombytes_set_implementation(impl_: *mut randombytes_implementation) -> c_int;
    pub fn randombytes_implementation_name() -> *const c_char;
    pub fn randombytes(buf: *mut c_void, buf_len: c_ulonglong);

    // sodium/randombytes_salsa20_random.h
    pub fn randombytes_salsa20_implementation_name() -> *const c_char;
    pub fn randombytes_salsa20_random() -> u32;
    pub fn randombytes_salsa20_random_stir();
    pub fn randombytes_salsa20_random_uniform(upper_bound: u32) -> u32;
    pub fn randombytes_salsa20_random_buf(buf: *mut c_void, size: usize);
    pub fn randombytes_salsa20_random_close() -> c_int;
    pub static randombytes_salsa20_implementation: randombytes_implementation;

    // sodium/randombytes_sysrandom.h
    pub fn randombytes_sysrandom_implementation_name() -> *const c_char;
    pub fn randombytes_sysrandom() -> u32;
    pub fn randombytes_sysrandom_stir();
    pub fn randombytes_sysrandom_uniform(upper_bound: u32) -> u32;
    pub fn randombytes_sysrandom_buf(buf: *mut c_void, size: usize);
    pub fn randombytes_sysrandom_close() -> c_int;
    pub static randombytes_sysrandom_implementation: randombytes_implementation;

    // sodium/version.h
    pub fn sodium_version_string() -> *const c_char;
    pub fn sodium_library_version_major() -> c_int;
    pub fn sodium_library_version_minor() -> c_int;

    // sodium/crypto_aead_chacha20poly1305.h
    pub fn crypto_aead_chacha20poly1305_ietf_encrypt(c: *mut c_uchar,
                                                     clen_p: *mut c_ulonglong,
                                                     m: *const c_uchar,
                                                     mlen: c_ulonglong,
                                                     ad: *const c_uchar,
                                                     adlen: c_ulonglong,
                                                     nsec: *const c_uchar,
                                                     npub: *const c_uchar,
                                                     k: *const c_uchar) -> c_int;
    pub fn crypto_aead_chacha20poly1305_ietf_decrypt(m: *mut c_uchar,
                                                     mlen_p: *mut c_ulonglong,
                                                     nsec: *mut c_uchar,
                                                     c: *const c_uchar,
                                                     clen: c_ulonglong,
                                                     ad: *const c_uchar,
                                                     adlen: c_ulonglong,
                                                     npub: *const c_uchar,
                                                     k: *const c_uchar) -> c_int;

    // sodium/crypto_aead_xchacha20poly1305.h
    pub fn crypto_aead_xchacha20poly1305_ietf_encrypt(c: *mut c_uchar,
                                                      clen_p: *mut c_ulonglong,
                                                      m: *const c_uchar,
                                                      mlen: c_ulonglong,
                                                      ad: *const c_uchar,
                                                      adlen: c_ulonglong,
                                                      nsec: *const c_uchar,
                                                      npub: *const c_uchar,
                                                      k: *const c_uchar) -> c_int;
    pub fn crypto_aead_xchacha20poly1305_ietf_decrypt(m: *mut c_uchar,
                                                      mlen_p: *mut c_ulonglong,
                                                      nsec: *mut c_uchar,
                                                      c: *const c_uchar,
                                                      clen: c_ulonglong,
                                                      ad: *const c_uchar,
                                                      adlen: c_ulonglong,
                                                      npub: *const c_uchar,
                                                      k: *const c_uchar) -> c_int;

    // sodium/utils.h
    pub fn sodium_increment(n: *mut c_uchar, nlen: usize);

    // sodium/crypto_pwhash_argon2i.h
    pub fn crypto_pwhash_argon2i_alg_argon2i13() -> c_int;
    pub fn crypto_pwhash_argon2i_bytes_min() -> usize;
    pub fn crypto_pwhash_argon2i_bytes_max() -> usize;
    pub fn crypto_pwhash_argon2i_passwd_min() -> usize;
    pub fn crypto_pwhash_argon2i_passwd_max() -> usize;
    pub fn crypto_pwhash_argon2i_saltbytes() -> usize;
    pub fn crypto_pwhash_argon2i_strbytes() -> usize;
    pub fn crypto_pwhash_argon2i_strprefix() -> *const c_char;
    pub fn crypto_pwhash_argon2i_opslimit_min() -> usize;
    pub fn crypto_pwhash_argon2i_opslimit_max() -> usize;
    pub fn crypto_pwhash_argon2i_memlimit_min() -> usize;
    pub fn crypto_pwhash_argon2i_memlimit_max() -> usize;
    pub fn crypto_pwhash_argon2i_opslimit_interactive() -> usize;
    pub fn crypto_pwhash_argon2i_memlimit_interactive() -> usize;
    pub fn crypto_pwhash_argon2i_opslimit_moderate() -> usize;
    pub fn crypto_pwhash_argon2i_memlimit_moderate() -> usize;
    pub fn crypto_pwhash_argon2i_opslimit_sensitive() -> usize;
    pub fn crypto_pwhash_argon2i_memlimit_sensitive() -> usize;
    pub fn crypto_pwhash_argon2i(out: *mut c_uchar,
                                 outlen: c_ulonglong,
                                 passwd: *const c_char,
                                 passwdlen: c_ulonglong,
                                 salt: *const c_uchar,
                                 opslimit: c_ulonglong, memlimit: usize,
                                 alg: c_int) -> c_int;
    pub fn crypto_pwhash_argon2i_str(out: *mut c_char,
                                     passwd: *const c_char,
                                     passwdlen: c_ulonglong,
                                     opslimit: c_ulonglong, memlimit: usize) -> c_int;
    pub fn crypto_pwhash_argon2i_str_verify(_str: *const c_char,
                                            passwd: *const c_char,
                                            passwdlen: c_ulonglong) -> c_int;

    // sodium/crypto_pwhash_argon2id.h
    pub fn crypto_pwhash_argon2id_alg_argon2id13() -> c_int;
    pub fn crypto_pwhash_argon2id_bytes_min() -> usize;
    pub fn crypto_pwhash_argon2id_bytes_max() -> usize;
    pub fn crypto_pwhash_argon2id_passwd_min() -> usize;
    pub fn crypto_pwhash_argon2id_passwd_max() -> usize;
    pub fn crypto_pwhash_argon2id_saltbytes() -> usize;
    pub fn crypto_pwhash_argon2id_strbytes() -> usize;
    pub fn crypto_pwhash_argon2id_strprefix() -> *const c_char;
    pub fn crypto_pwhash_argon2id_opslimit_min() -> usize;
    pub fn crypto_pwhash_argon2id_opslimit_max() -> usize;
    pub fn crypto_pwhash_argon2id_memlimit_min() -> usize;
    pub fn crypto_pwhash_argon2id_memlimit_max() -> usize;
    pub fn crypto_pwhash_argon2id_opslimit_interactive() -> usize;
    pub fn crypto_pwhash_argon2id_memlimit_interactive() -> usize;
    pub fn crypto_pwhash_argon2id_opslimit_moderate() -> usize;
    pub fn crypto_pwhash_argon2id_memlimit_moderate() -> usize;
    pub fn crypto_pwhash_argon2id_opslimit_sensitive() -> usize;
    pub fn crypto_pwhash_argon2id_memlimit_sensitive() -> usize;
    pub fn crypto_pwhash_argon2id(out: *mut c_uchar,
                                  outlen: c_ulonglong,
                                  passwd: *const c_char,
                                  passwdlen: c_ulonglong,
                                  salt: *const c_uchar,
                                  opslimit: c_ulonglong, memlimit: usize,
                                  alg: c_int) -> c_int;
    pub fn crypto_pwhash_argon2id_str(out: *mut c_char,
                                      passwd: *const c_char,
                                      passwdlen: c_ulonglong,
                                      opslimit: c_ulonglong, memlimit: usize) -> c_int;
    pub fn crypto_pwhash_argon2id_str_verify(_str: *const c_char,
                                             passwd: *const c_uchar,
                                             passwdlen: c_ulonglong) -> c_int;

    // sodium/crypto_pwhash.h
    pub fn crypto_pwhash_alg_argon2i13() -> c_int;
    pub fn crypto_pwhash_alg_argon2id13() -> c_int;
    pub fn crypto_pwhash_alg_default() -> c_int;
    pub fn crypto_pwhash_bytes_min() -> usize;
    pub fn crypto_pwhash_bytes_max() -> usize;
    pub fn crypto_pwhash_passwd_min() -> usize;
    pub fn crypto_pwhash_passwd_max() -> usize;
    pub fn crypto_pwhash_saltbytes() -> usize;
    pub fn crypto_pwhash_strbytes() -> usize;
    pub fn crypto_pwhash_strprefix() -> *const c_char;
    pub fn crypto_pwhash_opslimit_min() -> usize;
    pub fn crypto_pwhash_opslimit_max() -> usize;
    pub fn crypto_pwhash_memlimit_min() -> usize;
    pub fn crypto_pwhash_memlimit_max() -> usize;
    pub fn crypto_pwhash_opslimit_interactive() -> usize;
    pub fn crypto_pwhash_memlimit_interactive() -> usize;
    pub fn crypto_pwhash_opslimit_moderate() -> usize;
    pub fn crypto_pwhash_memlimit_moderate() -> usize;
    pub fn crypto_pwhash_opslimit_sensitive() -> usize;
    pub fn crypto_pwhash_memlimit_sensitive() -> usize;
    pub fn crypto_pwhash(out: *mut c_uchar, outlen: c_ulonglong,
                         passwd: *const c_char, passwdlen: c_ulonglong,
                         salt: *const c_uchar,
                         opslimit: c_ulonglong, memlimit: usize, alg: c_int) -> c_int;
    pub fn crypto_pwhash_str(out: *mut c_char,
                             passwd: *const c_char, passwdlen: c_ulonglong,
                             opslimit: c_ulonglong, memlimit: usize) -> c_int;
    pub fn crypto_pwhash_str_alg(out: *mut c_char,
                                 passwd: *const c_char, passwdlen: c_ulonglong,
                                 opslimit: c_ulonglong, memlimit: usize, alg: c_int) -> c_int;
    pub fn crypto_pwhash_str_verify(_str: *const c_char,
                                    passwd: *const c_char,
                                    passwdlen: c_ulonglong) -> c_int;
    pub fn crypto_pwhash_primitive() -> *const c_char;
}

// sodium/crypto_hash_sha256.h
#[repr(C)]
#[derive(Copy)]
pub struct crypto_hash_sha256_state {
    pub state: [u32; 8],
    pub count: [u32; 2],
    pub buf: [c_uchar; 64],
}

impl Clone for crypto_hash_sha256_state {
    fn clone(&self) -> crypto_hash_sha256_state {
        unsafe {
            let mut x: crypto_hash_sha256_state = mem::uninitialized();
            ptr::copy::<crypto_hash_sha256_state>(mem::transmute(self),
                                                  mem::transmute(&mut x),
                                                  mem::size_of::<crypto_hash_sha256_state>());
            x
        }
    }
}

// sodium/crypto_auth_hmacsha256.h
#[repr(C)]
#[derive(Copy, Clone)]
pub struct crypto_auth_hmacsha256_state {
    pub ictx: crypto_hash_sha256_state,
    pub octx: crypto_hash_sha256_state,
}

// sodium/crypto_hash_sha512.h
#[repr(C)]
#[derive(Copy)]
pub struct crypto_hash_sha512_state {
    pub state: [u64; 8],
    pub count: [u64; 2],
    pub buf: [c_uchar; 128],
}

impl Clone for crypto_hash_sha512_state {
    fn clone(&self) -> crypto_hash_sha512_state {
        unsafe {
            let mut x: crypto_hash_sha512_state = mem::uninitialized();
            ptr::copy::<crypto_hash_sha512_state>(mem::transmute(self),
                                                  mem::transmute(&mut x),
                                                  mem::size_of::<crypto_hash_sha512_state>());
            x
        }
    }
}

// sodium/crypto_auth_hmacsha512.h
#[repr(C)]
#[derive(Copy, Clone)]
pub struct crypto_auth_hmacsha512_state {
    pub ictx: crypto_hash_sha512_state,
    pub octx: crypto_hash_sha512_state,
}

// sodium/crypto_auth_hmacsha512256.h
pub type crypto_auth_hmacsha512256_state = crypto_auth_hmacsha512_state;

// sodium/crypto_generichash_blake2b.h
#[repr(C)]
#[repr(packed)]
#[derive(Copy)]
pub struct crypto_generichash_blake2b_state {
    pub h: [u64; 8],
    pub t: [u64; 2],
    pub f: [u64; 2],
    pub buf: [u8; 2 * 128],
    pub buflen: usize,
    pub last_node: u8,
}

impl Clone for crypto_generichash_blake2b_state {
    fn clone(&self) -> crypto_generichash_blake2b_state {
        unsafe {
            let mut x: crypto_generichash_blake2b_state = mem::uninitialized();
            ptr::copy::<crypto_generichash_blake2b_state>(mem::transmute(self),
                                                          mem::transmute(&mut x),
                                                          mem::size_of::<crypto_generichash_blake2b_state>());
            x
        }
    }
}

// sodium/crypto_generichash.h
pub type crypto_generichash_state = crypto_generichash_blake2b_state;

// sodium/crypto_int32.h
pub type crypto_int32 = i32;

// sodium/crypto_int64.h
pub type crypto_int64 = i64;

// sodium/crypto_uint16.h
pub type crypto_uint16 = u16;

// sodium/crypto_uint32.h
pub type crypto_uint32 = u32;

// sodium/crypto_uint64.h
pub type crypto_uint64 = u64;

// sodium/crypto_uint8.h
pub type crypto_uint8 = u8;

// sodium/crypto_onetimeauth_poly1305.h
#[repr(C)]
#[derive(Copy)]
pub struct crypto_onetimeauth_poly1305_state {
    pub aligner: c_ulonglong,
    pub opaque: [c_uchar; 136],
}

impl Clone for crypto_onetimeauth_poly1305_state {
    fn clone(&self) -> crypto_onetimeauth_poly1305_state {
        unsafe {
            let mut x: crypto_onetimeauth_poly1305_state = mem::uninitialized();
            ptr::copy::<crypto_onetimeauth_poly1305_state>(mem::transmute(self),
                                                           mem::transmute(&mut x),
                                                           mem::size_of::<crypto_onetimeauth_poly1305_state>());
            x
        }
    }
}

// sodium/crypto_onetimeauth.h
pub type crypto_onetimeauth_state = crypto_onetimeauth_poly1305_state;

// sodium/crypto_onetimeauth_poly1305.h
#[repr(C)]
#[derive(Copy, Clone)]
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
#[derive(Copy, Clone)]
pub struct randombytes_implementation {
    pub implementation_name: extern fn() -> *const c_char,
    pub random: extern fn() -> u32,
    pub stir: extern fn(),
    pub uniform: extern fn(upper_bound: u32) -> u32,
    pub buf: extern fn(buf: *mut c_void, size: usize),
    pub close: extern fn() -> c_int,
}

#[test]
fn test_it_work() {
    unsafe {
        sodium_init();
    }
}
