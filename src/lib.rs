
#![allow(non_camel_case_types)]
#![allow(dead_code)]

extern crate libc;

#[link(name = "sodium")]
extern {
    // sodium/core.h
    fn sodium_init() -> libc::c_int;

    // sodium/crypto_aead_chacha20poly1305.h
    fn crypto_aead_chacha20poly1305_keybytes() -> libc::size_t;
    fn crypto_aead_chacha20poly1305_nsecbytes() -> libc::size_t;
    fn crypto_aead_chacha20poly1305_npubbytes() -> libc::size_t;
    fn crypto_aead_chacha20poly1305_abytes() -> libc::size_t;
    fn crypto_aead_chacha20poly1305_encrypt(c: *mut libc::c_uchar,
                                            clen: *mut libc::c_ulonglong,
                                            m: *const libc::c_uchar,
                                            mlen: libc::c_ulonglong,
                                            ad: *const libc::c_uchar,
                                            adlen: libc::c_ulonglong,
                                            nsec: *const libc::c_uchar,
                                            npub: *const libc::c_uchar,
                                            k: *const libc::c_uchar) -> libc::c_int;
    fn crypto_aead_chacha20poly1305_decrypt(m: *mut libc::c_uchar,
                                            mlen: *mut libc::c_ulonglong,
                                            nsec: *mut libc::c_uchar,
                                            c: *const libc::c_uchar,
                                            clen: libc::c_ulonglong,
                                            ad: *const libc::c_uchar,
                                            adlen: libc::c_ulonglong,
                                            npub: *const libc::c_uchar,
                                            k: *const libc::c_uchar) -> libc::c_int;

    // sodium/crypto_auth.h
    fn crypto_auth_bytes() -> libc::size_t;
    fn crypto_auth_keybytes() -> libc::size_t;
    fn crypto_auth_primitive() -> *const libc::c_char;
    fn crypto_auth(out: *mut libc::c_uchar, in_: *const libc::c_uchar,
                   inlen: libc::c_ulonglong, k: *const libc::c_uchar) -> libc::c_int;
    fn crypto_auth_verify(h: *const libc::c_uchar, in_: *const libc::c_uchar,
                          inlen: libc::c_ulonglong, k: *const libc::c_uchar) -> libc::c_int;

    // sodium/crypto_auth_hmacsha256.h
    fn crypto_auth_hmacsha256_statebytes() -> libc::size_t;
    fn crypto_auth_hmacsha256_bytes() -> libc::size_t;
    fn crypto_auth_hmacsha256_keybytes() -> libc::size_t;
    fn crypto_auth_hmacsha256(out: *mut libc::c_uchar,
                              in_: *const libc::c_uchar,
                              inlen: libc::c_ulonglong,
                              k: *const libc::c_uchar) -> libc::c_int;
    fn crypto_auth_hmacsha256_verify(h: *const libc::c_uchar,
                                     in_: *const libc::c_uchar,
                                     inlen: libc::c_ulonglong,
                                     k: *const libc::c_uchar) -> libc::c_int;
    fn crypto_auth_hmacsha256_init(state: *mut crypto_auth_hmacsha256_state,
                                   key: *const libc::c_uchar,
                                   keylen: libc::size_t) -> libc::c_int;
    fn crypto_auth_hmacsha256_update(state: *mut crypto_auth_hmacsha256_state,
                                     in_: *const libc::c_uchar,
                                     inlen: libc::c_ulonglong) -> libc::c_int;
    fn crypto_auth_hmacsha256_final(state: *mut crypto_auth_hmacsha256_state,
                                    out: *mut libc::c_uchar) -> libc::c_int;

    // sodium/crypto_auth_hmacsha512.h
    fn crypto_auth_hmacsha512_statebytes() -> libc::size_t;
    fn crypto_auth_hmacsha512_bytes() -> libc::size_t;
    fn crypto_auth_hmacsha512_keybytes() -> libc::size_t;
    fn crypto_auth_hmacsha512(out: *mut libc::c_uchar,
                              in_: *const libc::c_uchar,
                              inlen: libc::c_ulonglong,
                              k: *const libc::c_uchar) -> libc::c_int;
    fn crypto_auth_hmacsha512_verify(h: *const libc::c_uchar,
                                     in_: *const libc::c_uchar,
                                     inlen: libc::c_ulonglong,
                                     k: *const libc::c_uchar) -> libc::c_int;
    fn crypto_auth_hmacsha512_init(state: *mut crypto_auth_hmacsha512_state,
                                   key: *const libc::c_uchar,
                                   keylen: libc::size_t) -> libc::c_int;
    fn crypto_auth_hmacsha512_update(state: *mut crypto_auth_hmacsha512_state,
                                     in_: *const libc::c_uchar,
                                     inlen: libc::c_ulonglong) -> libc::c_int;
    fn crypto_auth_hmacsha512_final(state: *mut crypto_auth_hmacsha512_state,
                                    out: *mut libc::c_uchar) -> libc::c_int;

    // sodium/crypto_auth_hmacsha512256.h
    fn crypto_auth_hmacsha512256_statebytes() -> libc::size_t;
    fn crypto_auth_hmacsha512256_bytes() -> libc::size_t;
    fn crypto_auth_hmacsha512256_keybytes() -> libc::size_t;
    fn crypto_auth_hmacsha512256(out: *mut libc::c_uchar, in_: *const libc::c_uchar,
                                 inlen: libc::c_ulonglong, k: *const libc::c_uchar) -> libc::c_int;
    fn crypto_auth_hmacsha512256_verify(h: *const libc::c_uchar,
                                        in_: *const libc::c_uchar,
                                        inlen: libc::c_ulonglong,
                                        k: *const libc::c_uchar);
    fn crypto_auth_hmacsha512256_init(state: *mut crypto_auth_hmacsha512256_state,
                                      key: *const libc::c_uchar,
                                      keylen: libc::size_t) -> libc::c_int;
    fn crypto_auth_hmacsha512256_update(state: *mut crypto_auth_hmacsha512256_state,
                                        in_: *const libc::c_uchar,
                                        inlen: libc::c_ulonglong) -> libc::c_int;
    fn crypto_auth_hmacsha512256_final(state: *mut crypto_auth_hmacsha512256_state,
                                       out: *mut libc::c_uchar) -> libc::c_int;

    // sodium/crypto_box.h
    fn crypto_box_seedbytes() -> libc::size_t;
    fn crypto_box_publickeybytes() -> libc::size_t;
    fn crypto_box_secretkeybytes() -> libc::size_t;
    fn crypto_box_noncebytes() -> libc::size_t;
    fn crypto_box_macbytes() -> libc::size_t;
    fn crypto_box_primitive() -> *const libc::c_char;
    fn crypto_box_seed_keypair(pk: *mut libc::c_uchar, sk: *mut libc::c_uchar,
                               seed: *const libc::c_uchar) -> libc::c_int;
    fn crypto_box_keypair(pk: *mut libc::c_uchar, sk: *mut libc::c_uchar) -> libc::c_int;
    fn crypto_box_easy(c: *mut libc::c_uchar, m: *const libc::c_uchar,
                       mlen: libc::c_ulonglong, n: *const libc::c_uchar,
                       pk: *const libc::c_uchar, sk: *const libc::c_uchar) -> libc::c_int;
    fn crypto_box_open_easy(m: *mut libc::c_uchar, c: *const libc::c_uchar,
                            clen: libc::c_ulonglong, n: *const libc::c_uchar,
                            pk: *const libc::c_uchar, sk: *const libc::c_uchar) -> libc::c_int;
    fn crypto_box_detached(c: *mut libc::c_uchar, mac: *mut libc::c_uchar,
                           m: *const libc::c_uchar, mlen: libc::c_ulonglong,
                           n: *const libc::c_uchar, pk: *const libc::c_uchar,
                           sk: *const libc::c_uchar) -> libc::c_int;
    fn crypto_box_open_detached(m: *mut libc::c_uchar, c: *const libc::c_uchar,
                                mac: *const libc::c_uchar,
                                clen: libc::c_ulonglong,
                                n: *const libc::c_uchar,
                                pk: *const libc::c_uchar,
                                sk: *const libc::c_uchar) -> libc::c_int;
    fn crypto_box_beforenmbytes() -> libc::size_t;
    fn crypto_box_beforenm(k: *mut libc::c_uchar, pk: *const libc::c_uchar,
                           sk: *const libc::c_uchar) -> libc::c_int;
    fn crypto_box_easy_afternm(c: *mut libc::c_uchar, m: *const libc::c_uchar,
                               mlen: libc::c_ulonglong, n: *const libc::c_uchar,
                               k: *const libc::c_uchar) -> libc::c_int;
    fn crypto_box_open_easy_afternm(m: *mut libc::c_uchar, c: *const libc::c_uchar,
                                    clen: libc::c_ulonglong, n: *const libc::c_uchar,
                                    k: *const libc::c_uchar) -> libc::c_int;
    fn crypto_box_detached_afternm(c: *mut libc::c_uchar, mac: *mut libc::c_uchar,
                                   m: *const libc::c_uchar, mlen: libc::c_ulonglong,
                                   n: *const libc::c_uchar, k: libc::c_uchar) -> libc::c_int;
    fn crypto_box_open_detached_afternm(m: *mut libc::c_uchar, c: *const libc::c_uchar,
                                        mac: *const libc::c_uchar,
                                        clen: libc::c_ulonglong, n: *const libc::c_uchar,
                                        k: *const libc::c_uchar) -> libc::c_int;
    fn crypto_box_zerobytes() -> libc::size_t;
    fn crypto_box_boxzerobytes() -> libc::size_t;
    fn crypto_box(c: *mut libc::c_uchar, m: *const libc::c_uchar,
                  mlen: libc::c_ulonglong, n: *const libc::c_uchar,
                  pk: *const libc::c_uchar, sk: *const libc::c_uchar) -> libc::c_int;
    fn crypto_box_open(m: *mut libc::c_uchar, c: *const libc::c_uchar,
                       clen: libc::c_ulonglong, n: *const libc::c_uchar,
                       pk: *const libc::c_uchar, sk: *const libc::c_uchar) -> libc::c_int;
    fn crypto_box_afternm(c: *mut libc::c_uchar, m: *const libc::c_uchar,
                          mlen: libc::c_ulonglong, n: *const libc::c_uchar,
                          k: *const libc::c_uchar) -> libc::c_int;
    fn crypto_box_open_afternm(m: *mut libc::c_uchar, c: *const libc::c_uchar,
                               clen: libc::c_ulonglong, n: *const libc::c_uchar,
                               k: *const libc::c_uchar) -> libc::c_int;

    // sodium/crypto_box_curve25519xsalsa20poly1305.h
    fn crypto_box_curve25519xsalsa20poly1305_seedbytes() -> libc::size_t;
    fn crypto_box_curve25519xsalsa20poly1305_publickeybytes() -> libc::size_t;
    fn crypto_box_curve25519xsalsa20poly1305_secretkeybytes() -> libc::size_t;
    fn crypto_box_curve25519xsalsa20poly1305_beforenmbytes() -> libc::size_t;
    fn crypto_box_curve25519xsalsa20poly1305_noncebytes() -> libc::size_t;
    fn crypto_box_curve25519xsalsa20poly1305_zerobytes() -> libc::size_t;
    fn crypto_box_curve25519xsalsa20poly1305_boxzerobytes() -> libc::size_t;
    fn crypto_box_curve25519xsalsa20poly1305_macbytes() -> libc::size_t;
    fn crypto_box_curve25519xsalsa20poly1305(c: *mut libc::c_uchar,
                                             m: *const libc::c_uchar,
                                             mlen: libc::c_ulonglong,
                                             n: *const libc::c_uchar,
                                             pk: *const libc::c_uchar,
                                             sk: *const libc::c_uchar) -> libc::c_int;
    fn crypto_box_curve25519xsalsa20poly1305_open(m: *mut libc::c_uchar,
                                                  c: *const libc::c_uchar,
                                                  clen: libc::c_ulonglong,
                                                  n: *const libc::c_uchar,
                                                  pk: *const libc::c_uchar,
                                                  sk: *const libc::c_uchar) -> libc::c_int;
    fn crypto_box_curve25519xsalsa20poly1305_seed_keypair(pk: *mut libc::c_uchar,
                                                          sk: *mut libc::c_uchar,
                                                          seed: *const libc::c_uchar) -> libc::c_int;
    fn crypto_box_curve25519xsalsa20poly1305_keypair(pk: *mut libc::c_uchar,
                                                     sk: *mut libc::c_uchar) -> libc::c_int;
    fn crypto_box_curve25519xsalsa20poly1305_beforenm(k: *mut libc::c_uchar,
                                                      pk: *const libc::c_uchar,
                                                      sk: *const libc::c_uchar) -> libc::c_int;
    fn crypto_box_curve25519xsalsa20poly1305_afternm(c: *mut libc::c_uchar,
                                                     m: *const libc::c_uchar,
                                                     mlen: libc::c_ulonglong,
                                                     n: *const libc::c_uchar,
                                                     k: *const libc::c_uchar) -> libc::c_int;
    fn crypto_box_curve25519xsalsa20poly1305_open_afternm(m: *mut libc::c_uchar,
                                                          c: *const libc::c_uchar,
                                                          clen: libc::c_ulonglong,
                                                          n: *const libc::c_uchar,
                                                          k: *const libc::c_uchar) -> libc::c_int;

    // sodium/crypto_core_hsalsa20.h
    fn crypto_core_hsalsa20_outputbytes() -> libc::size_t;
    fn crypto_core_hsalsa20_inputbytes() -> libc::size_t;
    fn crypto_core_hsalsa20_keybytes() -> libc::size_t;
    fn crypto_core_hsalsa20_constbytes() -> libc::size_t;
    fn crypto_core_hsalsa20(out: *mut libc::c_uchar, in_: *const libc::c_uchar,
                            k: *const libc::c_uchar, c: *const libc::c_uchar) -> libc::c_int;

    // sodium/crypto_core_salsa20.h
    fn crypto_core_salsa20_outputbytes() -> libc::size_t;
    fn crypto_core_salsa20_inputbytes() -> libc::size_t;
    fn crypto_core_salsa20_keybytes() -> libc::size_t;
    fn crypto_core_salsa20_constbytes() -> libc::size_t;
    fn crypto_core_salsa20(out: *mut libc::c_uchar, in_: *const libc::c_uchar,
                           k: *const libc::c_uchar, c: *const libc::c_uchar) -> libc::c_int;

    // sodium/crypto_core_salsa2012.h
    fn crypto_core_salsa2012_outputbytes() -> libc::size_t;
    fn crypto_core_salsa2012_inputbytes() -> libc::size_t;
    fn crypto_core_salsa2012_keybytes() -> libc::size_t;
    fn crypto_core_salsa2012_constbytes() -> libc::size_t;
    fn crypto_core_salsa2012(out: *mut libc::c_uchar, in_: *const libc::c_uchar,
                           k: *const libc::c_uchar, c: *const libc::c_uchar) -> libc::c_int;
}

// sodium/crypto_hash_sha256.h
#[repr(C)]
#[derive(Copy)]
pub struct crypto_hash_sha256_state {
    state: [libc::uint32_t; 8],
    count: [libc::uint32_t; 2],
    buf: [libc::c_uchar; 64],
}

// sodium/crypto_auth_hmacsha256.h
#[repr(C)]
#[derive(Copy)]
pub struct crypto_auth_hmacsha256_state {
    ictx: crypto_hash_sha256_state,
    octx: crypto_hash_sha256_state,
}

// sodium/crypto_hash_sha512.h
#[repr(C)]
#[derive(Copy)]
pub struct crypto_hash_sha512_state {
    state: [libc::uint64_t; 8],
    count: [libc::uint64_t; 2],
    buf: [libc::c_uchar; 128],
}

// sodium/crypto_auth_hmacsha512.h
#[repr(C)]
#[derive(Copy)]
pub struct crypto_auth_hmacsha512_state {
    ictx: crypto_hash_sha512_state,
    octx: crypto_hash_sha512_state,
}

// sodium/crypto_auth_hmacsha512256.h
pub type crypto_auth_hmacsha512256_state = crypto_auth_hmacsha512_state;

#[test]
fn test_it_work() {
    unsafe {
        sodium_init();
    }
}
