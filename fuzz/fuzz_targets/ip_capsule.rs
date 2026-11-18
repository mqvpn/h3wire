// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
#![no_main]

use bytes::BytesMut;
use h3wire_masque::capsule::CapsuleError;
use h3wire_masque::ip::{
    ADDRESS_ASSIGN, ADDRESS_REQUEST, ROUTE_ADVERTISEMENT, RouteError, decode_address_assign,
    decode_address_request, decode_routes, encode_address_assign, encode_address_request,
    encode_routes,
};
use libfuzzer_sys::fuzz_target;

// First byte picks the capsule type (mod 3), the rest is its value. No panic; whatever
// decodes must re-encode, and decode again to the same list. The decoders take values of
// any length (the carrier bounds received capsules), the encoders refuse values over
// `MAX_CONTROL_CAPSULE`: that `TooLarge` is expected, any other encoder error is not.
fuzz_target!(|data: &[u8]| {
    let Some((&k, value)) = data.split_first() else {
        return;
    };
    let mut out = BytesMut::new();
    // Skip the 1-2 byte type and length the encoder prepends; the codecs take the value only.
    let body = |out: &BytesMut, ty: u64| -> Vec<u8> {
        assert_eq!(u64::from(out[0]), ty);
        let mut b = &out[..];
        for _ in 0..2 {
            let n = 1usize << (b[0] >> 6);
            b = &b[n..];
        }
        b.to_vec()
    };
    match k % 3 {
        0 => {
            let Ok(list) = decode_address_assign(value) else {
                return;
            };
            match encode_address_assign(&list, &mut out) {
                Err(CapsuleError::TooLarge) => return,
                r => r.unwrap(),
            }
            assert_eq!(
                decode_address_assign(&body(&out, ADDRESS_ASSIGN)).unwrap(),
                list
            );
        }
        1 => {
            let Ok(list) = decode_address_request(value) else {
                return;
            };
            match encode_address_request(&list, &mut out) {
                Err(CapsuleError::TooLarge) => return,
                r => r.unwrap(),
            }
            assert_eq!(
                decode_address_request(&body(&out, ADDRESS_REQUEST)).unwrap(),
                list
            );
        }
        _ => {
            let Ok(list) = decode_routes(value) else {
                return;
            };
            match encode_routes(&list, &mut out) {
                Err(RouteError::Capsule(CapsuleError::TooLarge)) => return,
                r => r.unwrap(),
            }
            assert_eq!(
                decode_routes(&body(&out, ROUTE_ADVERTISEMENT)).unwrap(),
                list
            );
        }
    }
});
