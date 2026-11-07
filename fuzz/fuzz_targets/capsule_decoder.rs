// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
#![no_main]

use bytes::{Bytes, BytesMut};
use h3wire_masque::capsule::{Decoder, Head, encode};
use libfuzzer_sys::fuzz_target;

/// Feed `bytes` in `chunk`-sized pieces. Each head is handled by `pick(head index)`:
/// 0 take, 1 peek a varint then take, 2 skip. Returns the values taken whole.
fn run(bytes: &[u8], chunk: usize, pick: impl Fn(usize) -> u8) -> (Vec<(u64, Bytes)>, bool) {
    let mut d = Decoder::default();
    let (mut cur, mut peeked, mut idx) = (None::<Head>, false, 0);
    let mut taken = Vec::new();
    let mut failed = false;
    'feed: for piece in bytes.chunks(chunk) {
        d.push(Bytes::copy_from_slice(piece));
        loop {
            let Some(h) = cur else {
                match d.next() {
                    Ok(Some(h)) => (cur, peeked, idx) = (Some(h), false, idx + 1),
                    Ok(None) => break,
                    Err(_) => {
                        failed = true;
                        break 'feed;
                    }
                }
                continue;
            };
            let mode = pick(idx);
            let step = match mode {
                2 => d.skip().map(|done| done.then(Bytes::new)),
                _ => {
                    if mode == 1 && !peeked {
                        match d.peek_varint() {
                            Ok(Some(_)) => peeked = true,
                            Ok(None) => break,
                            Err(_) => {
                                failed = true;
                                break 'feed;
                            }
                        }
                    }
                    d.take(65_535)
                }
            };
            match step {
                Ok(Some(v)) => {
                    if mode == 0 {
                        taken.push((h.ty, v));
                    }
                    cur = None;
                }
                Ok(None) => break,
                Err(_) => {
                    failed = true;
                    break 'feed;
                }
            }
        }
    }
    let _ = d.finish();
    (taken, failed)
}

// Arbitrary bytes in arbitrary splits: no panic, the result must not depend on the
// split, and what was taken must survive a re-encode and decode.
fuzz_target!(|data: &[u8]| {
    let Some((&k, bytes)) = data.split_first() else {
        return;
    };
    let pick = |i: usize| (i as u8).wrapping_add(k) % 3;
    let (whole, failed) = run(bytes, bytes.len().max(1), pick);
    let (split, failed2) = run(bytes, usize::from(k % 17).max(1), pick);
    assert_eq!((&split, failed2), (&whole, failed));
    let mut re = BytesMut::new();
    for (ty, v) in &whole {
        encode(*ty, v, &mut re).unwrap();
    }
    let (again, failed) = run(&re, re.len().max(1), |_| 0);
    assert!(!failed);
    assert_eq!(again, whole);
});
