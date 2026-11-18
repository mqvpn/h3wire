// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
#![no_main]

use h3wire_masque::ip::IpTemplate;
use http::Uri;
use libfuzzer_sys::fuzz_target;

// Input: template, a NUL byte, then a request URI. No panic; whatever matches must
// expand, and the expansion must match back to the same scope.
fuzz_target!(|data: &[u8]| {
    let Some(i) = data.iter().position(|&b| b == 0) else {
        return;
    };
    let (Ok(tpl), Ok(uri)) = (
        std::str::from_utf8(&data[..i]),
        std::str::from_utf8(&data[i + 1..]),
    ) else {
        return;
    };
    let (Ok(tpl), Ok(uri)) = (IpTemplate::parse(tpl), uri.parse::<Uri>()) else {
        return;
    };
    let Ok(scope) = tpl.match_scope(&uri) else {
        return;
    };
    let again = tpl.expand(&scope).unwrap();
    assert_eq!(tpl.match_scope(&again).unwrap(), scope);
});
