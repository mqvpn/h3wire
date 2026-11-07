// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
#![no_main]

use h3wire_masque::template::UriTemplate;
use http::Uri;
use libfuzzer_sys::fuzz_target;

// Input: template, a NUL byte, then a request URI. No panic; whatever matches must
// re-expand to a URI that matches the same target.
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
    let (Ok(tpl), Ok(uri)) = (UriTemplate::parse(tpl), uri.parse::<Uri>()) else {
        return;
    };
    if let Ok(target) = tpl.match_target(&uri) {
        let again = tpl.expand(&target).unwrap();
        assert_eq!(tpl.match_target(&again).unwrap(), target);
    }
});
