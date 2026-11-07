// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The RFC 9298 §2 URI template subset (design spec §2.2).
//!
//! Absolute `https` templates; RFC 6570 Level 1 `{target_host}` and `{target_port}`, each
//! exactly once, each a whole path segment. A literal query is allowed and must match
//! exactly; variables are not allowed there or in the authority.

use http::Uri;
use http::uri::Authority;
use std::fmt::Write;
use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU16;
use std::str::FromStr;

/// Why a template or a match failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TemplateError {
    /// Not a valid URI template, or an expression other than `{name}`.
    Syntax,
    /// The scheme is not `https`.
    NotHttps,
    /// Not exactly one `target_host` and one `target_port` in the path.
    Variables,
    /// A variable shares its path segment with other text.
    NotWholeSegment,
    /// The host is empty, malformed, a zone-id IPv6 literal, or a bad percent escape.
    BadHost,
    /// The port is not 1-65535 decimal digits, or has a bad percent escape.
    BadPort,
    /// The URI's path or query does not fit the template.
    NoMatch,
}

impl std::fmt::Display for TemplateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Syntax => "invalid URI template",
            Self::NotHttps => "URI template scheme is not https",
            Self::Variables => "URI template needs one target_host and one target_port",
            Self::NotWholeSegment => "URI template variable is not a whole path segment",
            Self::BadHost => "invalid target host",
            Self::BadPort => "invalid target port",
            Self::NoMatch => "URI does not match the template",
        })
    }
}

impl std::error::Error for TemplateError {}

/// A CONNECT-UDP target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Host.
    pub host: TargetHost,
    /// Port.
    pub port: NonZeroU16,
}

impl Target {
    /// A target.
    pub fn new(host: TargetHost, port: NonZeroU16) -> Self {
        Self { host, port }
    }
}

/// A target host: an IP literal or a DNS name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetHost {
    /// A DNS name. One that parses as an IP literal matches back as [`TargetHost::Ip`].
    /// Checked here: non-empty, no `:`, no leading `[`, and (when matched) valid UTF-8
    /// after percent-decoding. Any further name policy is the application's (RFC 9298
    /// section 3.1).
    Name(String),
    /// An IP address.
    Ip(IpAddr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Seg {
    Lit(String),
    Host,
    Port,
}

/// A parsed template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriTemplate {
    authority: String,
    segs: Vec<Seg>,
    query: Option<String>,
}

impl UriTemplate {
    /// Parse a template of the documented subset.
    pub fn parse(s: &str) -> Result<Self, TemplateError> {
        // RFC 9298 section 2: printable ASCII only (other text must be percent-encoded).
        if s.contains('#') || !s.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(TemplateError::Syntax);
        }
        let rest = match s.split_at_checked(8) {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("https://") => rest,
            _ if s
                .get(..7)
                .is_some_and(|p| p.eq_ignore_ascii_case("http://")) =>
            {
                return Err(TemplateError::NotHttps);
            }
            _ => return Err(TemplateError::Syntax),
        };
        let (authority, rest) = rest.split_once('/').ok_or(TemplateError::Syntax)?;
        if authority.contains(['{', '}']) {
            return Err(TemplateError::Variables);
        }
        if !literal(authority) {
            return Err(TemplateError::Syntax);
        }
        Authority::from_str(authority).map_err(|_| TemplateError::Syntax)?;
        let (path, query) = match rest.split_once('?') {
            Some((p, q)) => (p, Some(q.to_owned())),
            None => (rest, None),
        };
        if query.as_deref().is_some_and(|q| q.contains(['{', '}'])) {
            return Err(TemplateError::Variables);
        }
        if query.as_deref().is_some_and(|q| !literal(q)) {
            return Err(TemplateError::Syntax);
        }
        let (mut hosts, mut ports) = (0, 0);
        let mut segs = Vec::new();
        for seg in path.split('/') {
            segs.push(match seg {
                "{target_host}" => {
                    hosts += 1;
                    Seg::Host
                }
                "{target_port}" => {
                    ports += 1;
                    Seg::Port
                }
                _ if seg.contains("{target_host}") || seg.contains("{target_port}") => {
                    return Err(TemplateError::NotWholeSegment);
                }
                _ if seg.contains(['{', '}']) => {
                    let inner = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}'));
                    let name = inner.is_some_and(|n| {
                        !n.is_empty() && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    });
                    return Err(if name {
                        TemplateError::Variables
                    } else {
                        TemplateError::Syntax
                    });
                }
                _ if !literal(seg) => return Err(TemplateError::Syntax),
                _ => Seg::Lit(seg.to_owned()),
            });
        }
        if hosts != 1 || ports != 1 {
            return Err(TemplateError::Variables);
        }
        let t = Self {
            authority: authority.to_owned(),
            segs,
            query,
        };
        // Literals and authority must form a valid URI once the variables are filled in.
        t.build("x", "1").map_err(|_| TemplateError::Syntax)?;
        Ok(t)
    }

    /// `https://{authority}/.well-known/masque/udp/{target_host}/{target_port}/`.
    pub fn default_for(authority: &Authority) -> Self {
        Self {
            authority: authority.as_str().to_owned(),
            segs: [".well-known", "masque", "udp"]
                .map(|s| Seg::Lit(s.into()))
                .into_iter()
                .chain([Seg::Host, Seg::Port, Seg::Lit(String::new())])
                .collect(),
            query: None,
        }
    }

    fn build(&self, host: &str, port: &str) -> Result<Uri, TemplateError> {
        let mut s = format!("https://{}", self.authority);
        for seg in &self.segs {
            s.push('/');
            s.push_str(match seg {
                Seg::Lit(l) => l,
                Seg::Host => host,
                Seg::Port => port,
            });
        }
        if let Some(q) = &self.query {
            s.push('?');
            s.push_str(q);
        }
        Uri::from_str(&s).map_err(|_| TemplateError::Syntax)
    }

    /// The request URI for `target`. Values are percent-encoded outside RFC 3986 unreserved.
    pub fn expand(&self, target: &Target) -> Result<Uri, TemplateError> {
        let host = match &target.host {
            TargetHost::Name(n) if n.is_empty() || n.contains(':') || n.starts_with('[') => {
                return Err(TemplateError::BadHost);
            }
            TargetHost::Name(n) => encode(n),
            TargetHost::Ip(ip) => encode(&ip.to_string()),
        };
        self.build(&host, &target.port.to_string())
    }

    /// The target in `uri`'s path and query. The scheme and authority are not compared
    /// (spec §2.2). A malformed percent escape is `BadHost`/`BadPort`, not `NoMatch`.
    ///
    /// Literal segments are compared byte for byte, with no percent-decoding normalisation.
    pub fn match_target(&self, uri: &Uri) -> Result<Target, TemplateError> {
        if uri.query() != self.query.as_deref() {
            return Err(TemplateError::NoMatch);
        }
        let path = uri.path().strip_prefix('/').ok_or(TemplateError::NoMatch)?;
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() != self.segs.len() {
            return Err(TemplateError::NoMatch);
        }
        let (mut host, mut port) = (None, None);
        for (seg, part) in self.segs.iter().zip(parts) {
            match seg {
                Seg::Lit(l) if l == part => {}
                Seg::Lit(_) => return Err(TemplateError::NoMatch),
                Seg::Host => host = Some(part),
                Seg::Port => port = Some(part),
            }
        }
        let (host, port) = (
            host.ok_or(TemplateError::NoMatch)?,
            port.ok_or(TemplateError::NoMatch)?,
        );
        Ok(Target::new(parse_host(host)?, parse_port(port)?))
    }
}

/// RFC 6570 section 2.1 literals (in printable ASCII, already checked): no double or
/// single quote, angle bracket, backslash, caret, backtick, bar or brace, and `%` only
/// as a two-hex-digit escape.
fn literal(s: &str) -> bool {
    let b = s.as_bytes();
    b.iter().enumerate().all(|(i, &c)| match c {
        b'%' => b
            .get(i + 1..i + 3)
            .is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit)),
        _ => !b"\"'<>\\^`{|}".contains(&c),
    })
}

fn parse_host(s: &str) -> Result<TargetHost, TemplateError> {
    let d = decode(s).ok_or(TemplateError::BadHost)?;
    if d.is_empty() {
        return Err(TemplateError::BadHost);
    }
    if let Some(inner) = d.strip_prefix('[') {
        let v6 = inner
            .strip_suffix(']')
            .and_then(|i| Ipv6Addr::from_str(i).ok());
        return v6
            .map(|a| TargetHost::Ip(a.into()))
            .ok_or(TemplateError::BadHost);
    }
    if let Ok(ip) = IpAddr::from_str(&d) {
        return Ok(TargetHost::Ip(ip));
    }
    // A colon is an IPv6 literal that failed to parse, e.g. with a zone id.
    if d.contains(':') {
        return Err(TemplateError::BadHost);
    }
    Ok(TargetHost::Name(d))
}

fn parse_port(s: &str) -> Result<NonZeroU16, TemplateError> {
    let d = decode(s).ok_or(TemplateError::BadPort)?;
    if d.is_empty() || !d.bytes().all(|b| b.is_ascii_digit()) {
        return Err(TemplateError::BadPort);
    }
    d.parse::<u16>()
        .ok()
        .and_then(NonZeroU16::new)
        .ok_or(TemplateError::BadPort)
}

fn encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Strict percent-decoding to UTF-8; `None` on a malformed escape or invalid UTF-8.
fn decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            if !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const DEFAULT: &str =
        "https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/";

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    fn tpl() -> UriTemplate {
        UriTemplate::parse(DEFAULT).unwrap()
    }

    #[test]
    fn parse_accepts_default() {
        let a: Authority = "proxy.example:8443".parse().unwrap();
        let t = UriTemplate::default_for(&a);
        assert_eq!(
            UriTemplate::parse(
                "https://proxy.example:8443/.well-known/masque/udp/{target_host}/{target_port}/"
            )
            .unwrap(),
            t
        );
        tpl();
        UriTemplate::parse("HTTPS://p/{target_host}/{target_port}/").unwrap();
        UriTemplate::parse("https://p/{target_port}/x/{target_host}?k=v").unwrap();
    }

    #[test]
    fn parse_rejects() {
        use TemplateError::*;
        let p = |s: &str| UriTemplate::parse(s).unwrap_err();
        assert_eq!(p("http://p/{target_host}/{target_port}/"), NotHttps);
        assert_eq!(p("/{target_host}/{target_port}/"), Syntax);
        assert_eq!(p("https://p"), Syntax);
        assert_eq!(p("https://p/{+target_host}/{target_port}/"), Syntax);
        assert_eq!(p("https://p/{target_host/{target_port}/"), Syntax);
        // The `?` splits the template there, so the braces land in the query.
        assert_eq!(p("https://p/{?x}/{target_host}/{target_port}"), Variables);
        assert_eq!(p("https://p/{target_host}/{target_port}?a#b"), Syntax);
        assert_eq!(p("https://p/{target_host}/{target_port}/x#y"), Syntax);
        assert_eq!(p("Http://p/{target_host}/{target_port}/"), NotHttps);
        assert_eq!(p("https://p/{target_host}/"), Variables);
        assert_eq!(p("https://p/{target_port}/"), Variables);
        assert_eq!(
            p("https://p/{target_host}/{target_host}/{target_port}"),
            Variables
        );
        assert_eq!(
            p("https://p/{target_host}/{target_port}/{other}"),
            Variables
        );
        assert_eq!(
            p("https://{target_host}/{target_host}/{target_port}"),
            Variables
        );
        assert_eq!(
            p("https://p/{target_host}/{target_port}?h={target_host}"),
            Variables
        );
        assert_eq!(
            p("https://p/x{target_host}/{target_port}/"),
            NotWholeSegment
        );
        assert_eq!(p("https://p/{target_host}1{target_port}/"), NotWholeSegment);
        // RFC 9298 section 2: ASCII 0x21-0x7E only; percent-encoded literals are fine.
        assert_eq!(
            p("https://proxy/\u{e9}/{target_host}/{target_port}/"),
            Syntax
        );
        assert_eq!(p("https://proxy/a b/{target_host}/{target_port}/"), Syntax);
        assert!(UriTemplate::parse("https://proxy/%C3%A9/{target_host}/{target_port}/").is_ok());
        // The authority ends at the first `/`: a query before it is not an authority.
        assert_eq!(p("https://proxy?x=/{target_host}/{target_port}/"), Syntax);
        // Authority literals follow the same rules.
        assert_eq!(
            p("https://bad%zz@127.0.0.1/{target_host}/{target_port}/"),
            Syntax
        );
        assert_eq!(p("https://pro'xy/{target_host}/{target_port}/"), Syntax);
        // RFC 6570 section 2.1 literals, in the path and the query.
        for bad in [
            "%zz", "%4", "a|b", "a^b", "a\\b", "a<b", "a\"b", "a'b", "a`b",
        ] {
            assert_eq!(
                p(&format!("https://p/{bad}/{{target_host}}/{{target_port}}/")),
                Syntax
            );
            assert_eq!(
                p(&format!(
                    "https://p/{{target_host}}/{{target_port}}/?q={bad}"
                )),
                Syntax
            );
        }
        assert!(UriTemplate::parse("https://p/{target_host}/{target_port}/?q=%C3%A9").is_ok());
    }

    #[test]
    fn expand_percent_encodes() {
        let ip = |s: &str| Target::new(TargetHost::Ip(s.parse().unwrap()), 443.try_into().unwrap());
        assert_eq!(
            tpl().expand(&ip("2001:db8::1")).unwrap().path(),
            "/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/"
        );
        let name = Target::new(TargetHost::Name("a%b/c d".into()), 1.try_into().unwrap());
        assert_eq!(
            tpl().expand(&name).unwrap().path(),
            "/.well-known/masque/udp/a%25b%2Fc%20d/1/"
        );
        let bad = Target::new(TargetHost::Name(String::new()), 1.try_into().unwrap());
        assert_eq!(tpl().expand(&bad), Err(TemplateError::BadHost));
    }

    fn arb_target() -> impl Strategy<Value = Target> {
        let host = prop_oneof![
            any::<std::net::Ipv4Addr>().prop_map(|a| TargetHost::Ip(a.into())),
            any::<Ipv6Addr>().prop_map(|a| TargetHost::Ip(a.into())),
            "[^:\\[][^:]{0,19}"
                .prop_filter("an IP literal", |n| IpAddr::from_str(n).is_err())
                .prop_map(TargetHost::Name),
        ];
        (host, 1..=u16::MAX).prop_map(|(h, p)| Target::new(h, NonZeroU16::new(p).unwrap()))
    }

    proptest! {
        #[test]
        fn match_round_trip(t in arb_target()) {
            let u = tpl().expand(&t).unwrap();
            prop_assert_eq!(tpl().match_target(&u).unwrap(), t);
        }
    }

    #[test]
    fn match_rejects() {
        use TemplateError::*;
        let m = |p: &str| tpl().match_target(&uri(p)).unwrap_err();
        let base = "/.well-known/masque/udp";
        assert_eq!(m(&format!("{base}/h/0/")), BadPort);
        assert_eq!(m(&format!("{base}/h/65536/")), BadPort);
        assert_eq!(m(&format!("{base}/h/+80/")), BadPort);
        assert_eq!(m(&format!("{base}/h/%3/")), BadPort);
        assert_eq!(m(&format!("{base}//80/")), BadHost);
        assert_eq!(m(&format!("{base}/fe80%3A%3A1%25eth0/80/")), BadHost);
        assert_eq!(m(&format!("{base}/h%zz/80/")), BadHost);
        assert_eq!(m(&format!("{base}/%5Bfe80%3A%3A1/80/")), BadHost);
        assert_eq!(m(&format!("{base}x/h/80/")), NoMatch);
        assert_eq!(m(&format!("{base}/h/80")), NoMatch);
        assert_eq!(m(&format!("{base}/h/80/?a=b")), NoMatch);
        assert_eq!(m("/"), NoMatch);
    }

    #[test]
    fn match_literal_query_and_brackets() {
        let t = UriTemplate::parse("https://p/{target_host}/{target_port}?k=v").unwrap();
        assert!(t.match_target(&uri("/h/80?k=v")).is_ok());
        assert_eq!(t.match_target(&uri("/h/80")), Err(TemplateError::NoMatch));
        assert_eq!(
            tpl()
                .match_target(&uri("/.well-known/masque/udp/%5B%3A%3A1%5D/80/"))
                .unwrap()
                .host,
            TargetHost::Ip("::1".parse().unwrap())
        );
    }

    #[test]
    fn match_ignores_authority() {
        let want = tpl()
            .match_target(&uri("/.well-known/masque/udp/h/80/"))
            .unwrap();
        for u in [
            "https://other.example/.well-known/masque/udp/h/80/",
            "https://proxy.example:443/.well-known/masque/udp/h/80/",
        ] {
            assert_eq!(tpl().match_target(&uri(u)).unwrap(), want);
        }
    }
}
