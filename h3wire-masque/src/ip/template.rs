// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 mp0rta
//! The CONNECT-IP URI template (RFC 9484 section 3): `{target}` and `{ipproto}`.

use super::IpPrefix;
use crate::template::{Core, TemplateError, decode, encode};
use http::Uri;
use http::uri::Authority;
use std::net::IpAddr;
use std::str::FromStr;

/// A CONNECT-IP URI template: RFC 6570 Level 1 `{target}` and `{ipproto}`, each at most once and
/// each a whole path segment. A variable the template lacks is a wildcard: it expands only
/// `*` and matches any request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpTemplate(Core);

const VARS: [&str; 2] = ["target", "ipproto"];

/// What a CONNECT-IP request is scoped to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// The target.
    pub target: ScopeTarget,
    /// The IP protocol number, or `None` for any.
    pub ipproto: Option<u8>,
}

impl Scope {
    /// Any target, any protocol.
    pub const ANY: Scope = Scope {
        target: ScopeTarget::Any,
        ipproto: None,
    };
}

/// The `target` of a [`Scope`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopeTarget {
    /// Any target (`*`).
    Any,
    /// An IP address or prefix.
    Prefix(IpPrefix),
    /// A host name.
    Host(String),
}

impl IpTemplate {
    /// Parse a template of the documented subset.
    pub fn parse(s: &str) -> Result<Self, TemplateError> {
        Core::parse(s, &VARS).map(Self)
    }

    /// `https://{authority}/.well-known/masque/ip/{target}/{ipproto}/`.
    pub fn default_for(authority: &Authority) -> Self {
        Self(Core::default_for(
            authority,
            &[".well-known", "masque", "ip"],
            &VARS,
        ))
    }

    /// The request URI for `scope`. Values are percent-encoded outside RFC 3986 unreserved.
    /// A scope that is not a wildcard in a variable the template lacks is `Variables`.
    pub fn expand(&self, scope: &Scope) -> Result<Uri, TemplateError> {
        let target = match &scope.target {
            ScopeTarget::Any => "*".to_owned(),
            ScopeTarget::Prefix(p) => {
                let full = if p.addr().is_ipv4() { 32 } else { 128 };
                if p.prefix_len() == full {
                    encode(&p.addr().to_string())
                } else {
                    encode(&format!("{}/{}", p.addr(), p.prefix_len()))
                }
            }
            ScopeTarget::Host(h) => {
                if h == "*" || IpAddr::from_str(h).is_ok() || !reg_name(h) {
                    return Err(TemplateError::BadTarget);
                }
                encode(h)
            }
        };
        let ipproto = scope.ipproto.map_or("*".to_owned(), |n| n.to_string());
        let wild = |name: &str, any: bool| self.0.has(name) || any;
        if !wild("target", scope.target == ScopeTarget::Any)
            || !wild("ipproto", scope.ipproto.is_none())
        {
            return Err(TemplateError::Variables);
        }
        self.0.build(&[("target", &target), ("ipproto", &ipproto)])
    }

    /// The scope in `uri`'s path and query. The scheme and authority are not compared. A
    /// malformed or unacceptable value is `BadTarget` / `BadProto`, not `NoMatch`.
    pub fn match_scope(&self, uri: &Uri) -> Result<Scope, TemplateError> {
        let mut scope = Scope::ANY;
        for (name, raw) in self.0.captures(uri)? {
            match name {
                "target" => scope.target = parse_target(raw)?,
                _ => scope.ipproto = parse_ipproto(raw)?,
            }
        }
        Ok(scope)
    }
}

/// RFC 3986 `reg-name` without escapes: unreserved or sub-delims only. Internationalised names
/// are sent as A-labels.
fn reg_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&b))
}

fn parse_target(raw: &str) -> Result<ScopeTarget, TemplateError> {
    use TemplateError::BadTarget;
    if raw.is_empty() || raw.contains(':') {
        return Err(BadTarget);
    }
    let d = decode(raw).ok_or(BadTarget)?;
    if d == "*" {
        return Ok(ScopeTarget::Any);
    }
    if let Some((addr, len)) = d.split_once('/') {
        let addr = IpAddr::from_str(addr).map_err(|_| BadTarget)?;
        let max = if addr.is_ipv4() { 2 } else { 3 };
        if !(1..=max).contains(&len.len()) || !len.bytes().all(|b| b.is_ascii_digit()) {
            return Err(BadTarget);
        }
        let len = len.parse().map_err(|_| BadTarget)?;
        return IpPrefix::new(addr, len)
            .map(ScopeTarget::Prefix)
            .map_err(|_| BadTarget);
    }
    if let Ok(addr) = IpAddr::from_str(&d) {
        return Ok(ScopeTarget::Prefix(IpPrefix::host(addr)));
    }
    // A colon that is not an IPv6 address is a zone id or garbage; `:` is not a reg-name char.
    if reg_name(&d) {
        Ok(ScopeTarget::Host(d))
    } else {
        Err(BadTarget)
    }
}

fn parse_ipproto(raw: &str) -> Result<Option<u8>, TemplateError> {
    use TemplateError::BadProto;
    if raw.is_empty() {
        return Err(BadProto);
    }
    let d = decode(raw).ok_or(BadProto)?;
    if d == "*" {
        return Ok(None);
    }
    if d.len() > 3 || !d.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BadProto);
    }
    d.parse().map(Some).map_err(|_| BadProto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const DEFAULT: &str = "https://proxy.example/.well-known/masque/ip/{target}/{ipproto}/";

    fn tpl() -> IpTemplate {
        IpTemplate::parse(DEFAULT).unwrap()
    }

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    fn pfx(s: &str, len: u8) -> ScopeTarget {
        ScopeTarget::Prefix(IpPrefix::new(s.parse().unwrap(), len).unwrap())
    }

    fn scope(target: ScopeTarget, ipproto: Option<u8>) -> Scope {
        Scope { target, ipproto }
    }

    #[test]
    fn parse_accepts() {
        let a: Authority = "proxy.example".parse().unwrap();
        assert_eq!(IpTemplate::default_for(&a), tpl());
        IpTemplate::parse("https://proxy:443/vpn").unwrap();
        IpTemplate::parse("https://p/{target}/").unwrap();
        IpTemplate::parse("https://p/x/{ipproto}").unwrap();
        IpTemplate::parse("https://p/{target}/{ipproto}?k=v").unwrap();
    }

    #[test]
    fn parse_rejects() {
        use TemplateError::*;
        let p = |s: &str| IpTemplate::parse(s).unwrap_err();
        assert_eq!(p("https://p/{target}/{target}/"), Variables);
        assert_eq!(p("https://p/{ipproto}/{ipproto}/"), Variables);
        assert_eq!(p("https://p/{target_host}/{target}/"), Variables);
        assert_eq!(p("https://p/{target}/?x={ipproto}"), Variables);
        assert_eq!(p("https://p/x{target}/"), NotWholeSegment);
        assert_eq!(p("http://p/{target}/"), NotHttps);
    }

    #[test]
    fn expand_forms() {
        let t = tpl();
        let path = |s: &Scope| t.expand(s).unwrap().to_string();
        let base = "https://proxy.example/.well-known/masque/ip";
        assert_eq!(path(&Scope::ANY), format!("{base}/*/*/"));
        assert_eq!(
            path(&scope(pfx("192.0.2.0", 24), None)),
            format!("{base}/192.0.2.0%2F24/*/")
        );
        assert_eq!(
            path(&scope(pfx("192.0.2.1", 32), None)),
            format!("{base}/192.0.2.1/*/")
        );
        assert_eq!(
            path(&scope(pfx("2001:db8::", 32), None)),
            format!("{base}/2001%3Adb8%3A%3A%2F32/*/")
        );
        assert_eq!(
            path(&scope(ScopeTarget::Host("example.com".into()), None)),
            format!("{base}/example.com/*/")
        );
        assert_eq!(
            path(&scope(ScopeTarget::Any, Some(17))),
            format!("{base}/*/17/")
        );
    }

    #[test]
    fn expand_needs_variable() {
        let t = IpTemplate::parse("https://p/vpn").unwrap();
        assert_eq!(
            t.expand(&scope(pfx("192.0.2.0", 24), None)),
            Err(TemplateError::Variables)
        );
        assert_eq!(
            t.expand(&scope(ScopeTarget::Any, Some(6))),
            Err(TemplateError::Variables)
        );
        assert_eq!(t.expand(&Scope::ANY).unwrap().to_string(), "https://p/vpn");
    }

    #[test]
    fn expand_rejects_bad_host() {
        for h in [
            "",
            "*",
            "a:b",
            "a/b",
            "192.0.2.1",
            "::1",
            "a b",
            "a@b",
            "\u{e9}",
        ] {
            assert_eq!(
                tpl().expand(&scope(ScopeTarget::Host(h.into()), None)),
                Err(TemplateError::BadTarget),
                "{h:?}"
            );
        }
    }

    #[test]
    fn match_rejects() {
        use TemplateError::*;
        let base = "/.well-known/masque/ip";
        let m = |t: &str, p: &str| tpl().match_scope(&uri(&format!("{base}/{t}/{p}/")));
        for t in [
            "2001:db8::1",
            "",
            "192.0.2.0%2F240",
            "192.0.2.0%2F33",
            "192.0.2.1%2F24",
            "2001%3Adb8%3A%3A%2F1280",
            "fe80%3A%3A1%25eth0",
            "a@b",
            "a%40b",
            "a%20b",
            "%C3%A9.example",
            "%zz",
        ] {
            assert_eq!(m(t, "*"), Err(BadTarget), "target {t:?}");
        }
        for p in ["", "256", "0017", "tcp", "-1", "%zz"] {
            assert_eq!(m("*", p), Err(BadProto), "proto {p:?}");
        }
    }

    #[test]
    fn match_forms() {
        let m = |p: &str| tpl().match_scope(&uri(p)).unwrap();
        let base = "/.well-known/masque/ip";
        assert_eq!(m(&format!("{base}/*/*/")), Scope::ANY);
        assert_eq!(
            m(&format!("{base}/192.0.2.0%2F24/17/")),
            scope(pfx("192.0.2.0", 24), Some(17))
        );
        assert_eq!(
            m(&format!("{base}/192.0.2.1/*/")),
            scope(pfx("192.0.2.1", 32), None)
        );
        assert_eq!(
            m(&format!("{base}/example.com/*/")).target,
            ScopeTarget::Host("example.com".into())
        );
    }

    #[test]
    fn match_missing_variable_is_wildcard() {
        let t = IpTemplate::parse("https://p/vpn/{ipproto}").unwrap();
        assert_eq!(
            t.match_scope(&uri("/vpn/6")).unwrap(),
            scope(ScopeTarget::Any, Some(6))
        );
        let t = IpTemplate::parse("https://p/{target}/vpn").unwrap();
        assert_eq!(t.match_scope(&uri("/*/vpn")).unwrap(), Scope::ANY);
        let t = IpTemplate::parse("https://p/vpn").unwrap();
        assert_eq!(t.match_scope(&uri("/vpn")).unwrap(), Scope::ANY);
    }

    #[test]
    fn match_path_mismatch() {
        assert_eq!(
            tpl().match_scope(&uri("/nope/*/*/")),
            Err(TemplateError::NoMatch)
        );
        assert_eq!(
            tpl().match_scope(&uri("/.well-known/masque/ip/*/")),
            Err(TemplateError::NoMatch)
        );
    }

    fn arb_scope() -> impl Strategy<Value = Scope> {
        let prefix = prop_oneof![
            (any::<std::net::Ipv4Addr>(), 0..=32u8).prop_filter_map("host bits", |(a, l)| {
                IpPrefix::new(IpAddr::V4(a), l).ok()
            }),
            (any::<std::net::Ipv6Addr>(), 0..=128u8).prop_filter_map("host bits", |(a, l)| {
                IpPrefix::new(IpAddr::V6(a), l).ok()
            }),
            any::<IpAddr>().prop_map(IpPrefix::host),
        ];
        let host = "[A-Za-z0-9._~!$&'()*+,;=-]{1,20}".prop_filter("an IP address or *", |h| {
            h != "*" && IpAddr::from_str(h).is_err()
        });
        let target = prop_oneof![
            Just(ScopeTarget::Any),
            prefix.prop_map(ScopeTarget::Prefix),
            host.prop_map(ScopeTarget::Host),
        ];
        (target, any::<Option<u8>>()).prop_map(|(target, ipproto)| Scope { target, ipproto })
    }

    proptest! {
        #[test]
        fn scope_round_trip(s in arb_scope()) {
            let t = tpl();
            let u = t.expand(&s).unwrap();
            prop_assert_eq!(t.match_scope(&u).unwrap(), s);
        }
    }
}
