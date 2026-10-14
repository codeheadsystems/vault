//! The Public Suffix List compiled into the library, behind `vault_client::autofill::SuffixList`
//! (docs/android.md, Web matching). Android has no public API for the list.
//!
//! `data/public_suffix_list.dat` is the list from
//! <https://publicsuffix.org/list/public_suffix_list.dat>, fetched on 2026-10-14 (its `VERSION`
//! line reads `2026-10-07_07-28-19_UTC`), under MPL-2.0.
//! `build.rs` drops its comments; the rules are parsed at first use.

use std::collections::HashSet;
use std::sync::OnceLock;
use vault_client::autofill::SuffixList;

/// The rules of a Public Suffix List, ICANN and private sections both, with internationalised
/// rules in their ASCII form.
pub struct Rules {
    /// Rules such as `co.uk`.
    normal: HashSet<String>,
    /// The parents of wildcard rules: `ck` for `*.ck`.
    wildcard: HashSet<String>,
    /// Exception rules without their `!`: `www.ck` for `!www.ck`.
    exception: HashSet<String>,
}

impl Rules {
    /// Parses list text: one rule per line, as the first whitespace-delimited word; lines that
    /// start with `//` and empty lines are skipped. A rule whose ASCII form cannot be computed,
    /// or with a `*` anywhere but a leading `*.` label, is skipped.
    pub fn parse(text: &str) -> Rules {
        let mut r = Rules {
            normal: HashSet::new(),
            wildcard: HashSet::new(),
            exception: HashSet::new(),
        };
        for rule in text.lines().filter_map(|l| l.split_whitespace().next()) {
            if rule.starts_with("//") {
                continue;
            }
            let (set, body) = if let Some(b) = rule.strip_prefix('!') {
                (&mut r.exception, b)
            } else if let Some(b) = rule.strip_prefix("*.") {
                (&mut r.wildcard, b)
            } else {
                (&mut r.normal, rule)
            };
            if let Some(ascii) = ascii(body) {
                set.insert(ascii);
            }
        }
        r
    }

    /// The known suffix of `host` (spec, Registrable domain): an exception rule's match without
    /// its first label when one matches, and otherwise the longest match of a normal or wildcard
    /// rule. `None` when only the default `*` rule applies. `host` is lowercase ASCII without a
    /// trailing `.`.
    pub fn known_suffix(&self, host: &str) -> Option<String> {
        // The host and each sequence of its trailing labels, longest first.
        let tails: Vec<&str> = std::iter::once(host)
            .chain(host.match_indices('.').map(|(i, _)| &host[i + 1..]))
            .collect();
        if let Some(n) = tails.iter().position(|t| self.exception.contains(*t)) {
            return tails.get(n + 1).map(|t| (*t).to_owned());
        }
        tails
            .iter()
            .enumerate()
            .find(|(n, t)| {
                self.normal.contains(**t)
                    || tails.get(n + 1).is_some_and(|p| self.wildcard.contains(*p))
            })
            .map(|(_, t)| (*t).to_owned())
    }
}

impl SuffixList for Rules {
    fn known_suffix(&self, host: &str) -> Option<String> {
        Rules::known_suffix(self, host)
    }
}

/// A rule's labels in lowercase ASCII, an internationalised label in its `xn--` form.
fn ascii(rule: &str) -> Option<String> {
    if rule.is_empty() || rule.contains('*') {
        return None;
    }
    if rule.is_ascii() {
        return Some(rule.to_ascii_lowercase());
    }
    idna::domain_to_ascii(rule).ok()
}

/// The compiled-in list, parsed at first use.
pub fn list() -> &'static Rules {
    static LIST: OnceLock<Rules> = OnceLock::new();
    LIST.get_or_init(|| Rules::parse(include_str!(concat!(env!("OUT_DIR"), "/psl-rules.txt"))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ks(r: &Rules, host: &str) -> Option<String> {
        r.known_suffix(host)
    }

    #[test]
    fn normal_rules_give_the_longest_match() {
        let r = Rules::parse("// a comment\n\ncom\nuk\nco.uk   trailing words\n");
        assert_eq!(ks(&r, "a.b.example.co.uk").as_deref(), Some("co.uk"));
        assert_eq!(ks(&r, "example.uk").as_deref(), Some("uk"));
        assert_eq!(ks(&r, "co.uk").as_deref(), Some("co.uk"));
        assert_eq!(ks(&r, "www.example.com").as_deref(), Some("com"));
        assert_eq!(ks(&r, "com").as_deref(), Some("com"));
        assert_eq!(
            ks(&r, "nas.lan"),
            None,
            "the default rule gives no known suffix"
        );
        assert_eq!(ks(&r, "localhost"), None);
        assert!(!r.normal.contains("// a comment") && !r.normal.contains("trailing"));
    }

    #[test]
    fn wildcard_and_exception_rules() {
        let r = Rules::parse("*.ck\n!www.ck\n*.kawasaki.jp\n!city.kawasaki.jp\njp\n");
        assert_eq!(ks(&r, "foo.ck").as_deref(), Some("foo.ck"));
        assert_eq!(ks(&r, "a.foo.ck").as_deref(), Some("foo.ck"));
        assert_eq!(ks(&r, "www.ck").as_deref(), Some("ck"));
        assert_eq!(ks(&r, "a.www.ck").as_deref(), Some("ck"));
        assert_eq!(ks(&r, "ck"), None, "*.ck needs a label before ck");
        assert_eq!(ks(&r, "x.kawasaki.jp").as_deref(), Some("x.kawasaki.jp"));
        assert_eq!(ks(&r, "a.x.kawasaki.jp").as_deref(), Some("x.kawasaki.jp"));
        assert_eq!(ks(&r, "city.kawasaki.jp").as_deref(), Some("kawasaki.jp"));
        assert_eq!(ks(&r, "a.city.kawasaki.jp").as_deref(), Some("kawasaki.jp"));
        assert_eq!(ks(&r, "kawasaki.jp").as_deref(), Some("jp"));
    }

    #[test]
    fn internationalised_rules_match_in_punycode() {
        let r = Rules::parse("рф\n公司.cn\ncn\nBIZ\n");
        assert_eq!(
            ks(&r, "xn--80ak6aa92e.xn--p1ai").as_deref(),
            Some("xn--p1ai")
        );
        assert_eq!(ks(&r, "a.xn--55qx5d.cn").as_deref(), Some("xn--55qx5d.cn"));
        assert_eq!(ks(&r, "example.biz").as_deref(), Some("biz"));
    }

    #[test]
    fn malformed_rules_are_skipped() {
        let r = Rules::parse("a.*.b\n*\n!\n*.\n");
        assert!(r.normal.is_empty() && r.wildcard.is_empty() && r.exception.is_empty());
    }

    #[test]
    fn the_compiled_in_list() {
        let l = list();
        assert!(l.normal.len() > 9000, "{} normal rules", l.normal.len());
        assert!(l.wildcard.contains("ck") && l.exception.contains("www.ck"));
        for (host, want) in [
            ("example.com", Some("com")),
            ("a.b.example.co.uk", Some("co.uk")),
            ("user.github.io", Some("github.io")),
            ("github.io", Some("github.io")),
            ("foo.ck", Some("foo.ck")),
            ("www.ck", Some("ck")),
            ("city.kawasaki.jp", Some("kawasaki.jp")),
            ("xn--80ak6aa92e.xn--p1ai", Some("xn--p1ai")),
            ("example.xn--fiqs8s", Some("xn--fiqs8s")),
            ("nas.lan", None),
            ("localhost", None),
        ] {
            assert_eq!(ks(l, host).as_deref(), want, "{host}");
        }
    }
}
