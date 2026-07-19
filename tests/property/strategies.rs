//! Shared proptest strategies (printable ASCII only (no NUL bytes)).

use proptest::prelude::*;

/// Reject strings that contain a NUL byte (Finding/target validation rejects them).
pub fn no_nul(s: String) -> bool {
    !s.contains('\0')
}

pub fn arb_scanner() -> impl Strategy<Value = String> {
    "[a-zA-Z][a-zA-Z0-9_-]{0,24}".prop_filter("scanner has no NUL", |s| no_nul(s.clone()))
}

pub fn arb_target() -> impl Strategy<Value = String> {
    "https://[a-z0-9.-]{1,48}/[a-zA-Z0-9/_-]{0,64}"
        .prop_filter("target has no NUL", |s| no_nul(s.clone()))
}

pub fn arb_tag() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_-]{0,32}".prop_filter("tag has no NUL", |s| no_nul(s.clone()))
}

pub fn arb_title() -> impl Strategy<Value = String> {
    "[\x20-\x7e]{1,120}".prop_filter("title has no NUL", |s| no_nul(s.clone()))
}

pub fn arb_detail() -> impl Strategy<Value = String> {
    "[\x20-\x7e]{0,200}".prop_filter("detail has no NUL", |s| no_nul(s.clone()))
}

pub fn arb_printable(max_len: usize) -> impl Strategy<Value = String> {
    // \x20-\x7e excludes NUL; dynamic length via string_regex (prop_filter on regex breaks Sized).
    let pattern = format!("[\\x20-\\x7e]{{0,{max_len}}}");
    prop::string::string_regex(&pattern).expect("printable ASCII regex")
}

pub fn arb_evidence_text() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 _./:-]{0,48}".prop_filter("evidence text has no NUL", |s| no_nul(s.clone()))
}
