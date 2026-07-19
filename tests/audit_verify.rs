//! Verification tests for secfinding audit findings.
//! These tests are expected to FAIL on the current codebase.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use secfinding::{Finding, FindingKind, Severity};

// FINDING 1: FindingKind::from_str never errors
#[test]
fn verify_kind_from_str_rejects_unknown() {
    let res = "totally-invalid-kind".parse::<FindingKind>();
    assert!(
        res.is_err(),
        "Unknown kind strings must be rejected, not silently mapped to Other"
    );
}

// FINDING 2: Finding::hash contract violated for signed-zero floats
#[test]
fn verify_hash_contract_for_signed_zero() {
    fn hash_finding(f: &Finding) -> u64 {
        let mut s = DefaultHasher::new();
        f.hash(&mut s);
        s.finish()
    }

    let f1 = Finding::builder("s", "t", Severity::Info)
        .title("x")
        .confidence(0.0)
        .build()
        .unwrap();

    // Round-trip through JSON so f2 has the same id as f1, differing only in confidence bits.
    let mut json = serde_json::to_string(&f1).unwrap();
    json = json.replace("0.0", "-0.0");
    let f2: Finding = serde_json::from_str(&json).unwrap();

    assert_eq!(f1.id(), f2.id(), "IDs must match after round-trip");
    assert_eq!(f1, f2, "0.0 and -0.0 confidence must be equal");
    assert_eq!(
        hash_finding(&f1),
        hash_finding(&f2),
        "Equal findings must have equal hashes"
    );
}

// FINDING 3: merge_chain silently drops references
#[test]
fn verify_merge_chain_preserves_references() {
    let a = Finding::builder("s", "t", Severity::Low)
        .title("A")
        .reference("https://ref-a.com")
        .build()
        .unwrap();
    let b = Finding::builder("s", "t", Severity::Low)
        .title("B")
        .reference("https://ref-b.com")
        .build()
        .unwrap();

    let merged = Finding::merge_chain(&a, &b).unwrap();
    let refs: Vec<&str> = merged.references().iter().map(|r| r.as_ref()).collect();
    assert!(refs.contains(&"https://ref-a.com"));
    assert!(refs.contains(&"https://ref-b.com"));
}

// FINDING 4: merge_chain silently drops cvss_score and confidence
#[test]
fn verify_merge_chain_preserves_cvss_and_confidence() {
    let a = Finding::builder("s", "t", Severity::Low)
        .title("A")
        .cvss_score(7.5)
        .confidence(0.8)
        .build()
        .unwrap();
    let b = Finding::builder("s", "t", Severity::Low)
        .title("B")
        .build()
        .unwrap();

    let merged = Finding::merge_chain(&a, &b).unwrap();
    assert_eq!(
        merged.cvss_score(),
        Some(7.5),
        "CVSS score must be preserved in merge"
    );
    assert_eq!(
        merged.confidence(),
        Some(0.8),
        "Confidence must be preserved in merge"
    );
}

// FINDING 5: builder fails to deduplicate references
#[test]
fn verify_builder_deduplicates_references() {
    let f = Finding::builder("s", "t", Severity::Info)
        .title("x")
        .reference("https://example.com")
        .reference("https://example.com")
        .build()
        .unwrap();
    assert_eq!(
        f.references().len(),
        1,
        "Duplicate references must be deduplicated"
    );
}

// FINDING 6: CVSS score clamps out-of-range values instead of rejecting
#[test]
fn verify_cvss_rejects_out_of_range() {
    let res = Finding::builder("s", "t", Severity::Info)
        .title("x")
        .cvss_score(15.0)
        .build();
    assert!(
        res.is_err(),
        "CVSS score above 10.0 must be rejected, not clamped"
    );
}

// FINDING 7: confidence clamps out-of-range values instead of rejecting
#[test]
fn verify_confidence_rejects_out_of_range() {
    let res = Finding::builder("s", "t", Severity::Info)
        .title("x")
        .confidence(1.5)
        .build();
    assert!(
        res.is_err(),
        "Confidence above 1.0 must be rejected, not clamped"
    );
}

// FINDING 8: deserialization accepts arbitrary format version
#[test]
fn verify_deserialization_rejects_unknown_version() {
    let json = r#"{"version":999,"scanner":"s","target":"t","severity":"high","title":"x"}"#;
    let res: Result<Finding, _> = serde_json::from_str(json);
    assert!(
        res.is_err(),
        "Unknown format versions must be rejected during deserialization"
    );
}

// FINDING 9: bridge::to_universal duplicates matched_values
#[cfg(feature = "secir")]
#[test]
fn verify_bridge_no_duplicate_matched_values() {
    let mut ir = secir::finding::Finding::new(
        "xss".to_string(),
        "XSS".to_string(),
        "https://example.com".to_string(),
        secir::Severity::High,
        "https://example.com/search".to_string(),
    );
    ir.matched_values = vec!["<script>".to_string()];

    let finding = secfinding::bridge::to_universal(&ir, "calyx").unwrap();
    assert_eq!(
        finding.matched_values().len(),
        1,
        "bridge must not duplicate matched_values"
    );
}
