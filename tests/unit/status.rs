use secfinding::FindingStatus;

#[test]
fn finding_status_default_is_open() {
    assert_eq!(FindingStatus::default(), FindingStatus::Open);
}

#[test]
fn finding_status_display() {
    assert_eq!(FindingStatus::Open.to_string(), "open");
    assert_eq!(FindingStatus::Resolved.to_string(), "resolved");
}

#[test]
fn finding_status_label() {
    assert_eq!(FindingStatus::Open.label(), "OPEN");
    assert_eq!(FindingStatus::Resolved.label(), "FIXD");
}

// Ported from the previously dead tests/unit/test_status.rs (orphaned behind an
// unwired tests/unit/mod.rs). Covers all four variants across label/serde/Copy/Eq.
#[test]
fn finding_status_labels() {
    assert_eq!(FindingStatus::Open.label(), "OPEN");
    assert_eq!(FindingStatus::Confirmed.label(), "CONF");
    assert_eq!(FindingStatus::FalsePositive.label(), "F/P");
    assert_eq!(FindingStatus::Resolved.label(), "FIXD");
}

#[test]
fn finding_status_serde_roundtrip() {
    for status in [
        FindingStatus::Open,
        FindingStatus::Confirmed,
        FindingStatus::FalsePositive,
        FindingStatus::Resolved,
    ] {
        let json = serde_json::to_string(&status).unwrap();
        let back: FindingStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }
}

#[test]
fn finding_status_serde_snake_case() {
    let open: FindingStatus = serde_json::from_str("\"open\"").unwrap();
    assert_eq!(open, FindingStatus::Open);

    let confirmed: FindingStatus = serde_json::from_str("\"confirmed\"").unwrap();
    assert_eq!(confirmed, FindingStatus::Confirmed);

    let fp: FindingStatus = serde_json::from_str("\"false_positive\"").unwrap();
    assert_eq!(fp, FindingStatus::FalsePositive);

    let resolved: FindingStatus = serde_json::from_str("\"resolved\"").unwrap();
    assert_eq!(resolved, FindingStatus::Resolved);
}

#[test]
fn finding_status_equality() {
    assert_eq!(FindingStatus::Open, FindingStatus::Open);
    assert_ne!(FindingStatus::Open, FindingStatus::Confirmed);
    assert_eq!(FindingStatus::Resolved, FindingStatus::Resolved);
}

#[test]
fn finding_status_copy() {
    let s1 = FindingStatus::Open;
    let s2 = s1;
    // s1 is still valid because FindingStatus is Copy
    assert_eq!(s1, FindingStatus::Open);
    assert_eq!(s2, FindingStatus::Open);
}
