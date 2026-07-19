use secfinding::Severity;

#[test]
fn ordering_and_display() {
    assert!(Severity::Critical > Severity::High);
    assert_eq!(Severity::High.to_string(), "high");
    assert_eq!(Severity::High.label(), "HIGH");
}

#[test]
fn try_from_u8() {
    assert_eq!(Severity::try_from(4u8).unwrap(), Severity::Critical);
    assert_eq!(Severity::try_from(0u8).unwrap(), Severity::Info);
    assert!(Severity::try_from(5u8).is_err());
}

#[test]
fn try_from_str() {
    assert_eq!(Severity::try_from("critical").unwrap(), Severity::Critical);
    assert_eq!(Severity::try_from("INFO").unwrap(), Severity::Info);
    assert!(Severity::try_from("unknown").is_err());
}

// Ported from the previously dead tests/unit/test_severity.rs (orphaned behind
// an unwired tests/unit/mod.rs).
#[test]
fn from_str_loose_variants() {
    assert_eq!(
        Severity::from_str_loose("CRITICAL"),
        Some(Severity::Critical)
    );
    assert_eq!(Severity::from_str_loose("crit"), Some(Severity::Critical));
    assert_eq!(Severity::from_str_loose("med"), Some(Severity::Medium));
    assert_eq!(
        Severity::from_str_loose("informational"),
        Some(Severity::Info)
    );
    assert_eq!(Severity::from_str_loose("bogus"), None);
}

#[test]
fn serde_roundtrip() {
    let json = serde_json::to_string(&Severity::High).unwrap();
    assert_eq!(json, "\"high\"");
    let back: Severity = serde_json::from_str(&json).unwrap();
    assert_eq!(back, Severity::High);
}
