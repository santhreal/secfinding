use secfinding::FindingKind;

#[test]
fn serde_and_display_kebab_case() {
    let json = serde_json::to_string(&FindingKind::TechDetect).unwrap();
    assert_eq!(json, "\"tech-detect\"");

    let parsed: FindingKind = serde_json::from_str("\"tech-detect\"").unwrap();
    assert_eq!(parsed, FindingKind::TechDetect);

    assert_eq!(FindingKind::TechDetect.to_string(), "tech-detect");
}

#[test]
fn from_str_case_insensitive() {
    assert_eq!(
        "VulneRability".parse::<FindingKind>().unwrap(),
        FindingKind::Vulnerability
    );
}

#[test]
fn from_str_kebab_and_snake() {
    assert_eq!(
        "tech-detect".parse::<FindingKind>().unwrap(),
        FindingKind::TechDetect
    );
    assert_eq!(
        "tech_detect".parse::<FindingKind>().unwrap(),
        FindingKind::TechDetect
    );
}

#[test]
fn from_str_unknown_is_rejected() {
    // Audit `verify_kind_from_str_rejects_unknown` made silent
    // fallback to `Other` an error  -  `Other` is now an intentional
    // classification, not a catch-all.
    assert!("some-weird-kind".parse::<FindingKind>().is_err());
    // Explicit "other" still parses as the intentional variant.
    assert_eq!("other".parse::<FindingKind>().unwrap(), FindingKind::Other);
}

// Ported from the previously dead tests/unit/test_kind.rs (orphaned behind an
// unwired tests/unit/mod.rs).
#[test]
fn actionable() {
    assert!(FindingKind::Vulnerability.is_actionable());
    assert!(FindingKind::SecretLeak.is_actionable());
    assert!(!FindingKind::TechDetect.is_actionable());
    assert!(!FindingKind::InfoDisclosure.is_actionable());
}
