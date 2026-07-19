use secfinding::{Finding, FindingKind, Severity};

#[test]
fn integration_finding_builder_roundtrip() {
    let f = Finding::builder("campaign", "https://example.test", Severity::Medium)
        .title("smoke")
        .kind(FindingKind::Exposure)
        .build()
        .expect("valid finding");
    assert_eq!(f.scanner(), "campaign");
    assert_eq!(f.severity(), Severity::Medium);
    assert_eq!(f.kind(), FindingKind::Exposure);
}
