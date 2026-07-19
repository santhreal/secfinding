#[cfg(feature = "secir")]
use secfinding::{
    bridge::{map_kind, map_severity, to_universal},
    FindingKind, Severity,
};

#[cfg(feature = "secir")]
#[test]
fn severity_mapping_covers_all() {
    assert_eq!(map_severity(secir::Severity::Info), Severity::Info);
    assert_eq!(map_severity(secir::Severity::Low), Severity::Low);
    assert_eq!(map_severity(secir::Severity::Medium), Severity::Medium);
    assert_eq!(map_severity(secir::Severity::High), Severity::High);
    assert_eq!(map_severity(secir::Severity::Critical), Severity::Critical);
    assert_eq!(map_severity(secir::Severity::Unknown), Severity::Info);
}

// Ported from the previously dead tests/unit/test_bridge.rs (orphaned behind an
// unwired tests/unit/mod.rs) and updated to the current API (UniversalSeverity
// was renamed to Severity). These exercise the full secir -> Finding bridge.
#[cfg(feature = "secir")]
#[test]
fn kind_mapping_covers_all_variants() {
    let variants = [
        secir::finding::FindingKind::Vulnerability,
        secir::finding::FindingKind::Misconfiguration,
        secir::finding::FindingKind::Exposure,
        secir::finding::FindingKind::TechDetect,
        secir::finding::FindingKind::DefaultCredentials,
        secir::finding::FindingKind::InfoDisclosure,
        secir::finding::FindingKind::FileDiscovery,
        secir::finding::FindingKind::Other,
    ];
    for v in &variants {
        let _ = map_kind(v);
    }
}

#[cfg(feature = "secir")]
#[test]
fn basic_conversion() {
    let ir = secir::finding::Finding::new(
        "test-template".to_string(),
        "Test Template".to_string(),
        "https://example.com".to_string(),
        secir::Severity::High,
        "https://example.com/admin".to_string(),
    );

    let finding = to_universal(&ir, "calyx").unwrap();
    assert_eq!(finding.scanner(), "calyx");
    assert_eq!(finding.target(), "https://example.com");
    assert_eq!(finding.severity(), Severity::High);
    assert_eq!(finding.title(), "Test Template");
    assert_eq!(finding.kind(), FindingKind::Other);
}

#[cfg(feature = "secir")]
#[test]
fn conversion_preserves_evidence() {
    let mut ir = secir::finding::Finding::new(
        "xss-test".to_string(),
        "XSS Test".to_string(),
        "https://example.com".to_string(),
        secir::Severity::Medium,
        "https://example.com/search".to_string(),
    );
    ir.request = Some("GET /search?q=<script> HTTP/1.1".to_string());
    ir.response = Some("HTTP/1.1 200 OK\n\n<script>".to_string());
    ir.matched_values = vec!["<script>".to_string()];
    ir.curl_command = Some("curl 'https://example.com/search?q=<script>'".to_string());

    let finding = to_universal(&ir, "calyx").unwrap();
    // request (Raw) + response (Raw) + 1 matched_value (PatternMatch) = 3 evidence items
    assert_eq!(finding.evidence().len(), 3);
    assert_eq!(
        finding.exploit_hint(),
        Some("curl 'https://example.com/search?q=<script>'")
    );
    assert_eq!(finding.matched_values()[0].as_ref(), "<script>");
}

#[cfg(feature = "secir")]
#[test]
fn empty_template_name_uses_id() {
    let ir = secir::finding::Finding::new(
        "CVE-2021-44228".to_string(),
        String::new(),
        "https://target.com".to_string(),
        secir::Severity::Critical,
        "https://target.com/api".to_string(),
    );

    let finding = to_universal(&ir, "karyx").unwrap();
    assert_eq!(finding.title(), "CVE-2021-44228");
}
