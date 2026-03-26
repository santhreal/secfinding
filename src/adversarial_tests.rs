use crate::*;

// === Severity ===

#[test]
fn severity_ordering() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::Info);
}

#[test]
fn severity_from_str_case_insensitive() {
    assert_eq!(
        Severity::from_str_loose("CRITICAL"),
        Some(Severity::Critical)
    );
    assert_eq!(Severity::from_str_loose("crit"), Some(Severity::Critical));
    assert_eq!(Severity::from_str_loose("High"), Some(Severity::High));
    assert_eq!(Severity::from_str_loose("med"), Some(Severity::Medium));
    assert_eq!(
        Severity::from_str_loose("informational"),
        Some(Severity::Info)
    );
}

#[test]
fn severity_from_str_invalid() {
    assert_eq!(Severity::from_str_loose(""), None);
    assert_eq!(Severity::from_str_loose("unknown"), None);
    assert_eq!(Severity::from_str_loose("\0"), None);
}

#[test]
fn severity_serde_roundtrip() {
    for sev in [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let back: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, back);
    }
}

// === Finding builder ===

#[test]
fn finding_builder_minimal() {
    let f = Finding::builder("scanner", "target", Severity::High)
        .title("test")
        .build()
        .unwrap();
    assert_eq!(f.scanner, "scanner");
    assert_eq!(f.target, "target");
    assert_eq!(f.severity, Severity::High);
    assert!(f.tags.is_empty());
    assert!(f.evidence.is_empty());
    assert!(f.cve_ids.is_empty());
}

#[test]
fn finding_builder_full() {
    let f = Finding::builder("s", "t", Severity::Critical)
        .title("XSS")
        .detail("Reflected input in response")
        .kind(FindingKind::Vulnerability)
        .evidence(Evidence::HttpResponse {
            status: 200,
            headers: vec![],
            body_excerpt: Some("alert(1)".into()),
        })
        .tag("xss")
        .tag("owasp-a03")
        .cve("CVE-2024-99999")
        .build()
        .unwrap();
    assert_eq!(f.title, "XSS");
    assert_eq!(f.tags.len(), 2);
    assert_eq!(f.cve_ids.len(), 1);
    assert_eq!(f.evidence.len(), 1);
}

#[test]
fn finding_builder_unicode() {
    let f = Finding::builder("扫描器", "目标.com", Severity::High)
        .title("跨站脚本")
        .detail("用户输入未过滤 🔒")
        .tag("日本語")
        .build()
        .unwrap();
    assert_eq!(f.scanner, "扫描器");
    assert!(f.detail.contains("🔒"));
}

#[test]
fn finding_serde_roundtrip() {
    let f = Finding::builder("s", "t", Severity::Medium)
        .title("Test")
        .kind(FindingKind::Misconfiguration)
        .build()
        .unwrap();
    let json = serde_json::to_string(&f).unwrap();
    let back: Finding = serde_json::from_str(&json).unwrap();
    assert_eq!(f.id, back.id);
    assert_eq!(f.severity, back.severity);
    assert_eq!(f.kind, back.kind);
}

#[test]
fn finding_unique_ids() {
    let a = Finding::builder("s", "t", Severity::Low)
        .title("a")
        .build()
        .unwrap();
    let b = Finding::builder("s", "t", Severity::Low)
        .title("b")
        .build()
        .unwrap();
    assert_ne!(a.id, b.id, "each finding should get a unique UUID");
}

// === Finding::new validation ===

#[test]
fn finding_new_rejects_empty_scanner() {
    let r = Finding::new("", "t", Severity::High, "title", "detail");
    assert!(r.is_err());
}

#[test]
fn finding_new_rejects_empty_target() {
    let r = Finding::new("s", "", Severity::High, "title", "detail");
    assert!(r.is_err());
}

#[test]
fn finding_new_rejects_empty_title() {
    let r = Finding::new("s", "t", Severity::High, "", "detail");
    assert!(r.is_err());
}

// === Evidence ===

#[test]
fn evidence_http_response_serde() {
    let e = Evidence::HttpResponse {
        status: 500,
        headers: vec![("Content-Type".into(), "text/html".into())],
        body_excerpt: Some("<html>error</html>".into()),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: Evidence = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// === FindingKind ===

#[test]
fn finding_kind_serde_roundtrip() {
    for kind in [
        FindingKind::Vulnerability,
        FindingKind::Misconfiguration,
        FindingKind::Exposure,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: FindingKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

// === Filter ===

#[test]
fn filter_by_severity() {
    let findings = vec![
        Finding::builder("s", "t", Severity::Info)
            .title("a")
            .build()
            .unwrap(),
        Finding::builder("s", "t", Severity::High)
            .title("b")
            .build()
            .unwrap(),
        Finding::builder("s", "t", Severity::Critical)
            .title("c")
            .build()
            .unwrap(),
    ];
    let filtered: Vec<_> = findings
        .iter()
        .filter(|f| f.severity >= Severity::High)
        .collect();
    assert_eq!(filtered.len(), 2);
}

#[test]
fn filter_by_tag() {
    let findings = vec![
        Finding::builder("s", "t", Severity::High)
            .title("a")
            .tag("sqli")
            .build()
            .unwrap(),
        Finding::builder("s", "t", Severity::High)
            .title("b")
            .tag("xss")
            .build()
            .unwrap(),
        Finding::builder("s", "t", Severity::High)
            .title("c")
            .tag("sqli")
            .tag("auth")
            .build()
            .unwrap(),
    ];
    let sqli: Vec<_> = findings
        .iter()
        .filter(|f| f.tags.contains(&"sqli".to_string()))
        .collect();
    assert_eq!(sqli.len(), 2);
}

// === Stress ===

#[test]
fn many_findings_unique_ids() {
    let findings: Vec<Finding> = (0..1_000)
        .map(|i| {
            Finding::builder("s", &format!("target-{i}"), Severity::Low)
                .title(&format!("finding-{i}"))
                .build()
                .unwrap()
        })
        .collect();
    let ids: std::collections::HashSet<_> = findings.iter().map(|f| f.id).collect();
    assert_eq!(ids.len(), 1_000);
}

#[test]
fn finding_with_long_detail() {
    let long = "x".repeat(100_000);
    let f = Finding::builder("s", "t", Severity::High)
        .title("test")
        .detail(&long)
        .build()
        .unwrap();
    assert_eq!(f.detail.len(), 100_000);
}

// === Dedup tags ===

#[test]
fn duplicate_tags_are_deduped() {
    let f = Finding::builder("s", "t", Severity::High)
        .title("test")
        .tag("sqli")
        .tag("sqli")
        .tag("sqli")
        .build()
        .unwrap();
    assert_eq!(f.tags.len(), 1);
}
