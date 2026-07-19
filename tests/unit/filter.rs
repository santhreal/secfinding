use secfinding::{filter, Finding, FindingFilter, Severity};

#[test]
fn filter_applies_severity_scanner_and_tags() {
    let f1 = Finding::builder("calyx", "target", Severity::High)
        .title("t")
        .tag("sql")
        .build()
        .unwrap();
    let f2 = Finding::builder("gossan", "target", Severity::Medium)
        .title("t")
        .tag("xss")
        .build()
        .unwrap();

    let findings = vec![f1, f2];

    let f = FindingFilter {
        min_severity: Some(Severity::High),
        ..Default::default()
    };
    assert_eq!(filter(&findings, &f).len(), 1);

    let f = FindingFilter {
        exclude_scanners: vec!["gossan".into()],
        ..Default::default()
    };
    assert_eq!(filter(&findings, &f).len(), 1);

    let f = FindingFilter {
        include_tags: vec!["xss".into()],
        ..Default::default()
    };
    assert_eq!(filter(&findings, &f).len(), 1);
}

// Ported from the previously dead tests/unit/test_filter.rs (orphaned behind an
// unwired tests/unit/mod.rs) and updated to the current API: FindingFilter grew
// several fields (so `..Default::default()` is required), its list fields are
// Vec<Arc<str>> (so string literals use `.into()`), and `filter` returns
// `Vec<&Finding>` whose fields are private (so accessors, not field access).
#[test]
fn filter_with_no_includes_keeps_matching_scanners() {
    let findings = vec![
        Finding::builder("a", "target", Severity::High)
            .title("t")
            .tag("x")
            .build()
            .unwrap(),
        Finding::builder("b", "target", Severity::Medium)
            .title("t")
            .tag("x")
            .build()
            .unwrap(),
    ];
    let config = FindingFilter {
        min_severity: Some(Severity::Medium),
        exclude_scanners: vec!["b".into()],
        ..Default::default()
    };

    let filtered = filter(&findings, &config);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].scanner(), "a");
}

#[test]
fn filter_all_excluded() {
    let findings = vec![Finding::builder("a", "target", Severity::High)
        .title("t")
        .build()
        .unwrap()];
    let config = FindingFilter {
        exclude_scanners: vec!["a".into()],
        ..Default::default()
    };

    let filtered = filter(&findings, &config);
    assert!(filtered.is_empty());
}

#[test]
fn filter_by_min_severity_only() {
    let findings = vec![
        Finding::builder("a", "target", Severity::Info)
            .title("t")
            .build()
            .unwrap(),
        Finding::builder("b", "target", Severity::Low)
            .title("t")
            .build()
            .unwrap(),
        Finding::builder("c", "target", Severity::Critical)
            .title("t")
            .build()
            .unwrap(),
    ];
    let config = FindingFilter {
        min_severity: Some(Severity::Low),
        ..Default::default()
    };

    let filtered = filter(&findings, &config);
    assert_eq!(filtered.len(), 2);
}

#[test]
fn filter_no_tags_match() {
    let findings = vec![Finding::builder("a", "target", Severity::High)
        .title("t")
        .tag("t1")
        .build()
        .unwrap()];
    let config = FindingFilter {
        include_tags: vec!["t2".into()],
        ..Default::default()
    };

    let filtered = filter(&findings, &config);
    assert!(filtered.is_empty());
}

#[test]
fn filter_multiple_conditions() {
    let findings = vec![
        Finding::builder("nmap", "target", Severity::High)
            .title("t")
            .tag("web")
            .build()
            .unwrap(),
        Finding::builder("burp", "target", Severity::Low)
            .title("t")
            .tag("web")
            .build()
            .unwrap(),
        Finding::builder("burp", "target", Severity::Critical)
            .title("t")
            .tag("api")
            .build()
            .unwrap(),
    ];
    let config = FindingFilter {
        min_severity: Some(Severity::High),
        exclude_scanners: vec!["nmap".into()],
        include_tags: vec!["api".into(), "web".into()],
        ..Default::default()
    };

    let filtered = filter(&findings, &config);
    // Only the burp critical finding remains (nmap is excluded, burp low is < High)
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].scanner(), "burp");
    assert_eq!(filtered[0].severity(), Severity::Critical);
}

#[test]
fn parse_toml_filter_config() {
    let toml_str = r#"
        min_severity = "high"
        exclude_scanners = ["test"]
        include_tags = ["t1", "t2"]
    "#;
    let config = FindingFilter::from_toml(toml_str).unwrap();
    assert_eq!(config.min_severity, Some(Severity::High));
    assert_eq!(config.exclude_scanners.len(), 1);
    assert_eq!(config.include_tags.len(), 2);
}

#[test]
fn parse_empty_toml_filter_config() {
    let config = FindingFilter::from_toml("").unwrap();
    assert_eq!(config.min_severity, None);
    assert!(config.exclude_scanners.is_empty());
    assert!(config.include_tags.is_empty());
}
