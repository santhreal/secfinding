use secfinding::{Finding, Severity};

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

#[test]
fn finding_with_long_detail() {
    let long = "x".repeat(100_000);
    let f = Finding::builder("s", "t", Severity::High)
        .title("test")
        .detail(&long)
        .build()
        .unwrap();
    assert_eq!(f.detail().len(), 100_000);
}

#[test]
fn duplicate_tags_are_deduped() {
    let f = Finding::builder("s", "t", Severity::High)
        .title("test")
        .tag("sqli")
        .tag("sqli")
        .tag("sqli")
        .build()
        .unwrap();
    assert_eq!(f.tags().len(), 1);
}

#[test]
fn finding_deserialization_allows_unknown_fields() {
    let json = r#"{
        "scanner":"scan",
        "target":"target",
        "severity":"high",
        "title":"title",
        "unexpected":true
    }"#;
    let finding = serde_json::from_str::<Finding>(json).unwrap();
    assert_eq!(finding.scanner(), "scan");
}

#[test]
fn finding_deserialization_rejects_invalid_cve() {
    let json = r#"{
        "scanner":"scan",
        "target":"target",
        "severity":"high",
        "title":"title",
        "cve_ids":["not-a-cve"]
    }"#;
    let error = serde_json::from_str::<Finding>(json).unwrap_err();
    assert!(error.to_string().contains("invalid CVE format"));
}

#[test]
fn finding_deserialization_deduplicates_tags_and_rejects_out_of_range_scores() {
    // Out-of-range scores used to clamp; the audit
    // (verify_confidence_rejects_out_of_range,
    // verify_cvss_rejects_out_of_range) made them hard errors. Tag
    // dedup still applies on the happy path.
    let bad = r#"{
        "scanner":"scan",
        "target":"target",
        "severity":"high",
        "title":"title",
        "confidence":1.5
    }"#;
    assert!(
        serde_json::from_str::<Finding>(bad).is_err(),
        "out-of-range confidence must be rejected at deserialization"
    );

    let bad_cvss = r#"{
        "scanner":"scan",
        "target":"target",
        "severity":"high",
        "title":"title",
        "cvss_score":99.9
    }"#;
    assert!(
        serde_json::from_str::<Finding>(bad_cvss).is_err(),
        "out-of-range cvss must be rejected at deserialization"
    );

    let good = r#"{
        "scanner":"scan",
        "target":"target",
        "severity":"high",
        "title":"title",
        "tags":["dup","dup","alpha"],
        "confidence":0.95,
        "cvss_score":9.8
    }"#;
    let finding = serde_json::from_str::<Finding>(good).unwrap();
    assert_eq!(
        finding.tags(),
        vec![std::sync::Arc::from("alpha"), std::sync::Arc::from("dup")]
    );
    assert_eq!(finding.confidence(), Some(0.95));
    assert_eq!(finding.cvss_score(), Some(9.8));
}

#[test]
fn many_findings_unique_ids() {
    let findings: Vec<Finding> = (0..1_000)
        .map(|i| {
            Finding::builder("s", format!("target-{i}"), Severity::Low)
                .title(format!("finding-{i}"))
                .build()
                .unwrap()
        })
        .collect();
    let ids: std::collections::HashSet<_> = findings.iter().map(|f| f.id()).collect();
    assert_eq!(ids.len(), 1_000);
}

#[test]
fn adversarial_empty_input_boundary() {
    let r = Finding::new("\0", "\0", Severity::High, "\0", "\0");
    assert!(
        r.is_err(),
        "Null bytes should be rejected in security findings"
    );
}

#[test]
fn adversarial_huge_input() {
    let huge = "A".repeat(1024 * 1024 * 10);
    let result = Finding::builder(&huge, "target", Severity::High)
        .title("title")
        .build();
    assert!(
        result.is_err(),
        "Engine must gracefully reject scanner strings exceeding the max length"
    );
}

#[test]
fn adversarial_invalid_utf8_simulated() {
    let invalid_utf8_simulated = String::from_utf8_lossy(b"hello \xFF world").to_string();
    let result = Finding::builder("scan", "target", Severity::High)
        .title(&invalid_utf8_simulated)
        .build();
    assert!(
        result.is_err(),
        "Unicode replacement character should be rejected in security findings"
    );
}

#[test]
fn adversarial_u32_max_bounds() {
    // Tests boundary condition of fields near U32 Max where length could be limited
    let size = 1024 * 1024 * 5; // 5 MB details
    let large = "A".repeat(size);
    let result = Finding::builder("scan", "target", Severity::High)
        .title("title")
        .detail(&large)
        .build();
    assert!(
        result.is_err(),
        "Engine must gracefully reject large detail strings (>1MB) rather than accept."
    );
}

#[test]
fn adversarial_empty_tags_vector() {
    let f = Finding::builder("s", "t", Severity::High)
        .title("t")
        .build()
        .unwrap();
    assert!(f.tags().is_empty(), "Empty tags vector should not panic");
}

#[test]
#[allow(clippy::legacy_numeric_constants)]
fn integer_limits_for_cvss_score() {
    let r = Finding::builder("s", "t", Severity::High)
        .title("t")
        .cvss_score(f64::INFINITY)
        .build();
    assert!(r.is_err());

    let r_neg = Finding::builder("s", "t", Severity::High)
        .title("t")
        .cvss_score(f64::NEG_INFINITY)
        .build();
    assert!(r_neg.is_err());
}

#[test]
#[allow(clippy::legacy_numeric_constants)]
fn integer_limits_for_confidence() {
    let r = Finding::builder("s", "t", Severity::High)
        .title("t")
        .confidence(f64::INFINITY)
        .build();
    assert!(r.is_err());

    let r_neg = Finding::builder("s", "t", Severity::High)
        .title("t")
        .confidence(f64::NEG_INFINITY)
        .build();
    assert!(r_neg.is_err());
}
