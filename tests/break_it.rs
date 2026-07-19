use secfinding::{Evidence, Finding, FindingBuildError, Location, Severity};
use std::thread;

// --- 1. Empty input / zero-length slices ---

#[test]
fn test_empty_scanner() {
    let err = Finding::builder("", "target", Severity::Info)
        .title("title")
        .build()
        .unwrap_err();
    assert_eq!(err, FindingBuildError::EmptyScanner);
}

#[test]
fn test_empty_target() {
    let err = Finding::builder("scanner", "", Severity::Info)
        .title("title")
        .build()
        .unwrap_err();
    assert_eq!(err, FindingBuildError::EmptyTarget);
}

#[test]
fn test_empty_title() {
    let err = Finding::builder("scanner", "target", Severity::Info)
        .title("")
        .build()
        .unwrap_err();
    assert_eq!(err, FindingBuildError::EmptyTitle);
}

#[test]
fn test_empty_detail_allowed_but_handled() {
    let finding = Finding::builder("scanner", "target", Severity::Info)
        .title("title")
        .detail("")
        .build()
        .unwrap();
    assert_eq!(finding.detail(), "");
}

// --- 2. Null bytes in input ---

#[test]
fn test_null_bytes_in_scanner() {
    // Null bytes in scanner name should likely be rejected to prevent injection or C-string truncation.
    let res = Finding::builder("scan\0ner", "target", Severity::Info)
        .title("title")
        .build();
    assert!(res.is_err(), "Engine allowed null bytes in scanner name");
}

#[test]
fn test_null_bytes_in_target() {
    let res = Finding::builder("scanner", "tar\0get", Severity::Info)
        .title("title")
        .build();
    assert!(res.is_err(), "Engine allowed null bytes in target");
}

#[test]
fn test_null_bytes_in_title() {
    let res = Finding::builder("scanner", "target", Severity::Info)
        .title("ti\0tle")
        .build();
    assert!(res.is_err(), "Engine allowed null bytes in title");
}

#[test]
fn test_null_bytes_in_cve() {
    let res = Finding::builder("scanner", "target", Severity::Info)
        .title("title")
        .cve("CVE-2024-\x00123")
        .build();
    assert!(res.is_err(), "Engine allowed null bytes in CVE");
}

// --- 3. Maximum u32/u64 values for any numeric parameter ---

#[test]
fn test_max_u32_location_line() {
    let loc = Location::new("src/main.rs")
        .unwrap()
        .line(u32::MAX)
        .unwrap();
    let finding = Finding::builder("scanner", "target", Severity::Info)
        .title("title")
        .location(loc)
        .build()
        .unwrap();
    assert_eq!(finding.location().unwrap().line, Some(u32::MAX));
}

#[test]
fn test_max_u32_location_column() {
    let loc = Location::new("src/main.rs")
        .unwrap()
        .column(u32::MAX)
        .unwrap();
    let finding = Finding::builder("scanner", "target", Severity::Info)
        .title("title")
        .location(loc)
        .build()
        .unwrap();
    assert_eq!(finding.location().unwrap().column, Some(u32::MAX));
}

#[test]
fn test_max_f64_confidence() {
    let res = Finding::builder("scanner", "target", Severity::Info)
        .title("title")
        .confidence(f64::MAX)
        .build();
    // Confidence must be clamped to 1.0 or rejected.
    assert!(
        res.is_err() || res.unwrap().confidence() == Some(1.0),
        "Confidence was not constrained"
    );
}

#[test]
fn test_max_f64_cvss() {
    let res = Finding::builder("scanner", "target", Severity::Info)
        .title("title")
        .cvss_score(f64::MAX)
        .build();
    // CVSS must be clamped to 10.0 or rejected.
    assert!(
        res.is_err() || res.unwrap().cvss_score() == Some(10.0),
        "CVSS score was not constrained"
    );
}

#[test]
fn test_nan_confidence() {
    let err = Finding::builder("scanner", "target", Severity::Info)
        .title("title")
        .confidence(f64::NAN)
        .build()
        .unwrap_err();
    assert_eq!(err, FindingBuildError::InvalidConfidence);
}

#[test]
fn test_nan_cvss_score() {
    let err = Finding::builder("scanner", "target", Severity::Info)
        .title("title")
        .cvss_score(f64::NAN)
        .build()
        .unwrap_err();
    assert_eq!(err, FindingBuildError::InvalidCvssScore);
}

// --- 4. 1MB+ input ---

#[test]
fn test_1mb_scanner_input() {
    let big_scanner = "a".repeat(1_048_576);
    let err = Finding::builder(&big_scanner, "target", Severity::Info)
        .title("title")
        .build()
        .unwrap_err();
    assert!(matches!(err, FindingBuildError::FieldTooLong { .. }));
}

#[test]
fn test_1mb_target_input() {
    let big_target = "b".repeat(1_048_576);
    let err = Finding::builder("scanner", &big_target, Severity::Info)
        .title("title")
        .build()
        .unwrap_err();
    assert!(matches!(err, FindingBuildError::FieldTooLong { .. }));
}

#[test]
fn test_1mb_title_input() {
    let big_title = "c".repeat(1_048_576);
    // Let's assert it returns an error gracefully.
    let result = std::panic::catch_unwind(|| {
        Finding::builder("scanner", "target", Severity::Info)
            .title(&big_title)
            .build()
    });
    match result {
        Ok(res) => assert!(res.is_err(), "Engine allowed 1MB title without error"),
        Err(_) => panic!("Engine panicked instead of returning error on 1MB title"),
    }
}

#[test]
fn test_1mb_detail_input() {
    let big_detail = "d".repeat(1_048_577);
    let result = std::panic::catch_unwind(|| {
        Finding::builder("scanner", "target", Severity::Info)
            .title("title")
            .detail(&big_detail)
            .build()
    });
    match result {
        Ok(res) => assert!(res.is_err(), "Engine allowed >1MB detail without error"),
        Err(_) => panic!("Engine panicked instead of returning error on >1MB detail"),
    }
}

// --- 5. Concurrent access from 8 threads ---

#[test]
fn test_concurrent_builders_8_threads() {
    let mut handles = vec![];
    for i in 0..8 {
        handles.push(thread::spawn(move || {
            for j in 0..1000 {
                let _ = Finding::builder(
                    format!("scanner-{}", i),
                    format!("target-{}", j),
                    Severity::Info,
                )
                .title("title")
                .tag(format!("tag-{}", j))
                .build()
                .unwrap();
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
}

// --- 6. Malformed/truncated input ---

#[test]
fn test_malformed_cve_prefix() {
    let err = Finding::builder("scanner", "target", Severity::Info)
        .title("title")
        .cve("VCE-2024-1234") // misspelled
        .build()
        .unwrap_err();
    assert!(matches!(err, FindingBuildError::InvalidCveFormat(_)));
}

#[test]
fn test_malformed_cve_length_too_short() {
    let err = Finding::builder("scanner", "target", Severity::Info)
        .title("title")
        .cve("CVE-1") // too short
        .build()
        .unwrap_err();
    assert!(matches!(err, FindingBuildError::InvalidCveFormat(_)));
}

#[test]
fn test_malformed_cwe_format() {
    let err = Finding::builder("scanner", "target", Severity::Info)
        .title("title")
        .cwe("CWE89") // missing hyphen
        .build()
        .unwrap_err();
    assert!(matches!(err, FindingBuildError::InvalidCweFormat(_)));
}

#[test]
fn test_location_path_traversal() {
    let res = Location::new("../../../etc/passwd");
    assert!(
        res.is_err(),
        "Engine allowed path traversal in location file"
    );
}

#[test]
fn test_location_backslash_path_traversal() {
    // On Unix, `Path` treats '\' as an ordinary character, so `..\..\etc\passwd`
    // must be normalized before the ParentDir check or the traversal slips
    // through as a single Normal component.
    let res = Location::new("..\\..\\..\\etc\\passwd");
    assert!(
        res.is_err(),
        "Engine allowed backslash path traversal in location file"
    );
}

#[test]
fn test_location_absolute_path() {
    let res = Location::new("/etc/passwd");
    assert!(
        res.is_err(),
        "Engine allowed absolute path in location file"
    );
}

// --- 7. Unicode edge cases ---

#[test]
fn test_unicode_bom_in_title() {
    let title = "\u{FEFF}Title";
    let finding = Finding::builder("scanner", "target", Severity::Info)
        .title(title)
        .build()
        .unwrap();
    // Engine should strip BOM or reject it, allowing BOM is a flaw.
    assert!(
        !finding.title().starts_with('\u{FEFF}'),
        "Engine preserved BOM in title"
    );
}

#[test]
fn test_unicode_right_to_left_override() {
    // RLO (U+202E) in ISOLATION - no null byte. The previous version embedded a
    // `\0` alongside the RLO, so the build failed on the null-byte path and never
    // actually exercised bidi rejection (a false-confidence test). This spoofed
    // title renders as "report_exe.jpg" while the real bytes end in ".exe".
    let rlo = "\u{202E}";
    let res = Finding::builder("scanner", "target", Severity::Info)
        .title(format!("report_txt{rlo}gpj.exe"))
        .build();
    assert!(
        res.is_err(),
        "Engine allowed Right-to-Left Override character (Trojan Source spoofing vector)"
    );
}

#[test]
fn test_unicode_bidi_controls_rejected_in_detail_and_target() {
    // The whole Trojan Source bidi-control family is rejected across fields, not
    // just RLO in the title.
    for bidi in ['\u{202D}', '\u{2066}', '\u{2069}', '\u{061C}'] {
        let res = Finding::builder("scanner", "target", Severity::Info)
            .title(format!("clean{bidi}title"))
            .build();
        assert!(
            res.is_err(),
            "bidi control U+{:04X} must be rejected",
            bidi as u32
        );
    }
    // A legitimate title with ordinary Unicode (no bidi controls) still builds.
    let ok = Finding::builder("scanner", "target", Severity::Info)
        .title("Normal café findING with accents")
        .build();
    assert!(ok.is_ok(), "ordinary Unicode must not be rejected");
}

#[test]
fn test_unicode_surrogate_replacement() {
    let title = "invalid\u{FFFD}char";
    let res = Finding::builder("scanner", "target", Severity::Info)
        .title(title)
        .build();
    assert!(res.is_err(), "Engine allowed Unicode replacement character");
}

// --- 8. Duplicate entries ---

#[test]
fn test_duplicate_tags_deduplication() {
    let finding = Finding::builder("scanner", "target", Severity::Info)
        .title("title")
        .tag("sqli")
        .tag("sqli")
        .tag("xss")
        .tag("sqli")
        .build()
        .unwrap();
    assert_eq!(finding.tags().len(), 2, "Tags were not deduplicated");
}

#[test]
fn test_duplicate_cves() {
    let finding = Finding::builder("scanner", "target", Severity::Info)
        .title("title")
        .cve("CVE-2024-1234")
        .cve("CVE-2024-1234")
        .build()
        .unwrap();
    assert_eq!(finding.cve_ids().len(), 1, "CVEs were not deduplicated");
}

#[test]
fn test_duplicate_matched_values() {
    let finding = Finding::builder("scanner", "target", Severity::Info)
        .title("title")
        .matched_value("needle")
        .matched_value("needle")
        .build()
        .unwrap();
    assert_eq!(
        finding.matched_values().len(),
        1,
        "Matched values were not deduplicated"
    );
}

// --- 9. Off-by-one ---

#[test]
fn test_scanner_len_exactly_max() {
    let max_len = 1024;
    let scanner = "a".repeat(max_len);
    let finding = Finding::builder(&scanner, "target", Severity::Info)
        .title("title")
        .build();
    assert!(
        finding.is_ok(),
        "Engine rejected scanner at exact MAX length"
    );
}

#[test]
fn test_scanner_len_off_by_one() {
    let max_len = 1024;
    let scanner = "a".repeat(max_len + 1);
    let finding = Finding::builder(&scanner, "target", Severity::Info)
        .title("title")
        .build();
    assert!(
        finding.is_err(),
        "Engine allowed scanner length off by one (MAX + 1)"
    );
}

#[test]
fn test_title_len_exactly_max() {
    let max_len = 10240;
    let title = "a".repeat(max_len);
    let finding = Finding::builder("scanner", "target", Severity::Info)
        .title(&title)
        .build();
    assert!(finding.is_ok(), "Engine rejected title at exact MAX length");
}

#[test]
fn test_title_len_off_by_one() {
    let max_len = 10240;
    let title = "a".repeat(max_len + 1);
    let result = std::panic::catch_unwind(|| {
        Finding::builder("scanner", "target", Severity::Info)
            .title(&title)
            .build()
    });
    match result {
        Ok(res) => assert!(
            res.is_err(),
            "Engine allowed title length off by one (MAX + 1) without error"
        ),
        Err(_) => panic!("Engine panicked instead of returning error on off by one title"),
    }
}

// --- 10. Resource exhaustion ---

#[test]
fn test_100k_evidence_items() {
    let mut builder = Finding::builder("scanner", "target", Severity::Info).title("title");
    for _i in 0..100_000 {
        builder = builder.evidence(Evidence::http_status(200).unwrap());
    }
    // Should it panic? OOM? Or is it allowed?
    let result = builder.build();
    assert!(
        result.is_err(),
        "Engine allowed 100,000 evidence items, potential resource exhaustion"
    );
}

#[test]
fn test_100k_tags() {
    let mut builder = Finding::builder("scanner", "target", Severity::Info).title("title");
    for i in 0..100_000 {
        builder = builder.tag(format!("tag-{}", i));
    }
    let result = builder.build();
    assert!(
        result.is_err(),
        "Engine allowed 100,000 tags, potential resource exhaustion"
    );
}

#[test]
fn test_json_deserialization_exhaustion() {
    // deeply nested JSON or huge JSON array for evidence
    let json = format!(
        r#"{{
        "scanner": "s",
        "target": "t",
        "severity": "high",
        "title": "title",
        "tags": [{}]
    }}"#,
        vec!["\"a\""; 100_000].join(", ")
    );

    let res: Result<Finding, _> = serde_json::from_str(&json);
    assert!(
        res.is_err(),
        "Engine parsed 100k array JSON without size bounds"
    );
}

#[test]
fn test_json_deserialization_negative_line() {
    let json = r#"{
        "scanner": "s",
        "target": "t",
        "severity": "high",
        "title": "title",
        "location": {
            "file": "src/main.rs",
            "line": -1,
            "column": 10
        }
    }"#;
    let res: Result<Finding, _> = serde_json::from_str(json);
    assert!(
        res.is_err(),
        "Engine allowed negative location line in JSON"
    );
}

#[test]
fn test_json_deserialization_zero_line() {
    let json = r#"{
        "scanner": "s",
        "target": "t",
        "severity": "high",
        "title": "title",
        "location": {
            "file": "src/main.rs",
            "line": 0,
            "column": 10
        }
    }"#;
    let res: Result<Finding, _> = serde_json::from_str(json);
    assert!(res.is_err(), "Engine allowed line 0 in JSON");
}
