//! S-proptest-01: FindingFilter TOML/JSON roundtrips and filter() invariants.

use chrono::{TimeZone, Utc};
use proptest::prelude::*;
use secfinding::{filter, Finding, FindingFilter, FindingKind, Severity, TagMode};
use std::sync::Arc;

fn json_roundtrip_filter(f: &FindingFilter) -> FindingFilter {
    let json = serde_json::to_string(f).unwrap();
    serde_json::from_str(&json).unwrap()
}

fn sample_findings() -> Vec<Finding> {
    vec![
        Finding::builder("alpha", "https://a.test", Severity::Critical)
            .title("c")
            .tag("web")
            .kind(FindingKind::Vulnerability)
            .confidence(0.95)
            .build()
            .unwrap(),
        Finding::builder("beta", "https://b.test", Severity::Low)
            .title("l")
            .tag("dns")
            .kind(FindingKind::Exposure)
            .confidence(0.2)
            .build()
            .unwrap(),
        Finding::builder("gamma", "https://g.test", Severity::Medium)
            .title("m")
            .tag("web")
            .tag("auth")
            .kind(FindingKind::Misconfiguration)
            .build()
            .unwrap(),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_filter_default_json(sev_bits in 0u8..5, tag in "[a-z]{2,6}") {
        let _ = (sev_bits, tag);
        let f = FindingFilter::default();
        let back = json_roundtrip_filter(&f);
        prop_assert_eq!(f, back);
    }

    #[test]
    fn prop_filter_min_severity_json(sev_bits in 0u8..5, tag in "[a-z]{2,6}") {
        let _ = tag;
        let f = FindingFilter {
            min_severity: Some(Severity::try_from(sev_bits).unwrap()),
            ..Default::default()
        };
        let back = json_roundtrip_filter(&f);
        prop_assert_eq!(f, back);
    }

    #[test]
    fn prop_filter_max_severity_json(sev_bits in 0u8..5, tag in "[a-z]{2,6}") {
        let _ = tag;
        let f = FindingFilter {
            max_severity: Some(Severity::try_from(sev_bits).unwrap()),
            ..Default::default()
        };
        let back = json_roundtrip_filter(&f);
        prop_assert_eq!(f, back);
    }

    #[test]
    fn prop_filter_include_scanner_json(sev_bits in 0u8..5, tag in "[a-z]{2,6}") {
        let _ = (sev_bits, tag);
        let f = FindingFilter {
            include_scanners: vec![Arc::from("alpha")],
            ..Default::default()
        };
        let back = json_roundtrip_filter(&f);
        prop_assert_eq!(f, back);
    }

    #[test]
    fn prop_filter_exclude_scanner_json(sev_bits in 0u8..5, tag in "[a-z]{2,6}") {
        let _ = (sev_bits, tag);
        let f = FindingFilter {
            exclude_scanners: vec![Arc::from("beta")],
            ..Default::default()
        };
        let back = json_roundtrip_filter(&f);
        prop_assert_eq!(f, back);
    }

    #[test]
    fn prop_filter_include_tag_json(sev_bits in 0u8..5, tag in "[a-z]{2,6}") {
        let _ = sev_bits;
        let f = FindingFilter {
            include_tags: vec![Arc::from(tag.as_str())],
            ..Default::default()
        };
        let back = json_roundtrip_filter(&f);
        prop_assert_eq!(f, back);
    }

    #[test]
    fn prop_filter_exclude_tag_json(sev_bits in 0u8..5, tag in "[a-z]{2,6}") {
        let _ = sev_bits;
        let f = FindingFilter {
            exclude_tags: vec![Arc::from(tag.as_str())],
            ..Default::default()
        };
        let back = json_roundtrip_filter(&f);
        prop_assert_eq!(f, back);
    }

    #[test]
    fn prop_filter_tag_mode_any_json(sev_bits in 0u8..5, tag in "[a-z]{2,6}") {
        let _ = (sev_bits, tag);
        let f = FindingFilter {
            tag_mode: TagMode::Any,
            include_tags: vec![Arc::from("web")],
            ..Default::default()
        };
        let back = json_roundtrip_filter(&f);
        prop_assert_eq!(f, back);
    }

    #[test]
    fn prop_filter_tag_mode_all_json(sev_bits in 0u8..5, tag in "[a-z]{2,6}") {
        let _ = (sev_bits, tag);
        let f = FindingFilter {
            tag_mode: TagMode::All,
            include_tags: vec![Arc::from("web"), Arc::from("auth")],
            ..Default::default()
        };
        let back = json_roundtrip_filter(&f);
        prop_assert_eq!(f, back);
    }

    #[test]
    fn prop_filter_include_kind_json(sev_bits in 0u8..5, tag in "[a-z]{2,6}") {
        let _ = (sev_bits, tag);
        let f = FindingFilter {
            include_kinds: vec![FindingKind::Vulnerability],
            ..Default::default()
        };
        let back = json_roundtrip_filter(&f);
        prop_assert_eq!(f, back);
    }

    #[test]
    fn prop_filter_exclude_kind_json(sev_bits in 0u8..5, tag in "[a-z]{2,6}") {
        let _ = (sev_bits, tag);
        let f = FindingFilter {
            exclude_kinds: vec![FindingKind::Exposure],
            ..Default::default()
        };
        let back = json_roundtrip_filter(&f);
        prop_assert_eq!(f, back);
    }

    #[test]
    fn prop_filter_min_confidence_json(sev_bits in 0u8..5, tag in "[a-z]{2,6}") {
        let _ = (sev_bits, tag);
        let f = FindingFilter {
            min_confidence: Some(0.5),
            ..Default::default()
        };
        let back = json_roundtrip_filter(&f);
        prop_assert_eq!(f, back);
    }

    #[test]
    fn prop_filter_date_range_json(sev_bits in 0u8..5, tag in "[a-z]{2,6}") {
        let _ = (sev_bits, tag);
        let f = FindingFilter {
            start_date: Some(Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap()),
            end_date: Some(Utc.with_ymd_and_hms(2030, 12, 31, 23, 59, 59).unwrap()),
            ..Default::default()
        };
        let back = json_roundtrip_filter(&f);
        prop_assert_eq!(f, back);
    }

    #[test]
    fn prop_filter_combined_json(sev_bits in 0u8..5, tag in "[a-z]{2,6}") {
        let _ = (sev_bits, tag);
        let f = FindingFilter {
            min_severity: Some(Severity::Medium),
            exclude_scanners: vec![Arc::from("gamma")],
            include_tags: vec![Arc::from("web")],
            tag_mode: TagMode::Any,
            exclude_kinds: vec![FindingKind::Other],
            min_confidence: Some(0.1),
            ..Default::default()
        };
        let back = json_roundtrip_filter(&f);
        prop_assert_eq!(f, back);
    }

    #[test]
    fn prop_filter_min_severity_subset(_case in 0u8..1) {
        let findings = sample_findings();
        let full = filter(&findings, &FindingFilter::default());
        let cfg = FindingFilter {
            min_severity: Some(Severity::High),
            ..Default::default()
        };
        let subset = filter(&findings, &cfg);
        prop_assert!(subset.len() <= full.len());
    }

    #[test]
    fn prop_filter_exclude_scanner_subset(_case in 0u8..1) {
        let findings = sample_findings();
        let full = filter(&findings, &FindingFilter::default());
        let cfg = FindingFilter {
            exclude_scanners: vec![Arc::from("alpha")],
            ..Default::default()
        };
        let subset = filter(&findings, &cfg);
        prop_assert!(subset.len() <= full.len());
        for f in &subset {
            prop_assert!(full.iter().any(|x| std::ptr::eq(*x, *f)));
        }
    }

    #[test]
    fn prop_filter_include_scanner_subset(_case in 0u8..1) {
        let findings = sample_findings();
        let full = filter(&findings, &FindingFilter::default());
        let cfg = FindingFilter {
            include_scanners: vec![Arc::from("beta")],
            ..Default::default()
        };
        let subset = filter(&findings, &cfg);
        prop_assert!(subset.len() <= full.len());
    }

    #[test]
    fn prop_filter_include_tag_any_subset(_case in 0u8..1) {
        let findings = sample_findings();
        let full = filter(&findings, &FindingFilter::default());
        let cfg = FindingFilter {
            include_tags: vec![Arc::from("dns")],
            tag_mode: TagMode::Any,
            ..Default::default()
        };
        let subset = filter(&findings, &cfg);
        prop_assert!(subset.len() <= full.len());
    }

    #[test]
    fn prop_filter_include_tag_all_subset(_case in 0u8..1) {
        let findings = sample_findings();
        let full = filter(&findings, &FindingFilter::default());
        let cfg = FindingFilter {
            include_tags: vec![Arc::from("web"), Arc::from("auth")],
            tag_mode: TagMode::All,
            ..Default::default()
        };
        let subset = filter(&findings, &cfg);
        prop_assert!(subset.len() <= full.len());
    }

    #[test]
    fn prop_filter_exclude_tag_subset(_case in 0u8..1) {
        let findings = sample_findings();
        let full = filter(&findings, &FindingFilter::default());
        let cfg = FindingFilter {
            exclude_tags: vec![Arc::from("web")],
            ..Default::default()
        };
        let subset = filter(&findings, &cfg);
        prop_assert!(subset.len() <= full.len());
    }

    #[test]
    fn prop_filter_include_kind_subset(_case in 0u8..1) {
        let findings = sample_findings();
        let full = filter(&findings, &FindingFilter::default());
        let cfg = FindingFilter {
            include_kinds: vec![FindingKind::Vulnerability, FindingKind::Misconfiguration],
            ..Default::default()
        };
        let subset = filter(&findings, &cfg);
        prop_assert!(subset.len() <= full.len());
    }

    #[test]
    fn prop_filter_exclude_kind_subset(_case in 0u8..1) {
        let findings = sample_findings();
        let full = filter(&findings, &FindingFilter::default());
        let cfg = FindingFilter {
            exclude_kinds: vec![FindingKind::Exposure],
            ..Default::default()
        };
        let subset = filter(&findings, &cfg);
        prop_assert!(subset.len() <= full.len());
    }

    #[test]
    fn prop_filter_min_confidence_subset(_case in 0u8..1) {
        let findings = sample_findings();
        let full = filter(&findings, &FindingFilter::default());
        let cfg = FindingFilter {
            min_confidence: Some(0.5),
            ..Default::default()
        };
        let subset = filter(&findings, &cfg);
        prop_assert!(subset.len() <= full.len());
    }

    #[test]
    fn prop_filter_max_severity_subset(_case in 0u8..1) {
        let findings = sample_findings();
        let full = filter(&findings, &FindingFilter::default());
        let cfg = FindingFilter {
            max_severity: Some(Severity::Medium),
            ..Default::default()
        };
        let subset = filter(&findings, &cfg);
        prop_assert!(subset.len() <= full.len());
    }

    #[test]
    fn prop_filter_toml_roundtrip(sev_bits in 0u8..5) {
        let toml = format!(
            "min_severity = \"{}\"\nexclude_scanners = [\"noise\"]\n",
            match sev_bits % 5 {
                0 => "info",
                1 => "low",
                2 => "medium",
                3 => "high",
                _ => "critical",
            }
        );
        let parsed = FindingFilter::from_toml(&toml).expect("toml");
        let back = json_roundtrip_filter(&parsed);
        prop_assert_eq!(parsed, back);
    }

    #[test]
    fn prop_filter_empty_toml_is_default(_case in 0u8..1) {
        let f = FindingFilter::from_toml("").expect("empty");
        prop_assert_eq!(f, FindingFilter::default());
    }

    #[test]
    fn prop_filter_empty_passes_all(_case in 0u8..1) {
        let findings = sample_findings();
        let out = filter(&findings, &FindingFilter::default());
        prop_assert_eq!(out.len(), findings.len());
    }

    #[test]
    fn prop_filter_min_severity_excludes_lower(_case in 0u8..1) {
        let findings = sample_findings();
        let cfg = FindingFilter {
            min_severity: Some(Severity::High),
            ..Default::default()
        };
        let out = filter(&findings, &cfg);
        for f in out {
            prop_assert!(f.severity() >= Severity::High);
        }
    }

    #[test]
    fn prop_filter_exclude_scanner_never_lists_excluded(scanner in "[a-z]{4,8}") {
        let f = Finding::builder(&scanner, "https://x.test", Severity::Low)
            .title("t")
            .build()
            .unwrap();
        let cfg = FindingFilter {
            exclude_scanners: vec![Arc::from(scanner.as_str())],
            ..Default::default()
        };
        let findings = [f];
        let out = filter(&findings, &cfg);
        prop_assert!(out.is_empty());
    }

    #[test]
    fn prop_filter_include_scanner_only_lists_allowed(
        scanner in "[a-z]{4,8}",
        other in "[a-z]{4,8}",
    ) {
        prop_assume!(scanner != other);
        let findings = vec![
            Finding::builder(&scanner, "https://a/", Severity::Low)
                .title("a")
                .build()
                .unwrap(),
            Finding::builder(&other, "https://b/", Severity::Low)
                .title("b")
                .build()
                .unwrap(),
        ];
        let cfg = FindingFilter {
            include_scanners: vec![Arc::from(scanner.as_str())],
            ..Default::default()
        };
        let out = filter(&findings, &cfg);
        prop_assert_eq!(out.len(), 1);
        prop_assert_eq!(out[0].scanner(), scanner.as_str());
    }

    #[test]
    fn prop_filter_idempotent_application(_case in 0u8..1) {
        let findings = sample_findings();
        let cfg = FindingFilter {
            min_severity: Some(Severity::Medium),
            include_tags: vec![Arc::from("web")],
            tag_mode: TagMode::Any,
            ..Default::default()
        };
        let once = filter(&findings, &cfg);
        let once_owned: Vec<Finding> = once.iter().map(|r| (*r).clone()).collect();
        let twice = filter(&once_owned, &cfg);
        prop_assert_eq!(once.len(), twice.len());
    }

    #[test]
    fn prop_filter_display_contains_configured_severity(sev_bits in 0u8..5) {
        let sev = Severity::try_from(sev_bits).unwrap();
        let f = FindingFilter {
            min_severity: Some(sev),
            ..Default::default()
        };
        let s = format!("{f}");
        prop_assert!(s.contains("min_severity"));
    }
}
