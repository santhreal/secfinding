//! The universal Finding type  -  every Santh tool produces these.

mod builder;
mod error;
mod ops;
mod serialize;
mod types;
mod validate;

pub use builder::FindingBuilder;
pub use error::FindingBuildError;
pub use types::{Finding, FindingConfig};

#[cfg(test)]
mod tests {
    use crate::{
        evidence::Evidence, kind::FindingKind, location::Location, severity::Severity,
        status::FindingStatus, Finding, FindingBuildError,
    };

    #[test]
    fn builder_basic() {
        let f = Finding::builder("gossan", "https://example.com", Severity::High)
            .title("Open Admin Panel")
            .detail("Admin panel accessible without authentication")
            .kind(FindingKind::Exposure)
            .tag("admin")
            .build()
            .unwrap();

        assert_eq!(f.scanner(), "gossan");
        assert_eq!(f.severity(), Severity::High);
        assert_eq!(f.kind(), FindingKind::Exposure);
        assert_eq!(f.tags()[0].as_ref(), "admin");
    }

    #[test]
    fn builder_empty_fields_fall_back_to_empty() {
        let f = Finding::builder("gossan", "https://example.com", Severity::Low)
            .title("title")
            .build()
            .unwrap();

        assert_eq!(f.title(), "title");
        assert_eq!(f.detail(), "");
        assert_eq!(f.kind(), FindingKind::Unclassified);
        assert_eq!(f.evidence().len(), 0);
    }

    #[test]
    fn builder_full_and_duplicate_tags_are_deduped() {
        let f = Finding::builder("calyx", "https://target.com", Severity::Critical)
            .title("Remote Code Execution")
            .detail("Template injection in search parameter")
            .kind(FindingKind::Vulnerability)
            .evidence(Evidence::http_status(500).unwrap())
            .tag("rce")
            .tag("rce")
            .tag("ssti")
            .tag("ssti")
            .cve("CVE-2024-12345")
            .cwe("CWE-94")
            .reference("https://nvd.nist.gov/vuln/detail/CVE-2024-12345")
            .confidence(0.95)
            .exploit_hint("curl https://target.com/search?q={{7*7}}")
            .remediation("Escape template input before rendering")
            .matched_value("49")
            .matched_value("49")
            .build()
            .unwrap();

        assert_eq!(f.title(), "Remote Code Execution");
        assert_eq!(f.cve_ids()[0].as_ref(), "CVE-2024-12345");
        assert_eq!(f.cwe_ids()[0].as_ref(), "CWE-94");
        assert_eq!(
            f.references()[0].as_ref(),
            "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"
        );
        assert_eq!(f.confidence(), Some(0.95));
        assert_eq!(
            f.remediation(),
            Some("Escape template input before rendering")
        );
        assert_eq!(f.tags()[0].as_ref(), "rce");
        assert_eq!(f.tags()[1].as_ref(), "ssti");
        assert_eq!(f.matched_values()[0].as_ref(), "49");
    }

    #[test]
    fn builder_rejects_very_long_cve_identifier() {
        let long = "CVE-".to_string() + &"9".repeat(30_000);
        let f = Finding::builder("scan", "target", Severity::Medium)
            .title("test")
            .cve(long.clone())
            .build();

        assert!(f.is_err());
    }

    #[test]
    fn serde_roundtrip_preserves_findings() {
        // Out-of-range confidence used to silently clamp; the audit
        // (`verify_confidence_rejects_out_of_range`) made it an error
        //  -  the test now asserts both the rejection AND that a valid
        // value round-trips losslessly.
        let err = Finding::builder("test", "target", Severity::Medium)
            .title("test")
            .confidence(1.5)
            .build();
        assert!(matches!(err, Err(FindingBuildError::InvalidConfidence)));

        let f = Finding::builder("test", "target", Severity::Medium)
            .title("test")
            .confidence(0.85)
            .reference("https://example.com/advisory")
            .cwe("CWE-89")
            .tag("cfg")
            .matched_value("needle")
            .build()
            .unwrap();

        let json = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(back.scanner(), "test");
        assert_eq!(back.severity(), Severity::Medium);
        assert_eq!(back.confidence(), Some(0.85));
        assert_eq!(back.cwe_ids()[0].as_ref(), "CWE-89");
        assert_eq!(
            back.references()[0].as_ref(),
            "https://example.com/advisory"
        );
        assert_eq!(back.tags()[0].as_ref(), "cfg");
        assert_eq!(back.matched_values()[0].as_ref(), "needle");
    }

    #[test]
    fn new_convenience_constructor() {
        let f = Finding::new("scanner", "target", Severity::Info, "Title", "Detail").unwrap();
        assert_eq!(f.scanner(), "scanner");
        assert_eq!(f.target(), "target");
        assert_eq!(f.severity(), Severity::Info);
        assert_eq!(f.title(), "Title");
        assert_eq!(f.detail(), "Detail");
        assert!(!f.id().is_nil());
    }

    #[test]
    fn each_finding_gets_unique_id() {
        let a = Finding::new("s", "t", Severity::Low, "title", "").unwrap();
        let b = Finding::new("s", "t", Severity::Low, "title", "").unwrap();
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn debug_impl_contains_title() {
        let f = Finding::new("scan", "target.com", Severity::High, "SQLi Found", "").unwrap();
        let debug = format!("{f:?}");
        assert!(debug.contains("SQLi Found"));
    }

    #[test]
    fn unicode_in_all_fields() {
        let f = Finding::builder("スキャナ", "https://例え.jp", Severity::Critical)
            .title("日本語の脆弱性")
            .detail("これはテストです")
            .tag("テスト")
            .build()
            .unwrap();
        assert_eq!(f.scanner(), "スキャナ");
        assert_eq!(f.title(), "日本語の脆弱性");
        let json = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(back.title(), f.title());
    }

    #[test]
    fn empty_strings_everywhere() {
        let f = Finding::new("", "", Severity::Info, "", "");
        assert!(f.is_err());
    }

    #[test]
    fn confidence_nan_fails() {
        let f = Finding::builder("s", "t", Severity::Info)
            .title("t")
            .confidence(f64::NAN)
            .build();
        assert!(f.is_err());
    }

    #[test]
    fn multiple_evidence_items() {
        let f = Finding::builder("s", "t", Severity::Medium)
            .title("title")
            .evidence(Evidence::http_status(200).unwrap())
            .evidence(Evidence::http_status(500).unwrap())
            .build()
            .unwrap();
        assert_eq!(f.evidence().len(), 2);
    }

    #[test]
    fn multiple_cves() {
        let f = Finding::builder("s", "t", Severity::High)
            .title("title")
            .cve("CVE-2024-0001")
            .cve("CVE-2024-0002")
            .cve("CVE-2024-0003")
            .build()
            .unwrap();
        assert_eq!(f.cve_ids().len(), 3);
        assert_eq!(f.cve_ids()[0].as_ref(), "CVE-2024-0001");
        assert_eq!(f.cve_ids()[1].as_ref(), "CVE-2024-0002");
        assert_eq!(f.cve_ids()[2].as_ref(), "CVE-2024-0003");
    }

    #[test]
    fn new_fields_and_builder_methods() {
        let loc = Location::new("src/main.rs")
            .unwrap()
            .line(10)
            .unwrap()
            .column(5)
            .unwrap();
        let f = Finding::builder("scanner", "target", Severity::Medium)
            .title("title")
            .status(FindingStatus::Confirmed)
            .location(loc.clone())
            .cvss_score(7.5)
            .scan_id("scan-123")
            .add_tags(vec!["tag1", "tag2"])
            .add_cves(vec!["CVE-2024-1111", "CVE-2024-2222"])
            .build()
            .unwrap();

        assert_eq!(f.status(), FindingStatus::Confirmed);
        assert_eq!(f.location(), Some(&loc));
        assert_eq!(f.cvss_score(), Some(7.5));
        assert_eq!(f.scan_id(), Some("scan-123"));
        assert!(f.tags().iter().any(|t| t.as_ref() == "tag1"));
        assert!(f.tags().iter().any(|t| t.as_ref() == "tag2"));
        assert_eq!(f.cve_ids().len(), 2);
    }

    #[test]
    fn hash_implementation_with_floats() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        fn calculate_hash<T: Hash>(t: &T) -> u64 {
            let mut s = DefaultHasher::new();
            t.hash(&mut s);
            s.finish()
        }

        let f1 = Finding::builder("s", "t", Severity::Info)
            .title("t")
            .confidence(0.5)
            .cvss_score(5.0)
            .build()
            .unwrap();

        let f2 = Finding::builder("s", "t", Severity::Info)
            .title("t")
            .confidence(0.5)
            .cvss_score(5.1) // different
            .build()
            .unwrap();

        let h1 = calculate_hash(&f1);
        let h2 = calculate_hash(&f2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn display_output_contains_new_fields() {
        let loc = Location::new("lib.rs").unwrap().line(42).unwrap();
        let f = Finding::builder("scanner", "target.com", Severity::Critical)
            .title("VULN")
            .status(FindingStatus::Resolved)
            .location(loc)
            .build()
            .unwrap();

        let s = f.to_string();
        assert!(s.contains("[CRIT]"));
        assert!(s.contains("[FIXD]"));
        assert!(s.contains("at lib.rs:42"));
    }
}
