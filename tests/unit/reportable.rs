use secfinding::{Finding, Reportable, Severity};

#[test]
fn finding_implements_reportable() {
    let f = Finding::builder("scanner", "target", Severity::High)
        .title("Test Finding")
        .detail("Some detail here")
        .build()
        .unwrap();

    assert_eq!(f.scanner(), "scanner");
    assert_eq!(f.target(), "target");
    assert_eq!(f.severity(), Severity::High);
    assert_eq!(f.title(), "Test Finding");
    assert_eq!(f.detail(), "Some detail here");
}

#[test]
fn default_trait_methods_return_none() {
    struct MinimalFinding;

    impl Reportable for MinimalFinding {
        fn scanner(&self) -> &str {
            "min"
        }
        fn target(&self) -> &str {
            "target"
        }
        fn severity(&self) -> Severity {
            Severity::Info
        }
        fn title(&self) -> &str {
            "min"
        }
    }

    let f = MinimalFinding;
    assert!(f.detail().is_empty());
    assert!(f.location().is_none());
    assert!(f.evidence().is_empty());
    assert!(f.cve_ids().is_empty());
    assert!(f.cwe_ids().is_empty());

    assert!(f.cvss_score().is_none());
    assert!(f.exploit_hint().is_none());
    assert!(f.remediation().is_none());
    assert!(f.tags().is_empty());
}

// Ported from the previously dead tests/unit/test_reportable.rs (orphaned behind
// an unwired tests/unit/mod.rs). The custom impls only override the required
// methods; cwe_ids/cve_ids/tags use the trait defaults (which return empty), so
// the stale `-> &[String]` overrides are dropped to match the current
// `-> &[Arc<str>]` signatures.
#[test]
fn custom_type_implements_reportable() {
    struct CustomFinding {
        name: String,
    }

    impl Reportable for CustomFinding {
        fn scanner(&self) -> &str {
            "custom"
        }
        fn target(&self) -> &str {
            "custom-target"
        }
        fn severity(&self) -> Severity {
            Severity::Critical
        }
        fn title(&self) -> &str {
            &self.name
        }
    }

    let f = CustomFinding { name: "XSS".into() };
    assert_eq!(f.scanner(), "custom");
    assert_eq!(f.severity(), Severity::Critical);
    assert_eq!(f.detail(), ""); // default
    assert!(f.tags().is_empty()); // default
    assert!(f.rule_id().contains("xss"));
}

#[test]
fn reportable_defaults_are_sensible() {
    struct Minimal;
    impl Reportable for Minimal {
        fn scanner(&self) -> &str {
            "s"
        }
        fn target(&self) -> &str {
            "t"
        }
        fn severity(&self) -> Severity {
            Severity::Info
        }
        fn title(&self) -> &str {
            "minimal"
        }
    }

    let m = Minimal;
    assert_eq!(m.detail(), "");
    assert!(m.cwe_ids().is_empty());
    assert!(m.cve_ids().is_empty());
    assert!(m.tags().is_empty());
    assert_eq!(m.confidence(), None);
    assert_eq!(m.exploit_hint(), None);
    assert_eq!(m.rule_id(), "s/minimal");
}

#[test]
fn reportable_custom_sarif_level() {
    struct CustomSev;
    impl Reportable for CustomSev {
        fn scanner(&self) -> &str {
            "s"
        }
        fn target(&self) -> &str {
            "t"
        }
        fn severity(&self) -> Severity {
            Severity::Critical
        }
        fn title(&self) -> &str {
            "t"
        }
    }
    let f = CustomSev;
    assert_eq!(f.sarif_level(), "error");
}

#[test]
fn reportable_custom_rule_id() {
    struct CustomRuleId;
    impl Reportable for CustomRuleId {
        fn scanner(&self) -> &str {
            "scanner"
        }
        fn target(&self) -> &str {
            "target"
        }
        fn severity(&self) -> Severity {
            Severity::Info
        }
        fn title(&self) -> &str {
            "MY custom TITLE!"
        }
        fn rule_id(&self) -> String {
            "CUSTOM-RULE-ID".to_string()
        }
    }
    let f = CustomRuleId;
    assert_eq!(f.rule_id(), "CUSTOM-RULE-ID");
}

#[test]
fn reportable_default_rule_id_formatting() {
    struct Spaces;
    impl Reportable for Spaces {
        fn scanner(&self) -> &str {
            "scan"
        }
        fn target(&self) -> &str {
            "target"
        }
        fn severity(&self) -> Severity {
            Severity::Info
        }
        fn title(&self) -> &str {
            "Some spaces here"
        }
    }
    let f = Spaces;
    assert_eq!(f.rule_id(), "scan/some-spaces-here");
}
