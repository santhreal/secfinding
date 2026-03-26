//! The `Reportable` trait — implement this on YOUR finding type to get
//! free SARIF/JSON/Markdown output via `secreport`.
//!
//! You do NOT need to use `secfinding::Finding`. Any struct that implements
//! `Reportable` works with the entire reporting pipeline.
//!
//! # Example
//!
//! ```rust
//! use secfinding::{Reportable, Severity};
//!
//! struct MyFinding {
//!     title: String,
//!     sev: u8, // your own severity system
//! }
//!
//! impl Reportable for MyFinding {
//!     fn scanner(&self) -> &str { "my-tool" }
//!     fn target(&self) -> &str { "target" }
//!     fn severity(&self) -> Severity {
//!         if self.sev > 8 { Severity::Critical } else { Severity::Medium }
//!     }
//!     fn title(&self) -> &str { &self.title }
//!     fn detail(&self) -> &str { "" }
//!     fn cwe_ids(&self) -> &[String] { &[] }
//!     fn cve_ids(&self) -> &[String] { &[] }
//!     fn tags(&self) -> &[String] { &[] }
//! }
//! ```

use crate::Severity;

/// Trait for any finding-like type that can be rendered into reports.
///
/// Implement this on your domain-specific finding type. The `secreport`
/// crate accepts `&[impl Reportable]` for all output formats.
///
/// Only `scanner`, `target`, `severity`, and `title` are required.
/// Everything else has sensible defaults.
pub trait Reportable {
    /// Which tool produced this finding.
    fn scanner(&self) -> &str;
    /// What was scanned (URL, file path, package name, etc.).
    fn target(&self) -> &str;
    /// How severe is this finding.
    fn severity(&self) -> Severity;
    /// Short human-readable title.
    fn title(&self) -> &str;
    /// Detailed description.
    #[allow(clippy::unnecessary_literal_bound)]
    fn detail(&self) -> &str {
        ""
    }
    /// CWE identifiers (e.g. `["CWE-89"]`).
    fn cwe_ids(&self) -> &[String];
    /// CVE identifiers.
    fn cve_ids(&self) -> &[String];
    /// Free-form tags.
    fn tags(&self) -> &[String];
    /// Confidence score 0.0-1.0 (None = not applicable).
    fn confidence(&self) -> Option<f64> {
        None
    }
    /// SARIF rule ID (defaults to "scanner/title-slug").
    fn rule_id(&self) -> String {
        format!(
            "{}/{}",
            self.scanner(),
            self.title().to_lowercase().replace(' ', "-")
        )
    }
    /// SARIF severity level string.
    fn sarif_level(&self) -> &str {
        self.severity().sarif_level()
    }
    /// Exploit hint / `PoC` command.
    fn exploit_hint(&self) -> Option<&str> {
        None
    }

    /// Evidence attached to the finding.
    fn evidence(&self) -> &[crate::Evidence] {
        &[]
    }
}

/// Blanket: secfinding's own `Finding` implements `Reportable`.
impl Reportable for crate::Finding {
    fn scanner(&self) -> &str {
        &self.scanner
    }
    fn target(&self) -> &str {
        &self.target
    }
    fn severity(&self) -> Severity {
        self.severity
    }
    fn title(&self) -> &str {
        &self.title
    }
    fn detail(&self) -> &str {
        &self.detail
    }
    fn cwe_ids(&self) -> &[String] {
        &[]
    }
    fn cve_ids(&self) -> &[String] {
        &self.cve_ids
    }
    fn tags(&self) -> &[String] {
        &self.tags
    }
    fn confidence(&self) -> Option<f64> {
        self.confidence
    }
    fn exploit_hint(&self) -> Option<&str> {
        self.exploit_hint.as_deref()
    }
    fn evidence(&self) -> &[crate::Evidence] {
        &self.evidence
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Finding, Severity};

    #[test]
    fn finding_implements_reportable() {
        let f = Finding::new("scanner", "target", Severity::High, "Title", "Detail").unwrap();
        assert_eq!(Reportable::scanner(&f), "scanner");
        assert_eq!(Reportable::target(&f), "target");
        assert_eq!(Reportable::severity(&f), Severity::High);
        assert_eq!(Reportable::title(&f), "Title");
        assert_eq!(Reportable::detail(&f), "Detail");
    }

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
            fn cwe_ids(&self) -> &[String] {
                &[]
            }
            fn cve_ids(&self) -> &[String] {
                &[]
            }
            fn tags(&self) -> &[String] {
                &[]
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
            fn cwe_ids(&self) -> &[String] {
                &[]
            }
            fn cve_ids(&self) -> &[String] {
                &[]
            }
            fn tags(&self) -> &[String] {
                &[]
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
            fn cwe_ids(&self) -> &[String] {
                &[]
            }
            fn cve_ids(&self) -> &[String] {
                &[]
            }
            fn tags(&self) -> &[String] {
                &[]
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
            fn cwe_ids(&self) -> &[String] {
                &[]
            }
            fn cve_ids(&self) -> &[String] {
                &[]
            }
            fn tags(&self) -> &[String] {
                &[]
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
            fn cwe_ids(&self) -> &[String] {
                &[]
            }
            fn cve_ids(&self) -> &[String] {
                &[]
            }
            fn tags(&self) -> &[String] {
                &[]
            }
        }
        let f = Spaces;
        assert_eq!(f.rule_id(), "scan/some-spaces-here");
    }
}
