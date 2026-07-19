//! The `Reportable` trait  -  implement this on YOUR finding type to get
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
//! }
//! ```

use crate::Severity;
use std::sync::Arc;

/// Trait for any finding-like type that can be rendered into reports.
///
/// Implement this on your domain-specific finding type. The `secreport`
/// crate accepts `&[impl Reportable]` for all output formats.
///
/// Only `scanner`, `target`, `severity`, and `title` are required.
/// Everything else has sensible defaults.
///
/// # Thread Safety
/// This trait does not impose `Send` or `Sync` bounds. Thread-safety depends on
/// the concrete implementing type.
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
    ///
    /// The default implementation returns an empty string slice
    /// (zero-length slice borrowed from `title()`).  Implementors
    /// that have a meaningful description should override this.
    fn detail(&self) -> &str {
        &self.title()[..0]
    }
    /// CWE identifiers (e.g. `["CWE-89"]`).
    fn cwe_ids(&self) -> &[Arc<str>] {
        &[]
    }
    /// CVE identifiers.
    fn cve_ids(&self) -> &[Arc<str>] {
        &[]
    }
    /// Free-form tags.
    fn tags(&self) -> &[Arc<str>] {
        &[]
    }
    /// Confidence score 0.0-1.0 (None = not applicable).
    fn confidence(&self) -> Option<f64> {
        None
    }
    /// CVSS score (0.0 to 10.0) if applicable.
    fn cvss_score(&self) -> Option<f64> {
        None
    }
    /// Current lifecycle state of the finding.
    fn status(&self) -> crate::FindingStatus {
        crate::FindingStatus::Open
    }
    /// Specific location in a file where the finding was discovered.
    fn location(&self) -> Option<&crate::Location> {
        None
    }
    /// ID of the scan run that produced this finding.
    fn scan_id(&self) -> Option<&str> {
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

    /// Actionable remediation guidance.
    fn remediation(&self) -> Option<&str> {
        None
    }

    /// Evidence attached to the finding.
    fn evidence(&self) -> &[crate::Evidence] {
        &[]
    }

    /// The domain classification of this finding.
    fn kind(&self) -> crate::FindingKind {
        crate::FindingKind::Unclassified
    }
}

/// Blanket: secfinding's own `Finding` implements `Reportable`.
impl Reportable for crate::Finding {
    fn scanner(&self) -> &str {
        self.scanner()
    }
    fn target(&self) -> &str {
        self.target()
    }
    fn severity(&self) -> Severity {
        self.severity()
    }
    fn title(&self) -> &str {
        self.title()
    }
    fn detail(&self) -> &str {
        self.detail()
    }
    fn cwe_ids(&self) -> &[Arc<str>] {
        self.cwe_ids()
    }
    fn cve_ids(&self) -> &[Arc<str>] {
        self.cve_ids()
    }
    fn tags(&self) -> &[Arc<str>] {
        self.tags()
    }
    fn confidence(&self) -> Option<f64> {
        self.confidence()
    }
    fn cvss_score(&self) -> Option<f64> {
        self.cvss_score()
    }
    fn status(&self) -> crate::FindingStatus {
        self.status()
    }
    fn location(&self) -> Option<&crate::Location> {
        self.location()
    }
    fn scan_id(&self) -> Option<&str> {
        self.scan_id()
    }
    fn exploit_hint(&self) -> Option<&str> {
        self.exploit_hint()
    }
    fn remediation(&self) -> Option<&str> {
        self.remediation()
    }
    fn evidence(&self) -> &[crate::Evidence] {
        self.evidence()
    }
    fn kind(&self) -> crate::FindingKind {
        self.kind()
    }
}
