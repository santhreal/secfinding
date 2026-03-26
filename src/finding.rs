//! The universal Finding type — every Santh tool produces these.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::evidence::Evidence;
use crate::kind::FindingKind;
use crate::severity::Severity;

/// A single security finding produced by any Santh tool.
///
/// This is the universal output format. Whether the finding comes from
/// Gossan (discovery), Karyx (routing), Calyx (templates), Sear (SAST),
/// jsdet (JS malware), or a binding (sqlmap-rs), it produces a `Finding`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for this finding instance.
    pub id: Uuid,

    /// Which tool/scanner produced this finding.
    pub scanner: String,

    /// The target that was scanned (URL, file path, domain, IP, etc.).
    pub target: String,

    /// Finding severity.
    pub severity: Severity,

    /// Short human-readable title.
    pub title: String,

    /// Detailed description of the finding.
    pub detail: String,

    /// Classification of the finding.
    #[serde(rename = "type")]
    pub kind: FindingKind,

    /// Typed evidence proving the finding.
    pub evidence: Vec<Evidence>,

    /// Free-form tags for categorization and filtering.
    #[serde(default)]
    pub tags: Vec<String>,

    /// When the finding was produced.
    pub timestamp: DateTime<Utc>,

    /// CVE identifiers associated with this finding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cve_ids: Vec<String>,

    /// Reference URLs (advisories, documentation, etc.).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,

    /// Statistical confidence score (0.0 to 1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,

    /// Ready-to-run command demonstrating exploitability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exploit_hint: Option<String>,

    /// Specific values that triggered the finding (matched strings, payloads, etc.).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_values: Vec<String>,
}

/// Builder for constructing findings with a fluent API.
///
/// Required fields are set in [`Finding::builder`]. Optional fields
/// are added via chained methods.
#[derive(Debug, Clone, PartialEq)]
pub struct FindingBuilder {
    scanner: String,
    target: String,
    severity: Severity,
    title: Option<String>,
    detail: Option<String>,
    kind: FindingKind,
    evidence: Vec<Evidence>,
    tags: Vec<String>,
    cve_ids: Vec<String>,
    references: Vec<String>,
    confidence: Option<f64>,
    exploit_hint: Option<String>,
    matched_values: Vec<String>,
}

impl Finding {
    /// Start building a finding with the three required fields.
    #[must_use]
    pub fn builder(
        scanner: impl Into<String>,
        target: impl Into<String>,
        severity: Severity,
    ) -> FindingBuilder {
        FindingBuilder {
            scanner: scanner.into(),
            target: target.into(),
            severity,
            title: None,
            detail: None,
            kind: FindingKind::Other,
            evidence: Vec::new(),
            tags: Vec::new(),
            cve_ids: Vec::new(),
            references: Vec::new(),
            confidence: None,
            exploit_hint: None,
            matched_values: Vec::new(),
        }
    }

    /// Quick constructor for simple findings without the builder.
    pub fn new(
        scanner: impl Into<String>,
        target: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Result<Self, &'static str> {
        let scanner = scanner.into();
        let target = target.into();
        let title = title.into();

        if scanner.is_empty() {
            return Err("scanner cannot be empty");
        }
        if target.is_empty() {
            return Err("target cannot be empty");
        }
        if title.is_empty() {
            return Err("title cannot be empty");
        }

        Ok(Self {
            id: Uuid::new_v4(),
            scanner,
            target,
            severity,
            title,
            detail: detail.into(),
            kind: FindingKind::Other,
            evidence: Vec::new(),
            tags: Vec::new(),
            timestamp: Utc::now(),
            cve_ids: Vec::new(),
            references: Vec::new(),
            confidence: None,
            exploit_hint: None,
            matched_values: Vec::new(),
        })
    }
}

impl FindingBuilder {
    /// Set the finding title.
    #[must_use]
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Set the finding detail/description.
    #[must_use]
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Set the finding kind.
    #[must_use]
    pub fn kind(mut self, kind: FindingKind) -> Self {
        self.kind = kind;
        self
    }

    /// Add a piece of evidence.
    #[must_use]
    pub fn evidence(mut self, ev: Evidence) -> Self {
        self.evidence.push(ev);
        self
    }

    /// Add a tag.
    #[must_use]
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Add a CVE identifier.
    #[must_use]
    pub fn cve(mut self, cve: impl Into<String>) -> Self {
        self.cve_ids.push(cve.into());
        self
    }

    /// Add a reference URL.
    #[must_use]
    pub fn reference(mut self, url: impl Into<String>) -> Self {
        self.references.push(url.into());
        self
    }

    /// Set the confidence score (0.0 to 1.0).
    #[must_use]
    pub fn confidence(mut self, score: f64) -> Self {
        self.confidence = Some(score);
        self
    }

    /// Set a ready-to-run exploit/PoC command.
    #[must_use]
    pub fn exploit_hint(mut self, hint: impl Into<String>) -> Self {
        self.exploit_hint = Some(hint.into());
        self
    }

    /// Add a matched value (payload, string, etc.).
    #[must_use]
    pub fn matched_value(mut self, value: impl Into<String>) -> Self {
        self.matched_values.push(value.into());
        self
    }

    /// Build the finding.
    pub fn build(mut self) -> Result<Finding, &'static str> {
        if self.scanner.is_empty() {
            return Err("scanner cannot be empty");
        }
        if self.target.is_empty() {
            return Err("target cannot be empty");
        }
        let title = self.title.unwrap_or_default();
        if title.is_empty() {
            return Err("title cannot be empty");
        }

        if let Some(conf) = self.confidence {
            if conf.is_nan() {
                return Err("confidence cannot be NaN");
            }
            self.confidence = Some(conf.clamp(0.0, 1.0));
        }

        for cve in &self.cve_ids {
            if !cve.starts_with("CVE-") || cve.len() > 30 || cve.len() < 8 {
                return Err("invalid CVE format");
            }
        }

        self.tags.sort_unstable();
        self.tags.dedup();

        Ok(Finding {
            id: Uuid::new_v4(),
            scanner: self.scanner,
            target: self.target,
            severity: self.severity,
            title,
            detail: self.detail.unwrap_or_default(),
            kind: self.kind,
            evidence: self.evidence,
            tags: self.tags,
            timestamp: Utc::now(),
            cve_ids: self.cve_ids,
            references: self.references,
            confidence: self.confidence,
            exploit_hint: self.exploit_hint,
            matched_values: self.matched_values,
        })
    }
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let title = if self.title.is_empty() {
            "(untitled)"
        } else {
            &self.title
        };
        let tags = if self.tags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", self.tags.join(", "))
        };
        let summary = format!("{title}{tags}");

        write!(
            f,
            "[{}] {} -> {} ({}): {}",
            self.severity, self.scanner, self.target, title, summary
        )
    }
}

impl TryFrom<Finding> for serde_json::Value {
    type Error = serde_json::Error;

    fn try_from(finding: Finding) -> Result<Self, Self::Error> {
        serde_json::to_value(finding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_basic() {
        let f = Finding::builder("gossan", "https://example.com", Severity::High)
            .title("Open Admin Panel")
            .detail("Admin panel accessible without authentication")
            .kind(FindingKind::Exposure)
            .tag("admin")
            .build()
            .unwrap();

        assert_eq!(f.scanner, "gossan");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.kind, FindingKind::Exposure);
        assert_eq!(f.tags, vec!["admin"]);
    }

    #[test]
    fn builder_empty_fields_fall_back_to_empty() {
        let f = Finding::builder("gossan", "https://example.com", Severity::Low)
            .title("title")
            .build()
            .unwrap();

        assert_eq!(f.title, "title");
        assert_eq!(f.detail, "");
        assert_eq!(f.kind, FindingKind::Other);
        assert_eq!(f.evidence.len(), 0);
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
            .reference("https://nvd.nist.gov/vuln/detail/CVE-2024-12345")
            .confidence(0.95)
            .exploit_hint("curl https://target.com/search?q={{7*7}}")
            .matched_value("49")
            .matched_value("49")
            .build()
            .unwrap();

        assert_eq!(f.title, "Remote Code Execution");
        assert_eq!(f.cve_ids, vec!["CVE-2024-12345"]);
        assert_eq!(
            f.references,
            vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-12345"]
        );
        assert_eq!(f.confidence, Some(0.95));
        assert_eq!(f.tags, vec!["rce", "ssti"]);
        assert_eq!(f.matched_values, vec!["49", "49"]);
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
        let f = Finding::builder("test", "target", Severity::Medium)
            .title("test")
            .confidence(1.5)
            .reference("https://example.com/advisory")
            .tag("cfg")
            .matched_value("needle")
            .build()
            .unwrap();

        let json = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(back.scanner, "test");
        assert_eq!(back.severity, Severity::Medium);
        assert_eq!(back.confidence, Some(1.0));
        assert_eq!(back.references, vec!["https://example.com/advisory"]);
        assert_eq!(back.tags, vec!["cfg"]);
        assert_eq!(back.matched_values, vec!["needle"]);
    }

    #[test]
    fn new_convenience_constructor() {
        let f = Finding::new("scanner", "target", Severity::Info, "Title", "Detail").unwrap();
        assert_eq!(f.scanner, "scanner");
        assert_eq!(f.target, "target");
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.title, "Title");
        assert_eq!(f.detail, "Detail");
        assert!(!f.id.is_nil());
    }

    #[test]
    fn each_finding_gets_unique_id() {
        let a = Finding::new("s", "t", Severity::Low, "title", "").unwrap();
        let b = Finding::new("s", "t", Severity::Low, "title", "").unwrap();
        assert_ne!(a.id, b.id);
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
        assert_eq!(f.scanner, "スキャナ");
        assert_eq!(f.title, "日本語の脆弱性");
        let json = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(back.title, f.title);
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
        assert_eq!(f.evidence.len(), 2);
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
        assert_eq!(f.cve_ids.len(), 3);
        assert_eq!(f.cve_ids[0], "CVE-2024-0001");
        assert_eq!(f.cve_ids[1], "CVE-2024-0002");
        assert_eq!(f.cve_ids[2], "CVE-2024-0003");
    }
}

impl Eq for Finding {}

impl PartialOrd for Finding {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Finding {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.severity.cmp(&other.severity)
            .then_with(|| self.scanner.cmp(&other.scanner))
            .then_with(|| self.target.cmp(&other.target))
            .then_with(|| self.title.cmp(&other.title))
            .then_with(|| self.id.cmp(&other.id))
    }
}
