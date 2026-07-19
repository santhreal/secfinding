//! Core types for security findings.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::evidence::Evidence;
use crate::kind::FindingKind;
use crate::location::Location;
use crate::severity::Severity;
use crate::status::FindingStatus;

/// Current version of the finding format.
pub const FORMAT_VERSION: u32 = 1;

/// Configuration for finding validation limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct FindingConfig {
    /// Maximum allowed length for scanner name.
    pub max_scanner_len: usize,
    /// Maximum allowed length for target.
    pub max_target_len: usize,
    /// Maximum allowed length for title.
    pub max_title_len: usize,
    /// Maximum allowed length for detail.
    pub max_detail_len: usize,
    /// Maximum allowed number of evidence items.
    pub max_evidence_count: usize,
    /// Maximum allowed number of tags.
    pub max_tags_count: usize,
    /// Maximum allowed number of CVE identifiers.
    pub max_cve_count: usize,
    /// Maximum allowed number of CWE identifiers.
    pub max_cwe_count: usize,
    /// Maximum allowed number of references.
    pub max_references_count: usize,
    /// Maximum allowed number of matched values.
    pub max_matched_values_count: usize,
}

impl Default for FindingConfig {
    fn default() -> Self {
        Self {
            max_scanner_len: 1024,
            max_target_len: 65_536,
            max_title_len: 10_240,
            max_detail_len: 1_048_576,
            max_evidence_count: 10_000,
            max_tags_count: 10_000,
            max_cve_count: 100,
            max_cwe_count: 100,
            max_references_count: 1_000,
            max_matched_values_count: 10_000,
        }
    }
}

/// A single security finding produced by any Santh tool.
///
/// This is the universal output format. Whether the finding comes from
/// Gossan (discovery), Karyx (routing), Calyx (templates), Sear (SAST),
/// jsdet (JS malware), or a binding (sqlmap-rs), it produces a `Finding`.
///
/// # Examples
///
/// ```
/// use secfinding::{Finding, FindingKind, Severity};
///
/// let finding = Finding::builder("scanner", "https://example.com", Severity::High)
///     .title("SQL injection")
///     .kind(FindingKind::Vulnerability)
///     .build()?;
///
/// assert_eq!(finding.kind(), FindingKind::Vulnerability);
/// # Ok::<(), secfinding::FindingBuildError>(())
/// ```
///
/// # Thread Safety
/// `Finding` is `Send` and `Sync`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    /// Format version.
    pub version: u32,

    /// Unique identifier for this finding instance.
    pub(crate) id: Uuid,

    /// Which tool/scanner produced this finding.
    pub(crate) scanner: Arc<str>,

    /// The target that was scanned (URL, file path, domain, IP, etc.).
    pub(crate) target: Arc<str>,

    /// Finding severity.
    pub(crate) severity: Severity,

    /// Short human-readable title.
    pub(crate) title: Arc<str>,

    /// Detailed description of the finding.
    pub(crate) detail: Arc<str>,

    /// Classification of the finding.
    #[serde(rename = "type")]
    pub(crate) kind: FindingKind,

    /// Current lifecycle state of the finding.
    pub(crate) status: FindingStatus,

    /// Typed evidence proving the finding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) evidence: Vec<Evidence>,

    /// Specific location in a file where the finding was discovered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) location: Option<Location>,

    /// Free-form tags for categorization and filtering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) tags: Vec<Arc<str>>,

    /// When the finding was produced.
    pub(crate) timestamp: DateTime<Utc>,

    /// CVE identifiers associated with this finding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) cve_ids: Vec<Arc<str>>,

    /// CWE identifiers associated with this finding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) cwe_ids: Vec<Arc<str>>,

    /// Reference URLs (advisories, documentation, etc.).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) references: Vec<Arc<str>>,

    /// Statistical confidence score (0.0 to 1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) confidence: Option<f64>,

    /// CVSS score (0.0 to 10.0) if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cvss_score: Option<f64>,

    /// ID of the scan run that produced this finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) scan_id: Option<Arc<str>>,

    /// Ready-to-run command demonstrating exploitability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) exploit_hint: Option<Arc<str>>,

    /// Actionable remediation guidance for the developer or operator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) remediation: Option<Arc<str>>,

    /// Specific values that triggered the finding (matched strings, payloads, etc.).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) matched_values: Vec<Arc<str>>,
}

impl Finding {
    /// Get the finding version.
    pub fn version(&self) -> u32 {
        self.version
    }
    /// Get the finding unique identifier.
    pub fn id(&self) -> Uuid {
        self.id
    }
    /// Get the scanner name.
    pub fn scanner(&self) -> &str {
        &self.scanner
    }
    /// Get the target scanned.
    pub fn target(&self) -> &str {
        &self.target
    }
    /// Get the finding severity.
    pub fn severity(&self) -> Severity {
        self.severity
    }
    /// Get the finding title.
    pub fn title(&self) -> &str {
        &self.title
    }
    /// Get the finding detailed description.
    pub fn detail(&self) -> &str {
        &self.detail
    }
    /// Get the finding classification.
    pub fn kind(&self) -> FindingKind {
        self.kind
    }
    /// Get the finding status.
    pub fn status(&self) -> FindingStatus {
        self.status
    }
    /// Get the evidence associated with the finding.
    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }
    /// Get the location of the finding.
    pub fn location(&self) -> Option<&Location> {
        self.location.as_ref()
    }
    /// Get the tags associated with the finding.
    pub fn tags(&self) -> &[Arc<str>] {
        &self.tags
    }
    /// Get the timestamp when the finding was produced.
    pub fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
    /// Get the CVE identifiers associated with the finding.
    pub fn cve_ids(&self) -> &[Arc<str>] {
        &self.cve_ids
    }
    /// Get the CWE identifiers associated with the finding.
    pub fn cwe_ids(&self) -> &[Arc<str>] {
        &self.cwe_ids
    }
    /// Get the reference URLs associated with the finding.
    pub fn references(&self) -> &[Arc<str>] {
        &self.references
    }
    /// Get the statistical confidence score (0.0 to 1.0).
    pub fn confidence(&self) -> Option<f64> {
        self.confidence
    }
    /// Get the CVSS score (0.0 to 10.0).
    pub fn cvss_score(&self) -> Option<f64> {
        self.cvss_score
    }
    /// Get the scan ID that produced this finding.
    pub fn scan_id(&self) -> Option<&str> {
        self.scan_id.as_deref()
    }
    /// Get the exploit hint.
    pub fn exploit_hint(&self) -> Option<&str> {
        self.exploit_hint.as_deref()
    }
    /// Get the remediation guidance.
    pub fn remediation(&self) -> Option<&str> {
        self.remediation.as_deref()
    }
    /// Get the matched values that triggered the finding.
    pub fn matched_values(&self) -> &[Arc<str>] {
        &self.matched_values
    }
}

impl std::hash::Hash for Finding {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.version.hash(state);
        self.id.hash(state);
        self.scanner.hash(state);
        self.target.hash(state);
        self.severity.hash(state);
        self.title.hash(state);
        self.detail.hash(state);
        self.kind.hash(state);
        self.status.hash(state);
        self.evidence.hash(state);
        self.location.hash(state);
        self.tags.hash(state);
        self.timestamp.hash(state);
        self.cve_ids.hash(state);
        self.cwe_ids.hash(state);
        self.references.hash(state);
        // Normalise +0.0 / -0.0 to a single bit pattern before
        // hashing. The derived PartialEq treats them as equal under
        // f64 == semantics, so the Hash contract demands the same
        // (`verify_hash_contract_for_signed_zero`). A bare `to_bits()`
        // call distinguishes them and breaks HashMap/HashSet lookups
        // round-tripped through JSON.
        if let Some(c) = self.confidence {
            let bits = if c == 0.0 {
                0.0_f64.to_bits()
            } else {
                c.to_bits()
            };
            state.write_u64(bits);
        }
        if let Some(s) = self.cvss_score {
            let bits = if s == 0.0 {
                0.0_f64.to_bits()
            } else {
                s.to_bits()
            };
            state.write_u64(bits);
        }
        self.scan_id.hash(state);
        self.exploit_hint.hash(state);
        self.remediation.hash(state);
        self.matched_values.hash(state);
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
        self.severity
            .cmp(&other.severity)
            .then_with(|| self.scanner.cmp(&other.scanner))
            .then_with(|| self.target.cmp(&other.target))
            .then_with(|| self.title.cmp(&other.title))
            .then_with(|| self.id.cmp(&other.id))
    }
}

/// Maximum length for field display.
const MAX_DISPLAY_LEN: usize = 200;

/// Returns a redacted version of a string field suitable for logging.
///
/// Known secret patterns (API keys, tokens, JWTs, `password=` pairs, PEM keys)
/// and URL credentials (`scheme://user:pass@host`) are masked via the canonical
/// [`santh_error::redact_secrets`], then the result is truncated for display.
/// Truncation respects UTF-8 char boundaries so multibyte input cannot panic.
pub(crate) fn redact_for_display(s: &str) -> String {
    let result = santh_error::redact_secrets(s);

    if result.len() > MAX_DISPLAY_LEN {
        // Back off to the nearest char boundary at or below the limit so a
        // multibyte codepoint straddling MAX_DISPLAY_LEN never panics the slice.
        let mut end = MAX_DISPLAY_LEN;
        while end > 0 && !result.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...[truncated]", &result[..end])
    } else {
        result
    }
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let target_safe = redact_for_display(&self.target);
        let title_safe = redact_for_display(&self.title);

        write!(
            f,
            "[{}] [{}] {} {} {}",
            self.severity.label(),
            self.status.label(),
            self.kind,
            target_safe,
            title_safe
        )?;
        if let Some(loc) = &self.location {
            write!(f, " at {loc}")?;
        }
        Ok(())
    }
}
