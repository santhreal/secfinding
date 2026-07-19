//! Configuration-driven finding filters for scan output pipelines.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{Finding, FindingKind, Severity};

/// Configuration for filtering findings from scan output.
///
/// # Examples
///
/// ```
/// use secfinding::{FindingFilter, Severity};
///
/// let filter = FindingFilter {
///     min_severity: Some(Severity::High),
///     exclude_scanners: vec!["noise-scanner".into()],
///     include_tags: vec!["auth".into()],
///     ..Default::default()
/// };
///
/// assert_eq!(filter.min_severity, Some(Severity::High));
/// ```
///
/// # Thread Safety
/// `FindingFilter` is `Send` and `Sync`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FindingFilter {
    /// Minimum severity level (inclusive). Findings below this are removed.
    #[serde(default)]
    pub min_severity: Option<Severity>,

    /// Maximum severity level (inclusive).
    #[serde(default)]
    pub max_severity: Option<Severity>,

    /// Scanner names that must be included. If non-empty, ONLY these scanners are included.
    #[serde(default)]
    pub include_scanners: Vec<Arc<str>>,

    /// Scanner names that must be excluded from results.
    #[serde(default)]
    pub exclude_scanners: Vec<Arc<str>>,

    /// Findings must contain matching tags.
    #[serde(default)]
    pub include_tags: Vec<Arc<str>>,

    /// Findings with any of these tags will be excluded.
    #[serde(default)]
    pub exclude_tags: Vec<Arc<str>>,

    /// Tag matching mode (Any or All). Defaults to Any.
    #[serde(default)]
    pub tag_mode: TagMode,

    /// Only include findings matching these kinds. Empty = all kinds.
    #[serde(default)]
    pub include_kinds: Vec<FindingKind>,

    /// Exclude findings matching these kinds.
    #[serde(default)]
    pub exclude_kinds: Vec<FindingKind>,

    /// Minimum confidence threshold (0.0 to 1.0).
    #[serde(default)]
    pub min_confidence: Option<f64>,

    /// Start of date range (inclusive).
    #[serde(default)]
    pub start_date: Option<DateTime<Utc>>,

    /// End of date range (inclusive).
    #[serde(default)]
    pub end_date: Option<DateTime<Utc>>,
}

/// Mode for tag matching.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TagMode {
    /// Finding must have AT LEAST ONE of the `include_tags`.
    #[default]
    Any,
    /// Finding must have ALL of the `include_tags`.
    All,
}

impl FindingFilter {
    /// Parse a TOML configuration string into a filter.
    ///
    /// # Errors
    ///
    /// Returns an error if the TOML string is malformed or contains invalid values.
    pub fn from_toml(toml: &str) -> Result<Self, String> {
        toml::from_str(toml).map_err(|e| format!("Failed to parse TOML filter config: {e}"))
    }
}

impl std::fmt::Display for FindingFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "min_severity={:?}, max_severity={:?}, include_scanners={}, exclude_scanners={}, include_tags={}, exclude_tags={}, tag_mode={:?}, include_kinds={}, exclude_kinds={}, min_confidence={:?}, start_date={:?}, end_date={:?}",
            self.min_severity,
            self.max_severity,
            self.include_scanners.join(","),
            self.exclude_scanners.join(","),
            self.include_tags.join(","),
            self.exclude_tags.join(","),
            self.tag_mode,
            self.include_kinds.iter().map(|k| format!("{k:?}")).collect::<Vec<_>>().join(","),
            self.exclude_kinds.iter().map(|k| format!("{k:?}")).collect::<Vec<_>>().join(","),
            self.min_confidence,
            self.start_date,
            self.end_date,
        )
    }
}

/// Filter findings by severity, scanner allow/deny list, tags, kinds, confidence, and dates.
#[must_use]
pub fn filter<'a>(findings: &'a [Finding], config: &FindingFilter) -> Vec<&'a Finding> {
    findings
        .iter()
        .filter(|finding| {
            // Severity filter
            if let Some(min) = config.min_severity {
                if finding.severity() < min {
                    return false;
                }
            }
            if let Some(max) = config.max_severity {
                if finding.severity() > max {
                    return false;
                }
            }

            // Scanner filter
            if !config.include_scanners.is_empty()
                && !config
                    .include_scanners
                    .iter()
                    .any(|s| s.as_ref() == finding.scanner())
            {
                return false;
            }
            if config
                .exclude_scanners
                .iter()
                .any(|s| s.as_ref() == finding.scanner())
            {
                return false;
            }

            // Tag filter. finding.tags() is sorted by the builder
            // (FindingBuilder::build calls sort_unstable), so membership is a
            // binary search: O(M log N) instead of the old O(N*M) nested scan.
            if !config.include_tags.is_empty() {
                let matches = match config.tag_mode {
                    TagMode::Any => config
                        .include_tags
                        .iter()
                        .any(|it| finding.tags().binary_search(it).is_ok()),
                    TagMode::All => config
                        .include_tags
                        .iter()
                        .all(|it| finding.tags().binary_search(it).is_ok()),
                };
                if !matches {
                    return false;
                }
            }
            if config
                .exclude_tags
                .iter()
                .any(|et| finding.tags().binary_search(et).is_ok())
            {
                return false;
            }

            // Kind filter
            if !config.include_kinds.is_empty() && !config.include_kinds.contains(&finding.kind()) {
                return false;
            }
            if config.exclude_kinds.contains(&finding.kind()) {
                return false;
            }

            // Confidence filter
            if let Some(min_conf) = config.min_confidence {
                if let Some(conf) = finding.confidence() {
                    if conf < min_conf {
                        return false;
                    }
                } else {
                    // Findings with no confidence score fail the threshold
                    return false;
                }
            }

            // Date filter
            if let Some(start) = config.start_date {
                if finding.timestamp() < start {
                    return false;
                }
            }
            if let Some(end) = config.end_date {
                if finding.timestamp() > end {
                    return false;
                }
            }

            true
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Finding;

    #[test]
    fn filter_applies_severity_scanner_and_tags() {
        let findings = vec![
            Finding::builder("nmap", "https://example.com", Severity::Critical)
                .title("RCE")
                .tag("critical")
                .build()
                .unwrap(),
            Finding::builder("burp", "https://example.com", Severity::High)
                .title("SQLi")
                .tag("sqli")
                .build()
                .unwrap(),
            Finding::builder("trivy", "https://example.org", Severity::Low)
                .title("Info")
                .tag("auth")
                .build()
                .unwrap(),
        ];

        let config = FindingFilter {
            min_severity: Some(Severity::High),
            exclude_scanners: vec!["nmap".into()],
            include_tags: vec!["sqli".into()],
            ..Default::default()
        };

        let filtered = filter(&findings, &config);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].scanner(), "burp");
    }

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
            include_tags: Vec::new(),
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
            min_severity: None,
            exclude_scanners: vec!["a".into()],
            include_tags: Vec::new(),
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
            exclude_scanners: Vec::new(),
            include_tags: Vec::new(),
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
            min_severity: None,
            exclude_scanners: Vec::new(),
            include_tags: vec!["t2".into()],
            ..Default::default()
        };

        let filtered = filter(&findings, &config);
        assert!(filtered.is_empty());
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
}
