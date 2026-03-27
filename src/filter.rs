//! Configuration-driven finding filters for scan output pipelines.

use serde::{Deserialize, Serialize};

use crate::{Finding, Severity};

/// Configuration for filtering findings from scan output.
///
/// # Thread Safety
/// `FindingFilter` is `Send` and `Sync`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingFilter {
    /// Minimum severity level (inclusive). Findings below this are removed.
    #[serde(default)]
    pub min_severity: Option<Severity>,

    /// Scanner names that must be excluded from results.
    #[serde(default)]
    pub exclude_scanners: Vec<String>,

    /// Findings must contain at least one matching tag from this list.
    #[serde(default)]
    pub include_tags: Vec<String>,
}

impl FindingFilter {
    /// Parse a TOML configuration string into a filter.
    ///
    /// # Errors
    /// Returns an error if the TOML string is malformed or contains invalid values.
    #[must_use]
    pub fn from_toml(toml: &str) -> Result<Self, String> {
        toml::from_str(toml).map_err(|e| format!("Failed to parse TOML filter config: {}", e))
    }
}

impl std::fmt::Display for FindingFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "min_severity={:?}, exclude_scanners={}, include_tags={}",
            self.min_severity,
            self.exclude_scanners.join(","),
            self.include_tags.join(",")
        )
    }
}

/// Filter findings by severity, scanner allow/deny list, and tags.
///
/// - `min_severity`: include findings where `finding.severity >= min`.
/// - `exclude_scanners`: remove matching scanners.
/// - `include_tags`: include only findings with at least one matching tag.
#[must_use]
pub fn filter<'a>(findings: &'a [Finding], config: &FindingFilter) -> Vec<&'a Finding> {
    findings
        .iter()
        .filter(|finding| {
            if let Some(min) = config.min_severity {
                if finding.severity < min {
                    return false;
                }
            }

            if config
                .exclude_scanners
                .iter()
                .any(|scanner| scanner == &finding.scanner)
            {
                return false;
            }

            if !config.include_tags.is_empty() {
                let matches_filter = finding
                    .tags
                    .iter()
                    .any(|finding_tag| config.include_tags.iter().any(|tag| tag == finding_tag));
                if !matches_filter {
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
            exclude_scanners: vec!["nmap".to_string()],
            include_tags: vec!["sqli".to_string()],
        };

        let filtered = filter(&findings, &config);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].scanner, "burp");
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
            exclude_scanners: vec!["b".to_string()],
            include_tags: Vec::new(),
        };

        let filtered = filter(&findings, &config);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].scanner, "a");
    }

    #[test]
    fn filter_all_excluded() {
        let findings = vec![Finding::builder("a", "target", Severity::High)
            .title("t")
            .build()
            .unwrap()];
        let config = FindingFilter {
            min_severity: None,
            exclude_scanners: vec!["a".to_string()],
            include_tags: Vec::new(),
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
            include_tags: vec!["t2".to_string()],
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
            exclude_scanners: vec!["nmap".to_string()],
            include_tags: vec!["api".to_string(), "web".to_string()],
        };

        let filtered = filter(&findings, &config);
        // Only the burp critical finding remains (nmap is excluded, burp low is < High)
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].scanner, "burp");
        assert_eq!(filtered[0].severity, Severity::Critical);
    }
}
