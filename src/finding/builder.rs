//! Builder for constructing [`Finding`] values with a fluent API.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::evidence::Evidence;
use crate::kind::FindingKind;
use crate::location::Location;
use crate::severity::Severity;
use crate::status::FindingStatus;

use super::error::FindingBuildError;
use super::types::{redact_for_display, Finding, FindingConfig, FORMAT_VERSION};
use super::validate::{
    validate_confidence, validate_cve, validate_cvss_score, validate_cwe, validate_detail,
    validate_scanner, validate_target, validate_title,
};

/// Builder for constructing findings with a fluent API.
///
/// Required fields are set in [`Finding::builder`]. Optional fields
/// are added via chained methods.
///
/// # Examples
///
/// ```
/// use secfinding::{Finding, Severity};
///
/// let finding = Finding::builder("scanner", "target", Severity::Medium)
///     .title("Leaked token")
///     .tag("secret")
///     .build()?;
///
/// assert_eq!(finding.tags()[0].as_ref(), "secret");
/// # Ok::<(), secfinding::FindingBuildError>(())
/// ```
///
/// # Thread Safety
/// `FindingBuilder` is `Send` and `Sync`.
#[derive(Debug, Clone, PartialEq)]
#[must_use = "FindingBuilder does nothing until you call build()"]
pub struct FindingBuilder {
    pub(crate) config: FindingConfig,
    pub(crate) scanner: String,
    pub(crate) target: String,
    pub(crate) severity: Severity,
    pub(crate) title: Option<String>,
    pub(crate) detail: Option<String>,
    pub(crate) kind: FindingKind,
    pub(crate) status: FindingStatus,
    pub(crate) evidence: Vec<Evidence>,
    pub(crate) location: Option<Location>,
    // List items are stored directly as Arc<str> (the Finding's own type) so a
    // caller holding Arc<str> values (e.g. Finding::merge_chain concatenating two
    // findings' tags/CVEs) passes them by cheap Arc clone instead of round-
    // tripping through an owned String and re-allocating in build().
    pub(crate) tags: Vec<Arc<str>>,
    pub(crate) cve_ids: Vec<Arc<str>>,
    pub(crate) cwe_ids: Vec<Arc<str>>,
    pub(crate) references: Vec<Arc<str>>,
    pub(crate) confidence: Option<f64>,
    pub(crate) cvss_score: Option<f64>,
    pub(crate) scan_id: Option<String>,
    pub(crate) exploit_hint: Option<String>,
    pub(crate) remediation: Option<String>,
    pub(crate) matched_values: Vec<Arc<str>>,
    pub(crate) timestamp: Option<DateTime<Utc>>,
}

impl FindingBuilder {
    /// Builds the finding or logs an error and returns None if validation fails.
    /// This is useful in contexts where panicking or returning a Result is undesirable.
    pub fn build_or_log(self) -> Option<Finding> {
        match self.build() {
            Ok(f) => Some(f),
            Err(e) => {
                tracing::error!(error = %e, "Failed to build Finding");
                None
            }
        }
    }

    /// Set a custom configuration for this builder.
    pub fn config(mut self, config: FindingConfig) -> Self {
        self.config = config;
        self
    }

    /// Set the finding title.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Set the finding detail/description.
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Set the finding kind.
    pub fn kind(mut self, kind: FindingKind) -> Self {
        self.kind = kind;
        self
    }

    /// Set the finding status.
    pub fn status(mut self, status: FindingStatus) -> Self {
        self.status = status;
        self
    }

    /// Add a piece of evidence.
    pub fn evidence(mut self, ev: Evidence) -> Self {
        self.evidence.push(ev);
        self
    }

    /// Set the finding location.
    pub fn location(mut self, loc: Location) -> Self {
        self.location = Some(loc);
        self
    }

    /// Add a tag.
    pub fn tag(mut self, tag: impl Into<Arc<str>>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Add multiple tags.
    pub fn add_tags(mut self, tags: impl IntoIterator<Item = impl Into<Arc<str>>>) -> Self {
        self.tags.extend(tags.into_iter().map(Into::into));
        self
    }

    /// Add a CVE identifier.
    pub fn cve(mut self, cve: impl Into<Arc<str>>) -> Self {
        self.cve_ids.push(cve.into());
        self
    }

    /// Add multiple CVE identifiers.
    pub fn add_cves(mut self, cves: impl IntoIterator<Item = impl Into<Arc<str>>>) -> Self {
        self.cve_ids.extend(cves.into_iter().map(Into::into));
        self
    }

    /// Add a CWE identifier.
    pub fn cwe(mut self, cwe: impl Into<Arc<str>>) -> Self {
        self.cwe_ids.push(cwe.into());
        self
    }

    /// Add a reference URL.
    pub fn reference(mut self, url: impl Into<Arc<str>>) -> Self {
        self.references.push(url.into());
        self
    }

    /// Set the confidence score (0.0 to 1.0).
    pub fn confidence(mut self, score: f64) -> Self {
        self.confidence = Some(score);
        self
    }

    /// Set the CVSS score (0.0 to 10.0).
    pub fn cvss_score(mut self, score: f64) -> Self {
        self.cvss_score = Some(score);
        self
    }

    /// Set the scan run ID.
    pub fn scan_id(mut self, id: impl Into<String>) -> Self {
        self.scan_id = Some(id.into());
        self
    }

    /// Set the timestamp.
    pub fn timestamp(mut self, ts: DateTime<Utc>) -> Self {
        self.timestamp = Some(ts);
        self
    }

    /// Set a ready-to-run exploit/PoC command.
    pub fn exploit_hint(mut self, hint: impl Into<String>) -> Self {
        self.exploit_hint = Some(hint.into());
        self
    }

    /// Set remediation guidance.
    pub fn remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    /// Add a matched value (payload, string, etc.).
    pub fn matched_value(mut self, value: impl Into<Arc<str>>) -> Self {
        self.matched_values.push(value.into());
        self
    }

    /// Build the finding.
    pub fn build(mut self) -> Result<Finding, FindingBuildError> {
        validate_scanner(&self.scanner, &self.config)?;
        validate_target(&self.target, &self.config)?;
        let title = self
            .title
            .unwrap_or_default()
            .trim_start_matches('\u{FEFF}')
            .to_string();
        validate_title(&title, &self.config)?;
        let detail = self
            .detail
            .unwrap_or_default()
            .trim_start_matches('\u{FEFF}')
            .to_string();
        validate_detail(&detail, &self.config)?;

        self.confidence = validate_confidence(self.confidence)?;
        self.cvss_score = validate_cvss_score(self.cvss_score)?;

        for cve in &self.cve_ids {
            validate_cve(cve)?;
        }
        for cwe in &self.cwe_ids {
            validate_cwe(cwe)?;
        }

        if self.evidence.len() > self.config.max_evidence_count {
            return Err(FindingBuildError::TooManyItems {
                field: "evidence",
                max: self.config.max_evidence_count,
            });
        }
        if self.tags.len() > self.config.max_tags_count {
            return Err(FindingBuildError::TooManyItems {
                field: "tags",
                max: self.config.max_tags_count,
            });
        }
        if self.cve_ids.len() > self.config.max_cve_count {
            return Err(FindingBuildError::TooManyItems {
                field: "cve_ids",
                max: self.config.max_cve_count,
            });
        }
        if self.cwe_ids.len() > self.config.max_cwe_count {
            return Err(FindingBuildError::TooManyItems {
                field: "cwe_ids",
                max: self.config.max_cwe_count,
            });
        }
        if self.references.len() > self.config.max_references_count {
            return Err(FindingBuildError::TooManyItems {
                field: "references",
                max: self.config.max_references_count,
            });
        }
        if self.matched_values.len() > self.config.max_matched_values_count {
            return Err(FindingBuildError::TooManyItems {
                field: "matched_values",
                max: self.config.max_matched_values_count,
            });
        }

        self.tags.sort_unstable();
        self.tags.dedup();
        self.cve_ids.sort_unstable();
        self.cve_ids.dedup();
        self.cwe_ids.sort_unstable();
        self.cwe_ids.dedup();
        self.matched_values.sort_unstable();
        self.matched_values.dedup();
        self.references.sort_unstable();
        self.references.dedup();

        Ok(Finding {
            version: FORMAT_VERSION,
            id: uuid::Uuid::new_v4(),
            scanner: Arc::from(self.scanner),
            target: Arc::from(self.target),
            severity: self.severity,
            title: Arc::from(title),
            detail: Arc::from(detail),
            kind: self.kind,
            status: self.status,
            evidence: self.evidence,
            location: self.location,
            tags: self.tags,
            timestamp: self.timestamp.unwrap_or_else(Utc::now),
            cve_ids: self.cve_ids,
            cwe_ids: self.cwe_ids,
            references: self.references,
            confidence: self.confidence,
            cvss_score: self.cvss_score,
            scan_id: self.scan_id.map(Arc::from),
            exploit_hint: self.exploit_hint.map(Arc::from),
            remediation: self.remediation.map(Arc::from),
            matched_values: self.matched_values,
        })
    }
}

impl Finding {
    /// Start building a finding with the three required fields.
    pub fn builder(
        scanner: impl Into<String>,
        target: impl Into<String>,
        severity: Severity,
    ) -> FindingBuilder {
        let s = scanner.into();
        let t = target.into();
        FindingBuilder {
            config: FindingConfig::default(),
            scanner: s,
            target: t,
            severity,
            title: None,
            detail: None,
            kind: FindingKind::Unclassified,
            status: FindingStatus::Open,
            evidence: Vec::new(),
            location: None,
            tags: Vec::new(),
            cve_ids: Vec::new(),
            cwe_ids: Vec::new(),
            references: Vec::new(),
            confidence: None,
            cvss_score: None,
            scan_id: None,
            exploit_hint: None,
            remediation: None,
            matched_values: Vec::new(),
            timestamp: None,
        }
    }

    /// Quick constructor for simple findings without the builder, using the
    /// default [`FindingConfig`] validation limits.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the required fields are empty or exceed crate limits.
    pub fn new(
        scanner: impl Into<String>,
        target: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Result<Self, FindingBuildError> {
        Self::new_with_config(
            scanner,
            target,
            severity,
            title,
            detail,
            &FindingConfig::default(),
        )
    }

    /// Quick constructor for simple findings with caller-supplied [`FindingConfig`]
    /// validation limits (the single owner of the construction logic; [`new`](Self::new)
    /// delegates here with the default config).
    ///
    /// # Errors
    ///
    /// Returns an error if any of the required fields are empty or exceed the
    /// limits in `config`.
    pub fn new_with_config(
        scanner: impl Into<String>,
        target: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        detail: impl Into<String>,
        config: &FindingConfig,
    ) -> Result<Self, FindingBuildError> {
        let scanner = scanner.into();
        let target = target.into();
        let title = title.into().trim_start_matches('\u{FEFF}').to_string();
        let detail = detail.into().trim_start_matches('\u{FEFF}').to_string();

        validate_scanner(&scanner, config)?;
        validate_target(&target, config)?;
        validate_title(&title, config)?;
        validate_detail(&detail, config)?;

        Ok(Self {
            version: FORMAT_VERSION,
            id: uuid::Uuid::new_v4(),
            scanner: Arc::from(scanner),
            target: Arc::from(target),
            severity,
            title: Arc::from(title),
            detail: Arc::from(detail),
            kind: FindingKind::Unclassified,
            status: FindingStatus::Open,
            evidence: Vec::new(),
            location: None,
            tags: Vec::new(),
            timestamp: Utc::now(),
            cve_ids: Vec::new(),
            cwe_ids: Vec::new(),
            references: Vec::new(),
            confidence: None,
            cvss_score: None,
            scan_id: None,
            exploit_hint: None,
            remediation: None,
            matched_values: Vec::new(),
        })
    }
}

impl std::fmt::Display for FindingBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scanner_safe = redact_for_display(&self.scanner);
        let target_safe = redact_for_display(&self.target);
        let title_safe = self
            .title
            .as_deref()
            .map_or_else(|| "<unset>".to_string(), redact_for_display);

        write!(
            f,
            "FindingBuilder(scanner={scanner_safe}, target={target_safe}, severity={}, title={title_safe})",
            self.severity
        )
    }
}

#[cfg(test)]
mod new_with_config_tests {
    use crate::{Finding, FindingConfig, Severity};

    #[test]
    fn new_with_config_enforces_custom_title_limit() {
        let title = "0123456789"; // 10 chars
        let tiny = FindingConfig {
            max_title_len: 5,
            ..FindingConfig::default()
        };
        // The custom config rejects the 10-char title...
        let too_long =
            Finding::new_with_config("scanner", "target", Severity::High, title, "detail", &tiny);
        assert!(
            too_long.is_err(),
            "custom max_title_len=5 must reject a 10-char title"
        );

        // ...while the default-config new() accepts the same title, proving the
        // supplied config (not the default) drives validation.
        let ok = Finding::new("scanner", "target", Severity::High, title, "detail");
        assert!(ok.is_ok(), "default config accepts the same title: {ok:?}");
    }
}
