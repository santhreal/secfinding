//! Serialization and deserialization for [`Finding`].

use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

use crate::evidence::Evidence;
use crate::kind::FindingKind;
use crate::location::Location;
use crate::severity::Severity;
use crate::status::FindingStatus;

use super::error::FindingBuildError;
use super::types::{Finding, FindingConfig, FORMAT_VERSION};
use super::validate::{
    validate_confidence, validate_cve, validate_cvss_score, validate_cwe, validate_detail,
    validate_scanner, validate_target, validate_title,
};

/// Default UUID generator for deserialization.
pub(crate) fn default_uuid() -> Uuid {
    Uuid::new_v4()
}

/// Default timestamp generator for deserialization.
pub(crate) fn default_timestamp() -> DateTime<Utc> {
    Utc::now()
}

/// Intermediate raw representation used to validate and normalize deserialized JSON.
#[derive(Deserialize)]
pub(crate) struct RawFinding {
    #[serde(default)]
    version: Option<u32>,
    #[serde(default)]
    id: Option<Uuid>,
    scanner: String,
    target: String,
    severity: Severity,
    title: String,
    #[serde(default)]
    detail: Option<String>,
    #[serde(rename = "type")]
    #[serde(default)]
    kind: Option<FindingKind>,
    #[serde(default)]
    status: Option<FindingStatus>,
    #[serde(default)]
    evidence: Vec<Evidence>,
    #[serde(default)]
    location: Option<Location>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    timestamp: Option<DateTime<Utc>>,
    #[serde(default)]
    cve_ids: Vec<String>,
    #[serde(default)]
    cwe_ids: Vec<String>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    confidence: Option<f64>,
    #[serde(default)]
    cvss_score: Option<f64>,
    #[serde(default)]
    scan_id: Option<String>,
    #[serde(default)]
    exploit_hint: Option<String>,
    #[serde(default)]
    remediation: Option<String>,
    #[serde(default)]
    matched_values: Vec<String>,
}

impl Finding {
    /// Convert from `RawFinding` with default configuration.
    pub(crate) fn try_from_raw(raw: RawFinding) -> Result<Self, FindingBuildError> {
        Self::try_from_raw_with_config(raw, &FindingConfig::default())
    }

    /// Convert from `RawFinding` with custom configuration.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn try_from_raw_with_config(
        raw: RawFinding,
        config: &FindingConfig,
    ) -> Result<Self, FindingBuildError> {
        // Reject unknown format versions outright. Silently accepting
        // an arbitrary version would let stale or forged producers
        // emit Finding-shaped JSON that this crate then trusts  -
        // audit finding `verify_deserialization_rejects_unknown_version`.
        if let Some(v) = raw.version {
            if v != FORMAT_VERSION {
                return Err(FindingBuildError::UnsupportedVersion {
                    actual: v,
                    expected: FORMAT_VERSION,
                });
            }
        }
        let title = raw.title.trim_start_matches('\u{FEFF}').to_string();
        let detail = raw
            .detail
            .unwrap_or_default()
            .trim_start_matches('\u{FEFF}')
            .to_string();
        validate_scanner(&raw.scanner, config)?;
        validate_target(&raw.target, config)?;
        validate_title(&title, config)?;
        validate_detail(&detail, config)?;
        let confidence = validate_confidence(raw.confidence)?;
        let cvss_score = validate_cvss_score(raw.cvss_score)?;
        for cve in &raw.cve_ids {
            validate_cve(cve)?;
        }
        for cwe in &raw.cwe_ids {
            validate_cwe(cwe)?;
        }

        if raw.evidence.len() > config.max_evidence_count {
            return Err(FindingBuildError::TooManyItems {
                field: "evidence",
                max: config.max_evidence_count,
            });
        }
        if raw.tags.len() > config.max_tags_count {
            return Err(FindingBuildError::TooManyItems {
                field: "tags",
                max: config.max_tags_count,
            });
        }
        if raw.cve_ids.len() > config.max_cve_count {
            return Err(FindingBuildError::TooManyItems {
                field: "cve_ids",
                max: config.max_cve_count,
            });
        }
        if raw.cwe_ids.len() > config.max_cwe_count {
            return Err(FindingBuildError::TooManyItems {
                field: "cwe_ids",
                max: config.max_cwe_count,
            });
        }
        if raw.references.len() > config.max_references_count {
            return Err(FindingBuildError::TooManyItems {
                field: "references",
                max: config.max_references_count,
            });
        }
        if raw.matched_values.len() > config.max_matched_values_count {
            return Err(FindingBuildError::TooManyItems {
                field: "matched_values",
                max: config.max_matched_values_count,
            });
        }

        let mut tags = raw.tags;
        tags.sort_unstable();
        tags.dedup();
        let mut cve_ids = raw.cve_ids;
        cve_ids.sort_unstable();
        cve_ids.dedup();
        let mut merged_cwes = raw.cwe_ids;
        merged_cwes.sort_unstable();
        merged_cwes.dedup();
        let mut matched_values = raw.matched_values;
        matched_values.sort_unstable();
        matched_values.dedup();
        // References are sorted + deduped like every other list field
        // (cve_ids/cwe_ids/matched_values) so deserialized findings are
        // deterministic and free of duplicate references.
        let mut references = raw.references;
        references.sort_unstable();
        references.dedup();

        Ok(Finding {
            version: raw.version.unwrap_or(FORMAT_VERSION),
            id: raw.id.unwrap_or_else(default_uuid),
            scanner: std::sync::Arc::from(raw.scanner),
            target: std::sync::Arc::from(raw.target),
            severity: raw.severity,
            title: std::sync::Arc::from(title),
            detail: std::sync::Arc::from(detail),
            kind: raw.kind.unwrap_or(FindingKind::Unclassified),
            status: raw.status.unwrap_or_default(),
            evidence: raw.evidence,
            location: raw.location,
            tags: tags.into_iter().map(std::sync::Arc::from).collect(),
            timestamp: raw.timestamp.unwrap_or_else(default_timestamp),
            cve_ids: cve_ids.into_iter().map(std::sync::Arc::from).collect(),
            cwe_ids: merged_cwes.into_iter().map(std::sync::Arc::from).collect(),
            references: references.into_iter().map(std::sync::Arc::from).collect(),
            confidence,
            cvss_score,
            scan_id: raw.scan_id.map(std::sync::Arc::from),
            exploit_hint: raw.exploit_hint.map(std::sync::Arc::from),
            remediation: raw.remediation.map(std::sync::Arc::from),
            matched_values: matched_values
                .into_iter()
                .map(std::sync::Arc::from)
                .collect(),
        })
    }
}

impl<'de> serde::Deserialize<'de> for Finding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let raw = RawFinding::deserialize(deserializer).map_err(serde::de::Error::custom)?;
        Finding::try_from_raw(raw).map_err(serde::de::Error::custom)
    }
}
