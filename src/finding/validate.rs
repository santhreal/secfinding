//! Validation logic for finding fields.

use super::error::FindingBuildError;
use super::types::FindingConfig;

/// Minimum byte-length of a CVE identifier (`"CVE-XX-Y"` = 8 chars).
const CVE_MIN_LEN: usize = 8;
/// Maximum byte-length of a CVE identifier.  Current longest observed
/// CVE is ~20 chars; 30 gives headroom for any future schema.
const CVE_MAX_LEN: usize = 30;

/// Minimum byte-length of a CWE identifier (`"CWE-X"` = 5 chars).
const CWE_MIN_LEN: usize = 5;
/// Maximum byte-length of a CWE identifier.
const CWE_MAX_LEN: usize = 30;

fn validate_non_empty_field(
    value: &str,
    error: FindingBuildError,
) -> Result<(), FindingBuildError> {
    if value.is_empty() {
        return Err(error);
    }
    Ok(())
}

fn validate_max_len(value: &str, field: &'static str, max: usize) -> Result<(), FindingBuildError> {
    if value.len() > max {
        return Err(FindingBuildError::FieldTooLong { field, max });
    }
    Ok(())
}

/// Unicode bidirectional formatting controls that enable visual text spoofing
/// (the "Trojan Source" class, CVE-2021-42574). Overrides, embeddings, and
/// isolates can reorder rendered text so a report shows a different filename,
/// extension, or payload than the underlying bytes - e.g. `report_txt<RLO>gpj.exe`
/// renders as `report_exe.jpg`. None are legitimate in a finding field, so they
/// are rejected rather than stripped (rejecting fails closed and surfaces the
/// tampered input).
const BIDI_CONTROLS: [char; 10] = [
    '\u{202A}', // LEFT-TO-RIGHT EMBEDDING
    '\u{202B}', // RIGHT-TO-LEFT EMBEDDING
    '\u{202C}', // POP DIRECTIONAL FORMATTING
    '\u{202D}', // LEFT-TO-RIGHT OVERRIDE
    '\u{202E}', // RIGHT-TO-LEFT OVERRIDE
    '\u{2066}', // LEFT-TO-RIGHT ISOLATE
    '\u{2067}', // RIGHT-TO-LEFT ISOLATE
    '\u{2068}', // FIRST STRONG ISOLATE
    '\u{2069}', // POP DIRECTIONAL ISOLATE
    '\u{061C}', // ARABIC LETTER MARK
];

fn validate_string_content(value: &str, field: &'static str) -> Result<(), FindingBuildError> {
    if value.contains('\0') {
        return Err(FindingBuildError::InvalidField {
            field,
            reason: "cannot contain null bytes",
        });
    }
    if value.contains('\u{FFFD}') {
        return Err(FindingBuildError::InvalidField {
            field,
            reason: "cannot contain Unicode replacement character (U+FFFD)",
        });
    }
    if value.chars().any(|c| BIDI_CONTROLS.contains(&c)) {
        return Err(FindingBuildError::InvalidField {
            field,
            reason:
                "cannot contain Unicode bidirectional control characters (text-spoofing vector)",
        });
    }
    Ok(())
}

/// Validate scanner field.
pub(crate) fn validate_scanner(
    scanner: &str,
    config: &FindingConfig,
) -> Result<(), FindingBuildError> {
    validate_non_empty_field(scanner, FindingBuildError::EmptyScanner)?;
    validate_max_len(scanner, "scanner", config.max_scanner_len)?;
    validate_string_content(scanner, "scanner")
}

/// Validate target field.
pub(crate) fn validate_target(
    target: &str,
    config: &FindingConfig,
) -> Result<(), FindingBuildError> {
    validate_non_empty_field(target, FindingBuildError::EmptyTarget)?;
    validate_max_len(target, "target", config.max_target_len)?;
    validate_string_content(target, "target")
}

/// Validate title field.
pub(crate) fn validate_title(title: &str, config: &FindingConfig) -> Result<(), FindingBuildError> {
    validate_non_empty_field(title, FindingBuildError::EmptyTitle)?;
    validate_max_len(title, "title", config.max_title_len)?;
    validate_string_content(title, "title")
}

/// Validate detail field.
pub(crate) fn validate_detail(
    detail: &str,
    config: &FindingConfig,
) -> Result<(), FindingBuildError> {
    validate_max_len(detail, "detail", config.max_detail_len)?;
    validate_string_content(detail, "detail")
}

/// Validate CVE identifier format.
pub(crate) fn validate_cve(cve: &str) -> Result<(), FindingBuildError> {
    if !cve.starts_with("CVE-") || cve.len() > CVE_MAX_LEN || cve.len() < CVE_MIN_LEN {
        return Err(FindingBuildError::InvalidCveFormat(cve.to_string()));
    }
    validate_string_content(cve, "cve_ids")
}

/// Validate CWE identifier format.
pub(crate) fn validate_cwe(cwe: &str) -> Result<(), FindingBuildError> {
    if !cwe.starts_with("CWE-") || cwe.len() > CWE_MAX_LEN || cwe.len() < CWE_MIN_LEN {
        return Err(FindingBuildError::InvalidCweFormat(cwe.to_string()));
    }
    validate_string_content(cwe, "cwe_ids")
}

/// Validate confidence score is finite and within `[0.0, 1.0]`.
///
/// Out-of-range values return an error; silently clamping was an
/// audit finding (`verify_confidence_rejects_out_of_range`)  -  a
/// caller asking for `confidence(1.5)` has a bug, not a UI hint.
pub(crate) fn validate_confidence(
    confidence: Option<f64>,
) -> Result<Option<f64>, FindingBuildError> {
    match confidence {
        Some(conf) if !conf.is_finite() => Err(FindingBuildError::InvalidConfidence),
        Some(conf) if !(0.0..=1.0).contains(&conf) => Err(FindingBuildError::InvalidConfidence),
        Some(conf) => Ok(Some(conf)),
        None => Ok(None),
    }
}

/// Validate CVSS score is finite and within `[0.0, 10.0]`.
///
/// Out-of-range values return an error; silently clamping was an
/// audit finding (`verify_cvss_rejects_out_of_range`).
pub(crate) fn validate_cvss_score(
    cvss_score: Option<f64>,
) -> Result<Option<f64>, FindingBuildError> {
    match cvss_score {
        Some(score) if !score.is_finite() => Err(FindingBuildError::InvalidCvssScore),
        Some(score) if !(0.0..=10.0).contains(&score) => Err(FindingBuildError::InvalidCvssScore),
        Some(score) => Ok(Some(score)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ANTI-RIG: pin CVE length bounds so a change to `CVE_MIN_LEN` or
    /// `CVE_MAX_LEN` is immediately visible via a test failure.
    #[test]
    fn cve_bounds_are_pinned() {
        assert_eq!(
            CVE_MIN_LEN, 8,
            "CVE_MIN_LEN changed, update bounds and this test"
        );
        assert_eq!(
            CVE_MAX_LEN, 30,
            "CVE_MAX_LEN changed, update bounds and this test"
        );
    }

    /// ANTI-RIG: pin CWE length bounds.
    #[test]
    fn cwe_bounds_are_pinned() {
        assert_eq!(
            CWE_MIN_LEN, 5,
            "CWE_MIN_LEN changed, update bounds and this test"
        );
        assert_eq!(
            CWE_MAX_LEN, 30,
            "CWE_MAX_LEN changed, update bounds and this test"
        );
    }

    #[test]
    fn validate_cve_accepts_valid_and_rejects_invalid() {
        // At minimum length (8 chars): "CVE-XX-Y" = 8 chars
        assert!(validate_cve("CVE-10-1").is_ok(), "8-char CVE must be valid");
        // Exactly at max length
        let at_max = format!("CVE-{}", "1".repeat(CVE_MAX_LEN - 4));
        assert!(validate_cve(&at_max).is_ok());
        // One char over max
        let over_max = format!("CVE-{}", "1".repeat(CVE_MAX_LEN - 4 + 1));
        assert!(validate_cve(&over_max).is_err());
        // Too short (7 chars)
        assert!(validate_cve("CVE-1-").is_err());
        // Wrong prefix
        assert!(validate_cve("cve-2024-1234").is_err());
        assert!(validate_cve("NVD-2024-1234").is_err());
    }

    #[test]
    fn validate_cwe_accepts_valid_and_rejects_invalid() {
        // At minimum length (5 chars): "CWE-X"
        assert!(validate_cwe("CWE-1").is_ok(), "5-char CWE must be valid");
        // Too short (4 chars)
        assert!(validate_cwe("CWE-").is_err());
        // Wrong prefix
        assert!(validate_cwe("cwe-89").is_err());
        assert!(validate_cwe("NVD-CWE-89").is_err());
    }
}
