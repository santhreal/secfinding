//! Error types for finding construction.

/// Errors that can occur when building a [`Finding`](super::types::Finding).
///
/// # Examples
///
/// ```
/// use secfinding::{Finding, FindingBuildError, Severity};
///
/// let error = Finding::builder("scanner", "target", Severity::High)
///     .build()
///     .unwrap_err();
///
/// assert_eq!(error, FindingBuildError::EmptyTitle);
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum FindingBuildError {
    /// Scanner name is empty.
    EmptyScanner,
    /// Target is empty.
    EmptyTarget,
    /// Title is empty.
    EmptyTitle,
    /// Confidence is NaN.
    InvalidConfidence,
    /// CVSS score is NaN.
    InvalidCvssScore,
    /// CVE identifier format is invalid.
    InvalidCveFormat(String),
    /// CWE identifier format is invalid.
    InvalidCweFormat(String),
    /// Field exceeds maximum length.
    FieldTooLong {
        /// Name of the field that was too long.
        field: &'static str,
        /// Maximum allowed length in bytes.
        max: usize,
    },
    /// Field contains invalid characters or content.
    InvalidField {
        /// Name of the offending field.
        field: &'static str,
        /// Why the field is invalid.
        reason: &'static str,
    },
    /// Field contains too many items.
    TooManyItems {
        /// Name of the field.
        field: &'static str,
        /// Maximum allowed count.
        max: usize,
    },
    /// Deserialized payload declared a Finding format version this
    /// crate does not understand.
    UnsupportedVersion {
        /// Version present in the payload.
        actual: u32,
        /// Version this build of secfinding produces and accepts.
        expected: u32,
    },
}

impl std::fmt::Display for FindingBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyScanner => write!(
                f,
                "scanner cannot be empty. Fix: pass the tool or scanner name that produced the finding."
            ),
            Self::EmptyTarget => write!(
                f,
                "target cannot be empty. Fix: pass the URL, host, file path, or asset identifier that was scanned."
            ),
            Self::EmptyTitle => write!(
                f,
                "title cannot be empty. Fix: provide a short finding summary such as `Exposed admin panel`."
            ),
            Self::InvalidConfidence => write!(
                f,
                "confidence cannot be NaN. Fix: use a finite confidence score between 0.0 and 1.0."
            ),
            Self::InvalidCvssScore => write!(
                f,
                "cvss_score cannot be NaN. Fix: use a finite CVSS score between 0.0 and 10.0."
            ),
            Self::InvalidCveFormat(cve) => {
                write!(f, "invalid CVE format: `{cve}`. Fix: use values like `CVE-2024-12345`.")
            }
            Self::InvalidCweFormat(cwe) => {
                write!(f, "invalid CWE format: `{cwe}`. Fix: use values like `CWE-89`.")
            }
            Self::FieldTooLong { field, max } => write!(
                f,
                "field `{field}` exceeds maximum length of {max} bytes. Fix: shorten or truncate the `{field}` to <= {max} bytes before building the Finding or increase the allowed maximum."
            ),
            Self::InvalidField { field, reason } => {
                write!(f, "field `{field}` is invalid: {reason}. Fix: sanitize the input before building the Finding.")
            }
            Self::TooManyItems { field, max } => write!(
                f,
                "field `{field}` contains too many items (max {max}). Fix: reduce the number of items in `{field}`."
            ),
            Self::UnsupportedVersion { actual, expected } => write!(
                f,
                "unsupported finding format version {actual}, expected {expected}. Fix: update the producing tool to emit version {expected} findings."
            ),
        }
    }
}

impl std::error::Error for FindingBuildError {}
