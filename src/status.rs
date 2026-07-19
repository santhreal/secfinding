//! Lifecycle status of a security finding.

use serde::{Deserialize, Serialize};

/// Current lifecycle state of a finding.
///
/// # Examples
///
/// ```
/// use secfinding::FindingStatus;
///
/// assert_eq!(FindingStatus::Open.label(), "OPEN");
/// assert_eq!(FindingStatus::Resolved.to_string(), "resolved");
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FindingStatus {
    /// New finding, needs triaging.
    #[default]
    Open,
    /// Manually confirmed to be a real issue.
    Confirmed,
    /// Manually marked as a false positive.
    FalsePositive,
    /// Issue has been fixed or remediated.
    Resolved,
}

impl FindingStatus {
    /// Short label for terminal output.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::Confirmed => "CONF",
            Self::FalsePositive => "F/P",
            Self::Resolved => "FIXD",
        }
    }
}

impl std::fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Open => "open",
            Self::Confirmed => "confirmed",
            Self::FalsePositive => "false_positive",
            Self::Resolved => "resolved",
        };
        f.write_str(s)
    }
}
