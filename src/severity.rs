//! Severity levels for security findings.

use serde::{Deserialize, Serialize};

/// Severity of a security finding.
///
/// Ordered from least to most severe. Supports comparison:
/// `Severity::Critical > Severity::High` is true.
///
/// # Thread Safety
/// `Severity` is `Send` and `Sync`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Severity {
    /// Informational — no security impact, useful context.
    Info,
    /// Low — minor issue, unlikely to be exploitable alone.
    Low,
    /// Medium — real risk, exploitable under certain conditions.
    Medium,
    /// High — serious vulnerability, likely exploitable.
    High,
    /// Critical — immediate risk, trivially exploitable.
    Critical,
}

impl Severity {
    /// Parse from a case-insensitive string.
    ///
    /// Returns `None` for unrecognized values.
    #[must_use]
    pub fn from_str_loose(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("info") || s.eq_ignore_ascii_case("informational") {
            Some(Self::Info)
        } else if s.eq_ignore_ascii_case("low") {
            Some(Self::Low)
        } else if s.eq_ignore_ascii_case("medium") || s.eq_ignore_ascii_case("med") {
            Some(Self::Medium)
        } else if s.eq_ignore_ascii_case("high") {
            Some(Self::High)
        } else if s.eq_ignore_ascii_case("critical") || s.eq_ignore_ascii_case("crit") {
            Some(Self::Critical)
        } else {
            None
        }
    }

    /// Short label for terminal output.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MED",
            Self::High => "HIGH",
            Self::Critical => "CRIT",
        }
    }

    /// SARIF level string.
    #[must_use]
    pub fn sarif_level(&self) -> &'static str {
        match self {
            Self::Critical | Self::High => "error",
            Self::Medium => "warning",
            Self::Low | Self::Info => "note",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        f.write_str(s)
    }
}

impl TryFrom<&str> for Severity {
    type Error = &'static str;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::from_str_loose(s)
            .ok_or("invalid severity. Fix: use `info`, `low`, `medium`, `high`, or `critical`.")
    }
}

impl TryFrom<String> for Severity {
    type Error = &'static str;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_str_loose(s.as_str())
            .ok_or("invalid severity. Fix: use `info`, `low`, `medium`, `high`, or `critical`.")
    }
}

impl TryFrom<u8> for Severity {
    type Error = &'static str;

    fn try_from(n: u8) -> Result<Self, Self::Error> {
        match n {
            0 => Ok(Self::Info),
            1 => Ok(Self::Low),
            2 => Ok(Self::Medium),
            3 => Ok(Self::High),
            4 => Ok(Self::Critical),
            _ => Err("invalid severity. Fix: use a numeric level between 0 and 4."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_and_display() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
        assert_eq!(Severity::Critical.to_string(), "critical");
        assert_eq!(Severity::Info.to_string(), "info");
    }

    #[test]
    fn from_str_loose_variants() {
        assert_eq!(
            Severity::from_str_loose("CRITICAL"),
            Some(Severity::Critical)
        );
        assert_eq!(Severity::from_str_loose("crit"), Some(Severity::Critical));
        assert_eq!(Severity::from_str_loose("med"), Some(Severity::Medium));
        assert_eq!(
            Severity::from_str_loose("informational"),
            Some(Severity::Info)
        );
        assert_eq!(Severity::from_str_loose("bogus"), None);
    }

    #[test]
    fn serde_roundtrip() {
        let json = serde_json::to_string(&Severity::High).unwrap();
        assert_eq!(json, "\"high\"");
        let back: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Severity::High);
    }
}
