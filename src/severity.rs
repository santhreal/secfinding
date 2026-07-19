//! Severity levels for security findings.

use serde::{Deserialize, Serialize};

/// Severity of a security finding.
///
/// Ordered from least to most severe. Supports comparison:
/// `Severity::Critical > Severity::High` is true.
///
/// # Examples
///
/// ```
/// use secfinding::Severity;
///
/// assert!(Severity::Critical > Severity::High);
/// assert_eq!(Severity::try_from("medium"), Ok(Severity::Medium));
/// ```
///
/// # Thread Safety
/// `Severity` is `Send` and `Sync`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Severity {
    /// Informational  -  no security impact, useful context.
    /// `Default` so structs that derive `Default` and contain a
    /// Severity field get the safest possible initial classification:
    /// do-no-harm, no escalation pressure.
    #[default]
    Info,
    /// Low  -  minor issue, unlikely to be exploitable alone.
    Low,
    /// Medium  -  real risk, exploitable under certain conditions.
    Medium,
    /// High  -  serious vulnerability, likely exploitable.
    High,
    /// Critical  -  immediate risk, trivially exploitable.
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
    pub fn label(self) -> &'static str {
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
    pub fn sarif_level(self) -> &'static str {
        match self {
            Self::Critical | Self::High => "error",
            Self::Medium => "warning",
            Self::Low | Self::Info => "note",
        }
    }

    /// `true` when `self` is at or above the supplied minimum
    /// threshold. The shared "min-severity gate" semantic every
    /// scanner CLI implements (`--min-severity high`); kept here so
    /// every consumer agrees on the comparison direction without
    /// each crate re-implementing it (those re-implementations
    /// flipped `Info` between lowest and highest, which is the
    /// correctness bug behind the consolidation audit).
    ///
    /// ```
    /// use secfinding::Severity;
    /// assert!(Severity::Critical.meets(Severity::High));
    /// assert!(!Severity::Low.meets(Severity::High));
    /// assert!(Severity::High.meets(Severity::High));
    /// ```
    #[must_use]
    pub fn meets(self, minimum: Self) -> bool {
        self >= minimum
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
    fn ordering_is_info_lowest_critical_highest() {
        // The correctness-bug surfaced by the dedup audit was crates
        // declaring Critical first under derived `Ord` (giving
        // Critical ordinal 0). Pin the canonical ordering here so a
        // future variant-shuffle can't silently re-invert it.
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
        assert!(Severity::Critical > Severity::Info);
    }

    #[test]
    fn default_is_info() {
        // Documented: `Default = Info` (do-no-harm initial value
        // for any struct that derives Default + contains a Severity
        // field). Pinned here so it can't drift.
        assert_eq!(Severity::default(), Severity::Info);
    }

    #[test]
    fn meets_at_or_above_threshold() {
        assert!(Severity::Critical.meets(Severity::High));
        assert!(Severity::High.meets(Severity::High));
        assert!(Severity::High.meets(Severity::Medium));
        assert!(Severity::Critical.meets(Severity::Info));
    }

    #[test]
    fn meets_below_threshold_is_false() {
        assert!(!Severity::Low.meets(Severity::High));
        assert!(!Severity::Medium.meets(Severity::High));
        assert!(!Severity::Info.meets(Severity::Low));
    }

    #[test]
    fn meets_with_info_threshold_always_true() {
        // Info threshold = "anything, including info". Useful as the
        // default `--min-severity info` CLI behaviour.
        for sev in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert!(sev.meets(Severity::Info), "{sev:?} should meet Info");
        }
    }

    #[test]
    fn from_str_loose_round_trips_through_display() {
        for sev in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            let s = sev.to_string();
            assert_eq!(
                Severity::from_str_loose(&s),
                Some(sev),
                "round-trip via Display->from_str_loose lost {sev:?}"
            );
        }
    }

    #[test]
    fn label_uppercase_short_form() {
        // `label()` is used by terminal renderers and HashMap keys
        // (e.g. severity_counts.get("CRIT")). Locked in.
        assert_eq!(Severity::Info.label(), "INFO");
        assert_eq!(Severity::Low.label(), "LOW");
        assert_eq!(Severity::Medium.label(), "MED");
        assert_eq!(Severity::High.label(), "HIGH");
        assert_eq!(Severity::Critical.label(), "CRIT");
    }

    #[test]
    fn sarif_level_collapses_to_three_buckets() {
        assert_eq!(Severity::Critical.sarif_level(), "error");
        assert_eq!(Severity::High.sarif_level(), "error");
        assert_eq!(Severity::Medium.sarif_level(), "warning");
        assert_eq!(Severity::Low.sarif_level(), "note");
        assert_eq!(Severity::Info.sarif_level(), "note");
    }

    #[test]
    fn try_from_u8_covers_0_through_4_and_rejects_others() {
        assert_eq!(Severity::try_from(0u8), Ok(Severity::Info));
        assert_eq!(Severity::try_from(1u8), Ok(Severity::Low));
        assert_eq!(Severity::try_from(2u8), Ok(Severity::Medium));
        assert_eq!(Severity::try_from(3u8), Ok(Severity::High));
        assert_eq!(Severity::try_from(4u8), Ok(Severity::Critical));
        assert!(Severity::try_from(5u8).is_err());
        assert!(Severity::try_from(255u8).is_err());
    }

    #[test]
    fn from_str_loose_handles_aliases_and_case() {
        // Locks in the loose-parsing surface the CLI relies on
        // (`--min-severity` accepting "crit", "Critical", "INFO", etc).
        assert_eq!(Severity::from_str_loose("info"), Some(Severity::Info));
        assert_eq!(Severity::from_str_loose("INFO"), Some(Severity::Info));
        assert_eq!(
            Severity::from_str_loose("informational"),
            Some(Severity::Info)
        );
        assert_eq!(Severity::from_str_loose("med"), Some(Severity::Medium));
        assert_eq!(Severity::from_str_loose("Medium"), Some(Severity::Medium));
        assert_eq!(Severity::from_str_loose("crit"), Some(Severity::Critical));
        assert_eq!(
            Severity::from_str_loose("Critical"),
            Some(Severity::Critical)
        );
        assert_eq!(Severity::from_str_loose("nonsense"), None);
        assert_eq!(Severity::from_str_loose(""), None);
    }

    #[test]
    fn serde_round_trip_lowercase_wire_format() {
        for sev in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let back: Severity = serde_json::from_str(&json).unwrap();
            assert_eq!(back, sev);
            // Wire format is lowercase  -  every consolidated consumer
            // depends on this.
            let s = sev.to_string();
            assert_eq!(json, format!("\"{s}\""));
        }
    }
}
