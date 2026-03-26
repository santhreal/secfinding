//! Classification of what a finding represents.

use serde::{Deserialize, Serialize};

/// What kind of security issue was found.
///
/// Extensible via `#[non_exhaustive]` — new variants can be added
/// without breaking downstream consumers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum FindingKind {
    /// A confirmed exploitable vulnerability (`SQLi`, `XSS`, `RCE`, etc.).
    Vulnerability,
    /// A security misconfiguration (missing headers, weak TLS, etc.).
    Misconfiguration,
    /// An exposed service, panel, or endpoint that should not be public.
    Exposure,
    /// Technology detection — informational, no direct security impact.
    TechDetect,
    /// Default or weak credentials found.
    DefaultCredentials,
    /// Information disclosure (stack traces, internal IPs, version numbers).
    InfoDisclosure,
    /// A file, directory, or backup found that should not be accessible.
    FileDiscovery,
    /// A hardcoded secret (API key, password, token) in source or artifacts.
    SecretLeak,
    /// A malicious or suspicious code pattern (malware, backdoor).
    MaliciousCode,
    /// A supply chain risk (dependency confusion, typosquatting).
    SupplyChain,
    /// Unclassified finding.
    Other,
}

impl FindingKind {
    /// Whether this finding kind typically requires immediate attention.
    #[must_use]
    pub fn is_actionable(&self) -> bool {
        matches!(
            self,
            Self::Vulnerability | Self::DefaultCredentials | Self::SecretLeak | Self::MaliciousCode
        )
    }
}

impl std::fmt::Display for FindingKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Vulnerability => "vulnerability",
            Self::Misconfiguration => "misconfiguration",
            Self::Exposure => "exposure",
            Self::TechDetect => "tech-detect",
            Self::DefaultCredentials => "default-credentials",
            Self::InfoDisclosure => "info-disclosure",
            Self::FileDiscovery => "file-discovery",
            Self::SecretLeak => "secret-leak",
            Self::MaliciousCode => "malicious-code",
            Self::SupplyChain => "supply-chain",
            Self::Other => "other",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_and_display_kebab_case() {
        let json = serde_json::to_string(&FindingKind::TechDetect).unwrap();
        assert_eq!(json, "\"tech-detect\"");

        let back: FindingKind = serde_json::from_str("\"default-credentials\"").unwrap();
        assert_eq!(back, FindingKind::DefaultCredentials);

        let rendered = FindingKind::SecretLeak.to_string();
        assert_eq!(rendered, "secret-leak");
    }

    #[test]
    fn actionable() {
        assert!(FindingKind::Vulnerability.is_actionable());
        assert!(FindingKind::SecretLeak.is_actionable());
        assert!(!FindingKind::TechDetect.is_actionable());
        assert!(!FindingKind::InfoDisclosure.is_actionable());
    }
}
