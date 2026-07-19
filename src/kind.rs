//! Classification of what a finding represents.

use serde::{Deserialize, Serialize};

/// What kind of security issue was found.
///
/// Extensible via `#[non_exhaustive]`  -  new variants can be added
/// without breaking downstream consumers.
///
/// # Examples
///
/// ```
/// use secfinding::FindingKind;
///
/// assert!(FindingKind::SecretLeak.is_actionable());
/// assert_eq!(FindingKind::TechDetect.to_string(), "tech-detect");
/// ```
///
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum FindingKind {
    /// A confirmed exploitable vulnerability (`SQLi`, `XSS`, `RCE`, etc.).
    Vulnerability,
    /// A security misconfiguration (missing headers, weak TLS, etc.).
    Misconfiguration,
    /// An exposed service, panel, or endpoint that should not be public.
    Exposure,
    /// Technology detection  -  informational, no direct security impact.
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
    /// Unclassified  -  kind has not been explicitly set.
    /// Distinct from `Other` which is an intentional classification.
    Unclassified,
    /// Intentionally classified as "other" (doesn't fit existing categories).
    Other,

    // ── v0.4.0 unified-machine classes ───────────────────────────────────
    /// Access-control failure: IDOR, BOLA, privilege escalation, missing
    /// function-level authorization.
    AccessControl,

    /// Authentication-flow weakness, broken auth, session fixation,
    /// MFA bypass, OAuth redirect-uri laxity.
    AuthFlow,

    /// Business-logic / workflow abuse, multi-step bypass, race on
    /// state machine, ordering-dependent leak.
    BusinessLogic,

    /// Bot-detection / stealth-probe finding (target detected our scanner).
    BotDetection,

    /// Captcha bypass succeeded (or attempted).
    CaptchaBypass,

    /// Detonation verdict (sear / apkdet / jsdet / etc artifact verdict).
    DetonationVerdict,

    /// Behavioral anomaly observed at runtime (soleno's class).
    BehavioralAnomaly,

    /// Declared or inferred invariant violated (appmap-driven).
    InvariantViolation,
}

impl FindingKind {
    /// Whether this finding kind typically requires immediate attention.
    #[must_use]
    pub fn is_actionable(&self) -> bool {
        matches!(
            self,
            Self::Vulnerability
                | Self::DefaultCredentials
                | Self::SecretLeak
                | Self::MaliciousCode
                | Self::AccessControl
                | Self::AuthFlow
                | Self::BusinessLogic
                | Self::InvariantViolation
        )
    }

    /// Whether a kind has been explicitly set (not `Unclassified`).
    #[must_use]
    pub fn is_classified(&self) -> bool {
        !matches!(self, Self::Unclassified)
    }

    /// Whether findings of this kind should always escalate severity to
    /// at least `High` in triage pipelines.
    #[must_use]
    pub fn requires_severity_bump(&self) -> bool {
        matches!(
            self,
            Self::DefaultCredentials | Self::SecretLeak | Self::MaliciousCode | Self::AccessControl
        )
    }

    /// The minimum severity a finding of this kind should have.
    ///
    /// Useful for dashboards that want to enforce severity floors
    /// based on finding classification.
    #[must_use]
    pub fn severity_floor(&self) -> crate::Severity {
        match self {
            Self::MaliciousCode | Self::DefaultCredentials | Self::AccessControl => {
                crate::Severity::High
            }
            Self::Vulnerability
            | Self::SecretLeak
            | Self::SupplyChain
            | Self::AuthFlow
            | Self::BusinessLogic
            | Self::InvariantViolation
            | Self::DetonationVerdict => crate::Severity::Medium,
            Self::Misconfiguration | Self::Exposure | Self::BehavioralAnomaly => {
                crate::Severity::Low
            }
            Self::InfoDisclosure
            | Self::FileDiscovery
            | Self::TechDetect
            | Self::BotDetection
            | Self::CaptchaBypass
            | Self::Other
            | Self::Unclassified => crate::Severity::Info,
        }
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
            Self::Unclassified => "unclassified",
            Self::Other => "other",
            Self::AccessControl => "access-control",
            Self::AuthFlow => "auth-flow",
            Self::BusinessLogic => "business-logic",
            Self::BotDetection => "bot-detection",
            Self::CaptchaBypass => "captcha-bypass",
            Self::DetonationVerdict => "detonation-verdict",
            Self::BehavioralAnomaly => "behavioral-anomaly",
            Self::InvariantViolation => "invariant-violation",
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for FindingKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalised = s.to_lowercase().replace('_', "-");
        match normalised.as_str() {
            "vulnerability" => Ok(Self::Vulnerability),
            "misconfiguration" => Ok(Self::Misconfiguration),
            "exposure" => Ok(Self::Exposure),
            "tech-detect" => Ok(Self::TechDetect),
            "default-credentials" => Ok(Self::DefaultCredentials),
            "info-disclosure" => Ok(Self::InfoDisclosure),
            "file-discovery" => Ok(Self::FileDiscovery),
            "secret-leak" => Ok(Self::SecretLeak),
            "malicious-code" => Ok(Self::MaliciousCode),
            "supply-chain" => Ok(Self::SupplyChain),
            "unclassified" => Ok(Self::Unclassified),
            "other" => Ok(Self::Other),
            "access-control" => Ok(Self::AccessControl),
            "auth-flow" => Ok(Self::AuthFlow),
            "business-logic" => Ok(Self::BusinessLogic),
            "bot-detection" => Ok(Self::BotDetection),
            "captcha-bypass" => Ok(Self::CaptchaBypass),
            "detonation-verdict" => Ok(Self::DetonationVerdict),
            "behavioral-anomaly" => Ok(Self::BehavioralAnomaly),
            "invariant-violation" => Ok(Self::InvariantViolation),
            // Unknown strings are caller bugs, not silent fallbacks  -
            // surfacing them lets `Other` remain an *intentional*
            // classification rather than a catch-all dumping ground.
            // Required by `verify_kind_from_str_rejects_unknown`.
            _ => Err(format!("unknown FindingKind `{s}`")),
        }
    }
}
