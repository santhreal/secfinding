//! Universal security finding types for the Santh ecosystem.
//!
//! Every Santh tool — web scanners, code analyzers, secret detectors,
//! template engines — produces findings. This crate provides the shared
//! types so all tools speak the same language.
//!
//! # Core Types
//!
//! - [`Severity`] — Info, Low, Medium, High, Critical
//! - [`FindingKind`] — What was found (vulnerability, misconfiguration, exposure, etc.)
//! - [`Evidence`] — Typed proof attached to a finding
//! - [`Finding`] — The universal finding struct
//!
//! # Usage
//!
//! ```rust
//! use secfinding::{Finding, Severity, Evidence, FindingKind};
//!
//! let finding = Finding::builder("my-scanner", "https://example.com", Severity::High)
//!     .title("SQL Injection")
//!     .detail("User input in login form is not sanitized")
//!     .kind(FindingKind::Vulnerability)
//!     .evidence(Evidence::HttpResponse {
//!         status: 500,
//!         headers: vec![],
//!         body_excerpt: Some("SQL syntax error".into()),
//!     })
//!     .tag("sqli")
//!     .tag("owasp-a03")
//!     .cve("CVE-2024-12345")
//!     .exploit_hint("sqlmap -u 'https://example.com/login' --data 'user=admin'")
//!     .build();
//! ```

#![warn(missing_docs)]
#![forbid(unsafe_code)]

mod evidence;
mod filter;
mod finding;
mod kind;
mod reportable;
mod severity;

#[cfg(test)]
mod adversarial_tests;

pub use evidence::Evidence;
pub use filter::{filter, FindingFilter};
pub use finding::{Finding, FindingBuilder};
pub use kind::FindingKind;
pub use reportable::Reportable;
pub use severity::Severity;

/// Convenience re-exports for common usage.
///
/// ```rust
/// use secfinding::prelude::*;
/// ```
pub mod prelude {
    pub use crate::{Evidence, Finding, FindingBuilder, FindingKind, Reportable, Severity};
}
