#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]
#![forbid(unsafe_code)]
//! Universal security finding types for the Santh ecosystem.
//!
//! Every Santh tool  -  web scanners, code analyzers, secret detectors,
//! template engines  -  produces findings. This crate provides the shared
//! types so all tools speak the same language.
//!
//! # Core Types
//!
//! - [`Severity`]  -  Info, Low, Medium, High, Critical
//! - [`FindingKind`]  -  What was found (vulnerability, misconfiguration, exposure, etc.)
//! - [`Evidence`]  -  Typed proof attached to a finding
//! - [`Finding`]  -  The universal finding struct
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
//!     .build()
//!     .unwrap();
//! ```

mod evidence;
mod filter;
mod finding;
mod kind;
mod location;
mod projection;
mod reportable;
mod severity;
mod status;

// Bridge from `secir::Finding` to `secfinding::Finding`. Gated with
// `cfg(any())` (always-false) because secir isn't yet on crates.io
// and declaring `secir = []` as a feature would emit a phantom
// optional dep into Cargo.toml. The bridge module remains in the
// tree for the in-tree tests; re-enable once secir publishes by
// flipping this to `#[cfg(feature = "secir")]` and adding
// `secir = { dep, optional = true }` + `secir = ["dep:secir"]`.
#[cfg(any())]
pub mod bridge;

pub use evidence::{AccessOutcome, Confidence, DetectorOutcome, Evidence, RoleResponseSample};
pub use filter::{filter, FindingFilter, TagMode};
pub use finding::{Finding, FindingBuildError, FindingBuilder, FindingConfig};
pub use kind::FindingKind;
pub use location::{Location, LocationError};
pub use projection::{projection_for_evidence, ProjectionKey};
pub use reportable::Reportable;
pub use severity::Severity;
pub use status::FindingStatus;

/// Convenience re-exports for common usage.
///
/// ```rust
/// use secfinding::prelude::*;
/// ```
pub mod prelude {
    pub use crate::{
        AccessOutcome, Confidence, DetectorOutcome, Evidence, Finding, FindingBuilder, FindingKind,
        FindingStatus, Location, ProjectionKey, Reportable, RoleResponseSample, Severity,
    };
}
