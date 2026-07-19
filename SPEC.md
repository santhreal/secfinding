# secfinding  -  Technical Spec

## Overview

Universal security finding types for the Santh ecosystem.  Every Santh tool  -  web scanners, code analyzers, secret detectors, template engines  -  produces findings. This crate provides the shared types so all tools speak the same language.  # Core Types  - [`Severity`]  -  Info, Low, Medium, High, Critical - [`FindingKind`]  -  What was found (vulnerability, misconfiguration, exposure, etc.) - [`Evidence`]  -  Typed proof attached to a finding - [`Finding`]  -  The universal finding struct  # Usage  ```rust use secfinding::{Finding, Severity, Evidence, FindingKind};  let finding = Finding::builder("my-scanner", "https://example.com", Severity::High) .title("SQL Injection") .detail("User input in login form is not sanitized") .kind(FindingKind::Vulnerability) .evidence(Evidence::HttpResponse { status: 500, headers: vec![], body_excerpt: Some("SQL syntax error".into()), }) .tag("sqli") .tag("owasp-a03") .cve("CVE-2024-12345") .exploit_hint("sqlmap -u 'https://example.com/login' --data 'user=admin'") .build() .unwrap(); ```

## Architecture

The crate is organized into the following public modules:

- `bridge`
- `prelude`

## Guarantees

- `#![forbid(unsafe_code)]` where applicable; see `src/lib.rs` for the exact lint preamble.
- All public types have doc comments.
- Error messages are actionable where applicable.

## Public API Summary

Key entry points are exported from `src/lib.rs` via `pub mod` and `pub use` re-exports.
Consult the module-level documentation in each source file for function signatures and usage examples.

## Error Handling

- Standard `Result` / error types.
