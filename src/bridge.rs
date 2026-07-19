//! Bridge from `secir::Finding` (template-engine IR) to `secfinding::Finding` (universal).
//!
//! The template scanning engines (Calyx, Karyx) produce `secir::Finding` internally.
//! This module converts them into the universal `secfinding::Finding` type so they
//! can flow through secreport, secfinding filters, and all ecosystem consumers.
//!
//! # Usage
//!
//! ```rust,no_run
//! use secfinding::bridge::to_universal;
//! // let ir_finding: secir::Finding = scanner.scan(...);
//! // let universal: secfinding::Finding = to_universal(&ir_finding, "calyx");
//! ```

use crate::evidence::Evidence;
use crate::finding::Finding;
use crate::kind::FindingKind;
use crate::severity::Severity as UniversalSeverity;
use crate::status::FindingStatus;
use std::sync::Arc;

/// Convert a `secir::Finding` into a universal `secfinding::Finding`.
///
/// Maps all fields from the template-engine internal representation to the
/// universal format. HTTP request/response dumps are stored as `Evidence::Raw`,
/// matched values as `Evidence::PatternMatch`, and the curl command is preserved
/// as `exploit_hint`.
///
/// # Arguments
///
/// * `ir`  -  The template-engine Finding from secir.
/// * `scanner_name`  -  The scanner that produced this finding (e.g. "calyx", "karyx").
///
/// # Errors
///
/// Returns `FindingBuildError` if the constructed finding fails validation
/// (e.g., empty scanner name or overly long fields).
pub fn to_universal(
    ir: &secir::finding::Finding,
    scanner_name: &str,
) -> Result<Finding, crate::FindingBuildError> {
    let severity = map_severity(ir.severity);
    let kind = map_kind(&ir.kind);

    let title = if ir.template_name.is_empty() {
        ir.template_id.clone()
    } else {
        ir.template_name.clone()
    };

    let mut builder = Finding::builder(scanner_name, &ir.target, severity)
        .title(title)
        .detail(ir.description.clone().unwrap_or_default())
        .kind(kind)
        .status(FindingStatus::Open)
        .timestamp(ir.timestamp);

    // Capture raw HTTP request/response as unstructured evidence
    if let Some(req) = &ir.request {
        builder = builder.evidence(Evidence::raw(format!("[request]\n{req}")));
    }
    if let Some(resp) = &ir.response {
        builder = builder.evidence(Evidence::raw(format!("[response]\n{resp}")));
    }

    // Matched values become pattern-match evidence
    for matched in &ir.matched_values {
        builder = builder.evidence(Evidence::PatternMatch {
            pattern: Arc::from(
                ir.matcher_name
                    .clone()
                    .unwrap_or_else(|| "template-match".to_string()),
            ),
            matched: Arc::from(matched.clone()),
        });
    }

    for tag in &ir.tags {
        builder = builder.tag(tag.clone());
    }

    for cve in &ir.cve_ids {
        builder = builder.cve(cve.clone());
    }

    for reference in &ir.references {
        builder = builder.reference(reference.clone());
    }

    if let Some(conf) = ir.confidence {
        builder = builder.confidence(conf);
    }

    if let Some(curl) = &ir.curl_command {
        builder = builder.exploit_hint(curl.clone());
    }

    for matched in &ir.matched_values {
        builder = builder.matched_value(matched.clone());
    }

    builder.build()
}

/// Map secir severity to secfinding severity.
pub fn map_severity(ir: secir::Severity) -> UniversalSeverity {
    match ir {
        secir::Severity::Info => UniversalSeverity::Info,
        secir::Severity::Low => UniversalSeverity::Low,
        secir::Severity::Medium => UniversalSeverity::Medium,
        secir::Severity::High => UniversalSeverity::High,
        secir::Severity::Critical => UniversalSeverity::Critical,
        // secir::Severity is #[non_exhaustive]  -  future variants map to Info
        _ => UniversalSeverity::Info,
    }
}

/// Map secir finding kind to secfinding finding kind.
pub fn map_kind(ir: &secir::finding::FindingKind) -> FindingKind {
    match ir {
        secir::finding::FindingKind::Vulnerability => FindingKind::Vulnerability,
        secir::finding::FindingKind::Misconfiguration => FindingKind::Misconfiguration,
        secir::finding::FindingKind::Exposure => FindingKind::Exposure,
        secir::finding::FindingKind::TechDetect => FindingKind::TechDetect,
        secir::finding::FindingKind::DefaultCredentials => FindingKind::DefaultCredentials,
        secir::finding::FindingKind::InfoDisclosure => FindingKind::InfoDisclosure,
        secir::finding::FindingKind::FileDiscovery => FindingKind::FileDiscovery,
        secir::finding::FindingKind::Other => FindingKind::Other,
        // secir::FindingKind is #[non_exhaustive]  -  future variants map to Other
        _ => FindingKind::Other,
    }
}
