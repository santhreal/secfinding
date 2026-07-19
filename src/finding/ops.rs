//! Higher-level operations on [`Finding`](super::types::Finding) collections.

use std::sync::Arc;

use super::error::FindingBuildError;
use super::types::Finding;

impl Finding {
    /// Group findings by target for batch triage.
    ///
    /// Returns a map from target string to the findings on that target,
    /// sorted by severity (descending).
    #[must_use]
    pub fn group_by_target<'a>(
        findings: &'a [Finding],
    ) -> std::collections::HashMap<&'a str, Vec<&'a Finding>> {
        let mut map: std::collections::HashMap<&'a str, Vec<&'a Finding>> =
            std::collections::HashMap::new();
        for f in findings {
            map.entry(f.target()).or_default().push(f);
        }
        for group in map.values_mut() {
            group.sort_by_key(|f| std::cmp::Reverse(f.severity()));
        }
        map
    }

    /// Merge two related findings into a single chain finding.
    ///
    /// The resulting finding takes the higher severity, combines
    /// evidence, tags, CVEs, CWEs, references, and matched values from
    /// both inputs. CVSS score and confidence are taken as the maximum
    /// of the two  -  preserving the most-severe quantitative signal.
    /// The title is combined with ` → ` to indicate the chain
    /// relationship.
    ///
    /// # Errors
    ///
    /// Returns `FindingBuildError` if the combined fields fail validation
    /// (e.g., empty title or overly long strings).
    pub fn merge_chain(a: &Finding, b: &Finding) -> Result<Finding, FindingBuildError> {
        let severity = std::cmp::max(a.severity, b.severity);
        let kind = if b.kind.is_actionable() {
            b.kind
        } else {
            a.kind
        };
        let mut evidence = a.evidence.clone();
        evidence.extend(b.evidence.iter().cloned());
        let mut tags: Vec<Arc<str>> = a.tags.iter().chain(b.tags.iter()).cloned().collect();
        tags.sort();
        tags.dedup();
        let mut cve_ids: Vec<Arc<str>> =
            a.cve_ids.iter().chain(b.cve_ids.iter()).cloned().collect();
        cve_ids.sort();
        cve_ids.dedup();
        let mut merged_cwes: Vec<Arc<str>> =
            a.cwe_ids.iter().chain(b.cwe_ids.iter()).cloned().collect();
        merged_cwes.sort();
        merged_cwes.dedup();
        let mut references: Vec<Arc<str>> = a
            .references
            .iter()
            .chain(b.references.iter())
            .cloned()
            .collect();
        references.sort();
        references.dedup();
        let mut matched_values: Vec<Arc<str>> = a
            .matched_values
            .iter()
            .chain(b.matched_values.iter())
            .cloned()
            .collect();
        matched_values.sort();
        matched_values.dedup();

        // Take the max of any quantitative signal  -  losing CVSS or
        // confidence on merge was an audit finding
        // (`verify_merge_chain_preserves_cvss_and_confidence`); the
        // chain is at least as severe as either input so the higher
        // score is the honest summary.
        let cvss_score = match (a.cvss_score, b.cvss_score) {
            (Some(x), Some(y)) => Some(x.max(y)),
            (Some(x), None) | (None, Some(x)) => Some(x),
            (None, None) => None,
        };
        let confidence = match (a.confidence, b.confidence) {
            (Some(x), Some(y)) => Some(x.max(y)),
            (Some(x), None) | (None, Some(x)) => Some(x),
            (None, None) => None,
        };

        let mut builder = Finding::builder(a.scanner(), a.target(), severity)
            .title(format!("{} → {}", a.title(), b.title()))
            .detail(format!("{}\n---\n{}", a.detail(), b.detail()))
            .kind(kind);

        for ev in &evidence {
            builder = builder.evidence(ev.clone());
        }
        // Pass the Arc<str> values by clone (a refcount bump, not a String
        // realloc): the builder now stores Arc<str> directly, so the whole
        // path is Arc -> Arc with no intermediate owned String on either side.
        for tag in &tags {
            builder = builder.tag(Arc::clone(tag));
        }
        for cve in &cve_ids {
            builder = builder.cve(Arc::clone(cve));
        }
        for cwe in &merged_cwes {
            builder = builder.cwe(Arc::clone(cwe));
        }
        for r in &references {
            builder = builder.reference(Arc::clone(r));
        }
        for mv in &matched_values {
            builder = builder.matched_value(Arc::clone(mv));
        }
        if let Some(s) = cvss_score {
            builder = builder.cvss_score(s);
        }
        if let Some(c) = confidence {
            builder = builder.confidence(c);
        }

        builder.build()
    }
}
