//! Projection-key extraction for secbench matching.
//!
//! `secfinding` cannot depend on `secbench-core` (circular: secbench depends
//! on secfinding for the universal Finding type). To let secbench's projection
//! matcher (`ARCHITECTURE.md` §4 concept 10) compare findings against oracle
//! cells, secfinding exposes a structural projection key per Evidence variant.
//! secbench-side code reads `Finding::projection_keys()`, dispatches on
//! `ProjectionKey::system`, and converts to its native `Coord` type.
//!
//! The well-known `system` tag set is mirrored in
//! `software/secbench/taxonomy.toml` under `[coord_system].allowed`. Adding a
//! new variant here that needs a new system tag REQUIRES adding the tag in
//! taxonomy.toml in the same PR, otherwise secbench's matcher falls back to
//! opaque bag-of-bytes comparison and loses agreement guarantees.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::evidence::{AccessOutcome, Evidence};
use crate::finding::Finding;

/// One projection-key sample. secbench's matcher dispatches on `system` to
/// promote this to its native `Coord` type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProjectionKey {
    /// Coordinate system identifier (matches secbench's `coord_system` taxonomy).
    /// Well-known tags: `Source`, `Http`, `Dataflow`, `RoleMatrix`,
    /// `WorkflowStep`, `AppMapEntity`, `StealthProbe`, `CaptchaChallenge`,
    /// `AuthSession`, `RuntimeTrace`, `DetonationArtifact`, `Opaque`.
    pub system: Arc<str>,
    /// Key within the coordinate system. Format is per-system:
    ///   - `Source`         → `"file:line"` or `"file:start-end"`
    ///   - `Http`           → `"METHOD URL"` or `"METHOD URL?param=key"`
    ///   - `Dataflow`       → `"source_id->sink_id"`
    ///   - `RoleMatrix`     → `"resource_kind:resource_id:owner_role:prober_role"`
    ///   - `WorkflowStep`   → `"workflow_id:step_id"`
    ///   - `AppMapEntity`   → entity id (opaque to secfinding)
    ///   - `StealthProbe`   → `"profile_name:detector_id"`
    ///   - `CaptchaChallenge` → `"vendor:challenge_type"`
    ///   - `AuthSession`    → session opaque id
    ///   - `RuntimeTrace`   → trace opaque id
    ///   - `DetonationArtifact` → artifact opaque id (URL / hash / digest)
    pub key: Arc<str>,
}

impl ProjectionKey {
    /// Construct a projection key from a system tag + key string.
    pub fn new(system: impl Into<Arc<str>>, key: impl Into<Arc<str>>) -> Self {
        Self {
            system: system.into(),
            key: key.into(),
        }
    }
}

impl std::fmt::Display for ProjectionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.system, self.key)
    }
}

impl Finding {
    /// Extract zero-or-more projection keys for this finding. secbench's
    /// matcher iterates the returned keys, dispatches on `system`, and
    /// scores each against active oracle cells.
    ///
    /// Per-Evidence dispatch: each evidence item independently yields
    /// keys. A finding with multiple evidence items can produce multiple
    /// keys; matchers handle the deduplication.
    #[must_use]
    pub fn projection_keys(&self) -> Vec<ProjectionKey> {
        let mut keys = Vec::new();
        for ev in self.evidence() {
            keys.extend(projection_for_evidence(ev));
        }
        keys
    }
}

/// Per-Evidence projection-key extraction. Visible for testing.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn projection_for_evidence(ev: &Evidence) -> Vec<ProjectionKey> {
    match ev {
        // ── existing variants ─────────────────────────────────────────────
        Evidence::HttpResponse { status, .. } => {
            // Status alone isn't a stable key; downstream callers should
            // pair with HttpRequest evidence on the same finding for the
            // (method, url) tuple. We surface status as Opaque so it
            // can still participate in coarse matching.
            vec![ProjectionKey::new(
                "Opaque",
                format!("http_response_status:{status}"),
            )]
        }
        Evidence::HttpRequest { method, url, .. } => {
            vec![ProjectionKey::new("Http", format!("{method} {url}"))]
        }
        Evidence::DnsRecord { record_type, value } => {
            vec![ProjectionKey::new(
                "Opaque",
                format!("dns:{record_type}:{value}"),
            )]
        }
        Evidence::Banner { .. } | Evidence::Raw { .. } => Vec::new(),
        Evidence::JsSnippet { url, line, .. } => {
            vec![ProjectionKey::new("Source", format!("{url}:{line}"))]
        }
        Evidence::Certificate { subject, .. } => {
            vec![ProjectionKey::new("Opaque", format!("cert:{subject}"))]
        }
        Evidence::CodeSnippet { file, line, .. } => {
            vec![ProjectionKey::new("Source", format!("{file}:{line}"))]
        }
        Evidence::PatternMatch { pattern, .. } => {
            vec![ProjectionKey::new("Opaque", format!("pattern:{pattern}"))]
        }

        // ── v0.4.0 additions ─────────────────────────────────────────────
        Evidence::AppMapReplay { endpoint, .. } => {
            vec![ProjectionKey::new("Http", endpoint.as_ref())]
        }
        Evidence::BolaProbe {
            owner_role,
            prober_role,
            resource_kind,
            resource_id_token,
            access_outcome,
            ..
        } => {
            // RoleMatrix key encodes the four dimensions of a BOLA cell:
            // resource kind + id + owner + prober. Access outcome lives in
            // the key so successful-with-data vs denied don't collapse.
            vec![ProjectionKey::new(
                "RoleMatrix",
                format!(
                    "{resource_kind}:{resource_id_token}:{owner_role}:{prober_role}:{}",
                    access_outcome_tag(*access_outcome)
                ),
            )]
        }
        Evidence::LoginFlowTrace {
            canary_response_status,
            ..
        } => {
            // Login-flow projects to AuthSession (the session-establishment
            // event) keyed on canary outcome.
            vec![ProjectionKey::new(
                "AuthSession",
                format!("canary:{canary_response_status}"),
            )]
        }
        Evidence::StealthProbe {
            profile_name,
            per_detector,
            ..
        } => {
            // One key per detector outcome (failures + passes both project;
            // matcher decides which oracle cells care).
            per_detector
                .iter()
                .map(|d| {
                    ProjectionKey::new(
                        "StealthProbe",
                        format!(
                            "{profile_name}:{}:{}",
                            d.detector_id,
                            if d.passed { "passed" } else { "failed" }
                        ),
                    )
                })
                .collect()
        }
        Evidence::CaptchaBypass {
            vendor,
            challenge_type,
            bypass_succeeded,
            ..
        } => {
            vec![ProjectionKey::new(
                "CaptchaChallenge",
                format!(
                    "{vendor}:{challenge_type}:{}",
                    if *bypass_succeeded {
                        "bypassed"
                    } else {
                        "blocked"
                    }
                ),
            )]
        }
        Evidence::WorkflowCrossStepWitness {
            workflow_id,
            observation_step,
            observation_role,
            ..
        } => {
            vec![ProjectionKey::new(
                "WorkflowStep",
                format!("{workflow_id}:{observation_step}:{observation_role}"),
            )]
        }
        Evidence::DomExecution { sink, source, .. } => {
            vec![ProjectionKey::new("Dataflow", format!("{source}->{sink}"))]
        }
        Evidence::SourceLeak {
            file,
            line_start,
            line_end,
            secret_kind,
            ..
        } => {
            let range = if line_start == line_end {
                line_start.to_string()
            } else {
                format!("{line_start}-{line_end}")
            };
            // Two projections: Source (file:line) for source-line oracles
            // + Opaque (secret-kind tag) for kind-only oracles.
            vec![
                ProjectionKey::new("Source", format!("{file}:{range}")),
                ProjectionKey::new("Opaque", format!("secret_kind:{secret_kind}")),
            ]
        }
        Evidence::RuntimeBehaviorTrace { anomaly_kind, .. } => {
            vec![ProjectionKey::new("RuntimeTrace", anomaly_kind.as_ref())]
        }
        Evidence::DetonationVerdict {
            verdict, family, ..
        } => {
            let mut keys = vec![ProjectionKey::new(
                "DetonationArtifact",
                format!("verdict:{verdict}"),
            )];
            if let Some(fam) = family {
                keys.push(ProjectionKey::new(
                    "DetonationArtifact",
                    format!("family:{fam}"),
                ));
            }
            keys
        }
        Evidence::InvariantViolation { invariant, .. } => {
            vec![ProjectionKey::new("AppMapEntity", invariant.as_ref())]
        }
    }
}

fn access_outcome_tag(o: AccessOutcome) -> &'static str {
    match o {
        AccessOutcome::SuccessWithData => "leak",
        AccessOutcome::SuccessEmpty => "ok_empty",
        AccessOutcome::Denied => "denied",
        AccessOutcome::NotFound => "not_found",
        AccessOutcome::Other => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{Confidence, DetectorOutcome, RoleResponseSample};

    #[test]
    fn http_request_projects_method_url() {
        let ev = Evidence::HttpRequest {
            method: "GET".into(),
            url: "https://example.com/api".into(),
            headers: vec![],
            body: None,
        };
        let keys = projection_for_evidence(&ev);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].system.as_ref(), "Http");
        assert_eq!(keys[0].key.as_ref(), "GET https://example.com/api");
    }

    #[test]
    fn bola_probe_projects_role_matrix() {
        let ev = Evidence::BolaProbe {
            owner_role: "user_a".into(),
            prober_role: "user_b".into(),
            resource_kind: "Note".into(),
            resource_id_token: "id_42".into(),
            access_outcome: AccessOutcome::SuccessWithData,
            leaked_privacy_fields: vec!["email".into()],
        };
        let keys = projection_for_evidence(&ev);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].system.as_ref(), "RoleMatrix");
        assert_eq!(keys[0].key.as_ref(), "Note:id_42:user_a:user_b:leak");
    }

    #[test]
    fn stealth_probe_emits_one_key_per_detector() {
        let ev = Evidence::StealthProbe {
            profile_name: "chrome131".into(),
            per_detector: vec![
                DetectorOutcome {
                    detector_id: "navigator-webdriver".into(),
                    passed: true,
                    detail: None,
                },
                DetectorOutcome {
                    detector_id: "canvas".into(),
                    passed: false,
                    detail: None,
                },
            ],
            overall_undetected: false,
        };
        let keys = projection_for_evidence(&ev);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].key.as_ref(), "chrome131:navigator-webdriver:passed");
        assert_eq!(keys[1].key.as_ref(), "chrome131:canvas:failed");
    }

    #[test]
    fn source_leak_emits_source_and_opaque_keys() {
        let ev = Evidence::SourceLeak {
            file: ".env".into(),
            line_start: 12,
            line_end: 12,
            secret_kind: "AWS_ACCESS_KEY".into(),
            confidence: Confidence::new(0.9).unwrap(),
            rotation_url_hint: None,
        };
        let keys = projection_for_evidence(&ev);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].system.as_ref(), "Source");
        assert_eq!(keys[0].key.as_ref(), ".env:12");
        assert_eq!(keys[1].system.as_ref(), "Opaque");
        assert_eq!(keys[1].key.as_ref(), "secret_kind:AWS_ACCESS_KEY");
    }

    #[test]
    fn detonation_verdict_with_family_emits_two_keys() {
        let ev = Evidence::DetonationVerdict {
            verdict: "malicious".into(),
            family: Some("Emotet".into()),
            confidence: Confidence::new(0.88).unwrap(),
            proof_excerpt: "shellcode signature".into(),
        };
        let keys = projection_for_evidence(&ev);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].system.as_ref(), "DetonationArtifact");
        assert_eq!(keys[0].key.as_ref(), "verdict:malicious");
        assert_eq!(keys[1].key.as_ref(), "family:Emotet");
    }

    #[test]
    fn detonation_verdict_no_family_emits_one_key() {
        let ev = Evidence::DetonationVerdict {
            verdict: "likely_safe".into(),
            family: None,
            confidence: Confidence::new(0.7).unwrap(),
            proof_excerpt: "static-only".into(),
        };
        let keys = projection_for_evidence(&ev);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key.as_ref(), "verdict:likely_safe");
    }

    #[test]
    fn appmap_replay_projects_endpoint_as_http() {
        let ev = Evidence::AppMapReplay {
            endpoint: "/api/notes/:id".into(),
            per_role: vec![RoleResponseSample {
                role_id: "r".into(),
                status: 200,
                response_hash: "h".into(),
                diff_excerpt: None,
            }],
            diff_summary: "".into(),
        };
        let keys = projection_for_evidence(&ev);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].system.as_ref(), "Http");
        assert_eq!(keys[0].key.as_ref(), "/api/notes/:id");
    }

    #[test]
    fn raw_and_banner_yield_no_keys() {
        assert!(projection_for_evidence(&Evidence::raw("x")).is_empty());
        assert!(projection_for_evidence(&Evidence::Banner { raw: "x".into() }).is_empty());
    }
}
