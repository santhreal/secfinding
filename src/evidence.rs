//! Typed evidence attached to findings.
//!
//! Each variant carries structured proof. Consumers use the tag to
//! render evidence correctly (terminal, markdown, SARIF, etc.).

use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// Confidence score in `[0.0, 1.0]`. Newtype around `f32` so the enclosing
/// enums can derive `Hash` + `Eq` cleanly (raw f32 cannot due to NaN /
/// signed-zero semantics).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Confidence(f32);

impl Confidence {
    /// Construct a new confidence value. Returns Err if value is NaN or
    /// outside `[0.0, 1.0]`.
    pub fn new(value: f32) -> Result<Self, &'static str> {
        if value.is_nan() {
            return Err("confidence cannot be NaN");
        }
        if !(0.0..=1.0).contains(&value) {
            return Err("confidence must be in [0.0, 1.0]");
        }
        Ok(Self(value))
    }

    /// Raw f32 value.
    #[must_use]
    pub fn value(self) -> f32 {
        self.0
    }
}

impl Eq for Confidence {}

impl Hash for Confidence {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.2}", self.0)
    }
}

/// Concrete evidence proving a finding is real.
///
/// Extensible via `#[non_exhaustive]`  -  new evidence types can be added
/// for new tools (firmware, mobile, etc.) without breaking existing consumers.
///
/// # Examples
///
/// ```
/// use secfinding::Evidence;
///
/// let evidence = Evidence::http_status(403)?;
/// assert_eq!(evidence.to_string(), "http-response status=403 headers=0 body_excerpt=none");
/// # Ok::<(), &'static str>(())
/// ```
///
/// # Thread Safety
/// `Evidence` is `Send` and `Sync`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Evidence {
    /// HTTP response data (status, headers, body excerpt).
    HttpResponse {
        /// HTTP status code.
        #[serde(deserialize_with = "deserialize_http_status")]
        status: u16,
        /// Response headers as key-value pairs.
        headers: Vec<(Arc<str>, Arc<str>)>,
        /// First N bytes of the response body.
        body_excerpt: Option<Arc<str>>,
    },

    /// DNS record evidence.
    DnsRecord {
        /// Record type (A, AAAA, CNAME, MX, TXT, etc.).
        record_type: Arc<str>,
        /// Record value.
        value: Arc<str>,
    },

    /// Service banner captured during port scanning.
    Banner {
        /// Raw banner text.
        raw: Arc<str>,
    },

    /// JavaScript source snippet with context.
    JsSnippet {
        /// URL of the JS file.
        url: Arc<str>,
        /// Line number in the file.
        #[serde(deserialize_with = "deserialize_positive_usize")]
        line: usize,
        /// The matched code snippet.
        snippet: Arc<str>,
    },

    /// TLS certificate information.
    Certificate {
        /// Certificate subject (CN).
        subject: Arc<str>,
        /// Subject Alternative Names.
        san: Vec<Arc<str>>,
        /// Certificate issuer.
        issuer: Arc<str>,
        /// Expiration date.
        expires: Arc<str>,
    },

    /// Source code snippet (for SAST, malware detection).
    CodeSnippet {
        /// File path.
        file: Arc<str>,
        /// Line number.
        #[serde(deserialize_with = "deserialize_positive_usize")]
        line: usize,
        /// Column number (optional).
        #[serde(default, deserialize_with = "deserialize_optional_positive_usize")]
        column: Option<usize>,
        /// The matched code.
        snippet: Arc<str>,
        /// Programming language.
        language: Option<Arc<str>>,
    },

    /// HTTP request that triggered the finding (for template/vuln scanners).
    HttpRequest {
        /// HTTP method.
        method: Arc<str>,
        /// Full URL.
        url: Arc<str>,
        /// Request headers.
        headers: Vec<(Arc<str>, Arc<str>)>,
        /// Request body.
        body: Option<Arc<str>>,
    },

    /// Matched pattern or regex (for pattern-based scanners).
    PatternMatch {
        /// The pattern or regex that matched.
        pattern: Arc<str>,
        /// The matched content.
        matched: Arc<str>,
    },

    /// Unstructured evidence  -  fallback for anything that doesn't fit
    /// above. A **struct variant** (not a newtype): an internally-tagged
    /// enum (`#[serde(tag = "type")]`) cannot serialize a newtype variant
    /// holding a bare string  -  serde panics with "cannot serialize
    /// tagged newtype variant". Every other variant here is a struct
    /// variant for exactly this reason; `Raw` now matches. Construct it
    /// with [`Evidence::raw`].
    Raw {
        /// The unstructured evidence text.
        value: Arc<str>,
    },

    // ── v0.4.0 unified-machine variants ─────────────────────────────────
    /// Multi-role replay evidence from appmap.
    AppMapReplay {
        /// Endpoint replayed.
        endpoint: Arc<str>,
        /// Per-role samples.
        per_role: Vec<RoleResponseSample>,
        /// Summary of meaningful diff across roles.
        diff_summary: Arc<str>,
    },

    /// IDOR / BOLA probe evidence.
    BolaProbe {
        /// Role that owns the resource.
        owner_role: Arc<str>,
        /// Role that probed.
        prober_role: Arc<str>,
        /// Resource kind (`Note`, `Workspace`, ...).
        resource_kind: Arc<str>,
        /// Sanitized id token.
        resource_id_token: Arc<str>,
        /// Outcome of the probe.
        access_outcome: AccessOutcome,
        /// Privacy-bound field names leaked (values redacted).
        leaked_privacy_fields: Vec<Arc<str>>,
    },

    /// Login-flow trace from loginflow.
    LoginFlowTrace {
        /// Step kinds traversed.
        steps: Vec<Arc<str>>,
        /// Captured cookies (count).
        captured_cookies_count: usize,
        /// Captured auth headers (count).
        captured_headers_count: usize,
        /// Canary endpoint response status proving login.
        #[serde(deserialize_with = "deserialize_http_status")]
        canary_response_status: u16,
    },

    /// Stealth probe report (per-detector pass/fail).
    StealthProbe {
        /// Profile name applied.
        profile_name: Arc<str>,
        /// Per-detector outcomes.
        per_detector: Vec<DetectorOutcome>,
        /// Overall undetected verdict.
        overall_undetected: bool,
    },

    /// Captcha bypass observation.
    CaptchaBypass {
        /// Vendor identifier.
        vendor: Arc<str>,
        /// Challenge subtype.
        challenge_type: Arc<str>,
        /// Elapsed time to solve in ms.
        time_to_solve_ms: u64,
        /// Solver retries before success.
        retries: u32,
        /// Whether bypass succeeded.
        bypass_succeeded: bool,
    },

    /// Cross-step workflow witness.
    WorkflowCrossStepWitness {
        /// Workflow identifier.
        workflow_id: Arc<str>,
        /// Step at which payload injected.
        injection_step: Arc<str>,
        /// Step at which payload observed firing.
        observation_step: Arc<str>,
        /// Role observing.
        observation_role: Arc<str>,
        /// Payload excerpt.
        payload_excerpt: Arc<str>,
    },

    /// DOM execution evidence.
    DomExecution {
        /// Sink that fired.
        sink: Arc<str>,
        /// Source the payload came from.
        source: Arc<str>,
        /// Whether the marker was observed firing.
        executed: bool,
        /// The sentinel string proving execution.
        observed_marker: Arc<str>,
    },

    /// Source-leak evidence (secret found at a file location).
    SourceLeak {
        /// File path.
        file: Arc<str>,
        /// Inclusive start line.
        #[serde(deserialize_with = "deserialize_positive_usize")]
        line_start: usize,
        /// Inclusive end line.
        #[serde(deserialize_with = "deserialize_positive_usize")]
        line_end: usize,
        /// Secret kind identifier.
        secret_kind: Arc<str>,
        /// Detector confidence.
        confidence: Confidence,
        /// Optional URL hint for rotating the leaked credential.
        rotation_url_hint: Option<Arc<str>>,
    },

    /// Runtime behavior trace from soleno or daylight.
    RuntimeBehaviorTrace {
        /// Kind of anomaly.
        anomaly_kind: Arc<str>,
        /// Trace excerpt (redacted).
        trace_excerpt: Arc<str>,
        /// Refs to related events.
        causally_related_events: Vec<Arc<str>>,
    },

    /// Detonation verdict from sear / apkdet / jsdet / etc.
    DetonationVerdict {
        /// Verdict.
        verdict: Arc<str>,
        /// Optional family.
        family: Option<Arc<str>>,
        /// Detector confidence.
        confidence: Confidence,
        /// Proof excerpt.
        proof_excerpt: Arc<str>,
    },

    /// Inferred or declared invariant violated.
    InvariantViolation {
        /// Invariant statement.
        invariant: Arc<str>,
        /// Violation detail.
        violation_detail: Arc<str>,
    },
}

/// One per-role sample inside an `AppMapReplay` evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RoleResponseSample {
    /// Role identifier.
    pub role_id: Arc<str>,
    /// HTTP status observed.
    pub status: u16,
    /// Stable hash of the response body.
    pub response_hash: Arc<str>,
    /// Excerpt of the meaningful-diff.
    pub diff_excerpt: Option<Arc<str>>,
}

/// Outcome classes for a BOLA probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessOutcome {
    /// Request succeeded with owner data (the leak).
    SuccessWithData,
    /// Request succeeded but body empty / sanitized.
    SuccessEmpty,
    /// Correctly denied.
    Denied,
    /// Not found.
    NotFound,
    /// Other.
    Other,
}

/// One per-detector outcome inside a `StealthProbe` evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DetectorOutcome {
    /// Detector identifier.
    pub detector_id: Arc<str>,
    /// Whether stealth defeated this detector.
    pub passed: bool,
    /// Optional detail when failed.
    pub detail: Option<Arc<str>>,
}

impl Evidence {
    /// Unstructured fallback evidence. Accepts `&str`, `String`,
    /// `Arc<str>`  -  anything `Into<Arc<str>>`.
    pub fn raw(value: impl Into<Arc<str>>) -> Self {
        Self::Raw {
            value: value.into(),
        }
    }

    /// Create an HTTP response evidence with just a status code.
    ///
    /// # Errors
    ///
    /// Returns an error if the status code is not within the valid HTTP range (100-599).
    pub fn http_status(status: u16) -> Result<Self, &'static str> {
        if !(100..=599).contains(&status) {
            return Err(
                "HTTP status code must be between 100 and 599. Fix: pass a valid RFC HTTP status code.",
            );
        }
        Ok(Self::HttpResponse {
            status,
            headers: vec![],
            body_excerpt: None,
        })
    }

    /// Create a code snippet evidence.
    ///
    /// `line` and `column` are validated (1-based). Returns an error for invalid coordinates.
    ///
    /// # Errors
    ///
    /// Returns an error if `line` is 0 or if `column` is `Some(0)`.
    pub fn code(
        file: impl Into<String>,
        line: usize,
        snippet: impl Into<String>,
        column: Option<usize>,
        language: Option<String>,
    ) -> Result<Self, &'static str> {
        if line == 0 {
            return Err(
                "line values must be 1 or greater. Fix: pass a positive source line number.",
            );
        }
        if let Some(0) = column {
            return Err(
                "column values must be 1 or greater. Fix: pass a positive source column number.",
            );
        }

        Ok(Self::CodeSnippet {
            file: Arc::from(file.into()),
            line,
            column,
            snippet: Arc::from(snippet.into()),
            language: language.map(Arc::from),
        })
    }
}

fn deserialize_http_status<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let status = u16::deserialize(deserializer)?;
    if !(100..=599).contains(&status) {
        return Err(serde::de::Error::custom(
            "HTTP status code must be between 100 and 599. Fix: pass a valid RFC HTTP status code.",
        ));
    }
    Ok(status)
}

fn deserialize_positive_usize<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = usize::deserialize(deserializer)?;
    if value == 0 {
        return Err(serde::de::Error::custom(
            "line values must be 1 or greater. Fix: pass a positive source line number.",
        ));
    }
    Ok(value)
}

fn deserialize_optional_positive_usize<'de, D>(deserializer: D) -> Result<Option<usize>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<usize>::deserialize(deserializer)?;
    match value {
        Some(0) => Err(serde::de::Error::custom(
            "column values must be 1 or greater. Fix: pass a positive source column number.",
        )),
        _ => Ok(value),
    }
}

// Small helper formatters keep the main `fmt` implementation compact and
// easier to audit for correctness.
fn fmt_http_response(
    f: &mut std::fmt::Formatter<'_>,
    status: u16,
    headers: &[(Arc<str>, Arc<str>)],
    body_excerpt: Option<&Arc<str>>,
) -> std::fmt::Result {
    let excerpt = body_excerpt.as_ref().map_or_else(
        || "none".to_string(),
        |s| format!("<redacted,len={}>", s.len()),
    );
    write!(
        f,
        "http-response status={status} headers={} body_excerpt={excerpt}",
        headers.len()
    )
}

fn fmt_http_request(
    f: &mut std::fmt::Formatter<'_>,
    method: &str,
    url: &str,
    headers: &[(Arc<str>, Arc<str>)],
    body: Option<&Arc<str>>,
) -> std::fmt::Result {
    let body_info = body.as_ref().map_or_else(
        || "none".to_string(),
        |b| format!("<redacted,len={}>", b.len()),
    );
    write!(
        f,
        "http-request:{method} {url} headers={} body={body_info}",
        headers.len()
    )
}

fn fmt_code_snippet(
    f: &mut std::fmt::Formatter<'_>,
    file: &str,
    line: usize,
    language: Option<&Arc<str>>,
) -> std::fmt::Result {
    if let Some(lang) = language {
        write!(f, "code-snippet:{file}:{line} [{lang}]")
    } else {
        write!(f, "code-snippet:{file}:{line}")
    }
}

impl std::fmt::Display for Evidence {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HttpResponse {
                status,
                headers,
                body_excerpt,
            } => fmt_http_response(f, *status, headers, body_excerpt.as_ref()),
            Self::DnsRecord { record_type, .. } => write!(f, "dns:{record_type}"),
            Self::Banner { raw } => write!(f, "banner<len={}>", raw.len()),
            Self::JsSnippet { url, line, .. } => write!(f, "js-snippet:{url}:{line}"),
            Self::Certificate {
                subject,
                issuer,
                san,
                ..
            } => write!(
                f,
                "certificate:{subject} issuer={issuer} san_count={}",
                san.len()
            ),
            Self::CodeSnippet {
                file,
                line,
                language,
                ..
            } => fmt_code_snippet(f, file, *line, language.as_ref()),
            Self::HttpRequest {
                method,
                url,
                headers,
                body,
            } => fmt_http_request(f, method, url, headers, body.as_ref()),
            Self::PatternMatch { pattern, matched } => write!(
                f,
                "pattern-match:{pattern} => <redacted,len={}>",
                matched.len()
            ),
            Self::Raw { value } => write!(f, "raw:<redacted,len={}>", value.len()),
            Self::AppMapReplay {
                endpoint, per_role, ..
            } => write!(f, "appmap-replay:{endpoint} roles={}", per_role.len()),
            Self::BolaProbe {
                owner_role,
                prober_role,
                resource_kind,
                access_outcome,
                leaked_privacy_fields,
                ..
            } => write!(
                f,
                "bola-probe:{resource_kind} owner={owner_role} prober={prober_role} outcome={access_outcome:?} leaked_fields={}",
                leaked_privacy_fields.len()
            ),
            Self::LoginFlowTrace {
                steps,
                captured_cookies_count,
                captured_headers_count,
                canary_response_status,
            } => write!(
                f,
                "login-flow:steps={} cookies={captured_cookies_count} headers={captured_headers_count} canary={canary_response_status}",
                steps.len()
            ),
            Self::StealthProbe {
                profile_name,
                per_detector,
                overall_undetected,
            } => write!(
                f,
                "stealth-probe:{profile_name} detectors={} undetected={overall_undetected}",
                per_detector.len()
            ),
            Self::CaptchaBypass {
                vendor,
                challenge_type,
                time_to_solve_ms,
                retries,
                bypass_succeeded,
            } => write!(
                f,
                "captcha-bypass:{vendor}/{challenge_type} time_ms={time_to_solve_ms} retries={retries} succeeded={bypass_succeeded}"
            ),
            Self::WorkflowCrossStepWitness {
                workflow_id,
                injection_step,
                observation_step,
                observation_role,
                ..
            } => write!(
                f,
                "workflow-cross-step:{workflow_id} {injection_step}->{observation_step} as={observation_role}"
            ),
            Self::DomExecution {
                sink,
                source,
                executed,
                ..
            } => write!(f, "dom-execution:source={source} sink={sink} executed={executed}"),
            Self::SourceLeak {
                file,
                line_start,
                line_end,
                secret_kind,
                confidence,
                ..
            } => write!(
                f,
                "source-leak:{file}:{line_start}-{line_end} kind={secret_kind} confidence={confidence}"
            ),
            Self::RuntimeBehaviorTrace {
                anomaly_kind,
                causally_related_events,
                ..
            } => write!(
                f,
                "runtime-behavior:{anomaly_kind} related_events={}",
                causally_related_events.len()
            ),
            Self::DetonationVerdict {
                verdict,
                family,
                confidence,
                ..
            } => match family {
                Some(fam) => write!(f, "detonation:{verdict} family={fam} confidence={confidence}"),
                None => write!(f, "detonation:{verdict} confidence={confidence}"),
            },
            Self::InvariantViolation { invariant, .. } => {
                write!(f, "invariant-violation:{invariant}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_tagged() {
        let ev = Evidence::HttpResponse {
            status: 403,
            headers: vec![("server".into(), "cloudflare".into())],
            body_excerpt: Some("blocked".into()),
        };
        let json = serde_json::to_value(&ev).unwrap();
        assert_eq!(json["type"], "http_response");
        assert_eq!(json["status"], 403);
    }

    /// REGRESSION: `Evidence::Raw` MUST serialize and round-trip. It was
    /// a newtype variant in an internally-tagged enum, which serde
    /// **panics** on ("cannot serialize tagged newtype variant ...
    /// containing a string")  -  a real defect that broke every
    /// JSON/JSONL consumer (e.g. `gossan subdomain --format json`) and
    /// had been *documented-around* (omitted from generated tests)
    /// rather than fixed. As a struct variant it serializes cleanly.
    #[test]
    fn raw_evidence_serializes_and_roundtrips() {
        let ev = Evidence::raw("unstructured proof");
        // The exact serialization that used to panic:
        let json = serde_json::to_string(&ev).expect("Raw must serialize");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["type"], "raw");
        assert_eq!(v["value"], "unstructured proof");
        let back: Evidence = serde_json::from_str(&json).unwrap();
        match back {
            Evidence::Raw { value } => assert_eq!(value.as_ref(), "unstructured proof"),
            other => panic!("round-trip changed variant: {other:?}"),
        }
        // Constructor accepts &str / String / Arc<str>.
        let _ = Evidence::raw(String::from("s"));
        let _ = Evidence::raw(std::sync::Arc::<str>::from("a"));
    }

    #[test]
    fn code_snippet_roundtrip() {
        let ev = Evidence::code("src/main.rs", 42, "let key = \"AKIA...\";", None, None).unwrap();
        let json = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&json).unwrap();
        if let Evidence::CodeSnippet {
            file,
            line,
            snippet,
            ..
        } = back
        {
            assert_eq!(file.as_ref(), "src/main.rs");
            assert_eq!(line, 42);
            assert_eq!(snippet.as_ref(), "let key = \"AKIA...\";");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn helper_constructors_roundtrip() {
        let ev = Evidence::http_status(201).unwrap();
        let json = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&json).unwrap();
        if let Evidence::HttpResponse {
            status,
            headers,
            body_excerpt,
        } = back
        {
            assert_eq!(status, 201);
            assert!(headers.is_empty());
            assert!(body_excerpt.is_none());
        } else {
            panic!("wrong variant");
        }

        let snippet = Evidence::code("lib.rs", 10, "secret = 'x'", None, None).unwrap();
        let json = serde_json::to_string(&snippet).unwrap();
        let back: Evidence = serde_json::from_str(&json).unwrap();
        if let Evidence::CodeSnippet { line, snippet, .. } = back {
            assert_eq!(line, 10);
            assert!(snippet.contains("secret"));
        } else {
            panic!("wrong variant");
        }
    }

    // ── v0.4.0 variant roundtrip tests ────────────────────────────────

    #[test]
    fn v04_appmap_replay_roundtrip() {
        let ev = Evidence::AppMapReplay {
            endpoint: "/api/notes/:id".into(),
            per_role: vec![RoleResponseSample {
                role_id: "owner".into(),
                status: 200,
                response_hash: "h".into(),
                diff_excerpt: None,
            }],
            diff_summary: "ok".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn v04_bola_probe_all_outcomes_roundtrip() {
        for outcome in [
            AccessOutcome::SuccessWithData,
            AccessOutcome::SuccessEmpty,
            AccessOutcome::Denied,
            AccessOutcome::NotFound,
            AccessOutcome::Other,
        ] {
            let ev = Evidence::BolaProbe {
                owner_role: "a".into(),
                prober_role: "b".into(),
                resource_kind: "Note".into(),
                resource_id_token: "42".into(),
                access_outcome: outcome,
                leaked_privacy_fields: vec!["email".into()],
            };
            let json = serde_json::to_string(&ev).unwrap();
            let back: Evidence = serde_json::from_str(&json).unwrap();
            assert_eq!(back, ev);
        }
    }

    #[test]
    fn v04_login_flow_trace_roundtrip_and_canary_validation() {
        let ev = Evidence::LoginFlowTrace {
            steps: vec!["discover".into(), "drive".into()],
            captured_cookies_count: 3,
            captured_headers_count: 1,
            canary_response_status: 200,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
        let bad = json.replace(
            "\"canary_response_status\":200",
            "\"canary_response_status\":7",
        );
        assert!(serde_json::from_str::<Evidence>(&bad).is_err());
    }

    #[test]
    fn v04_stealth_probe_roundtrip() {
        let ev = Evidence::StealthProbe {
            profile_name: "chrome131".into(),
            per_detector: vec![
                DetectorOutcome {
                    detector_id: "webdriver".into(),
                    passed: true,
                    detail: None,
                },
                DetectorOutcome {
                    detector_id: "canvas".into(),
                    passed: false,
                    detail: Some("matched".into()),
                },
            ],
            overall_undetected: false,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn v04_captcha_bypass_roundtrip() {
        let ev = Evidence::CaptchaBypass {
            vendor: "CloudflareTurnstile".into(),
            challenge_type: "managed".into(),
            time_to_solve_ms: 4321,
            retries: 1,
            bypass_succeeded: true,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn v04_workflow_cross_step_witness_roundtrip() {
        let ev = Evidence::WorkflowCrossStepWitness {
            workflow_id: "wf".into(),
            injection_step: "s1".into(),
            observation_step: "s2".into(),
            observation_role: "b".into(),
            payload_excerpt: "<img>".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn v04_dom_execution_roundtrip() {
        let ev = Evidence::DomExecution {
            sink: "innerHTML".into(),
            source: "location.hash".into(),
            executed: true,
            observed_marker: "MARK".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn v04_source_leak_roundtrip_validates_line_zero() {
        let ev = Evidence::SourceLeak {
            file: ".env".into(),
            line_start: 12,
            line_end: 12,
            secret_kind: "AWS_ACCESS_KEY".into(),
            confidence: Confidence::new(0.95).unwrap(),
            rotation_url_hint: Some("https://x".into()),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
        let bad = r#"{"type":"source_leak","file":"x","line_start":0,"line_end":1,"secret_kind":"x","confidence":0.5,"rotation_url_hint":null}"#;
        assert!(serde_json::from_str::<Evidence>(bad).is_err());
    }

    #[test]
    fn v04_runtime_behavior_trace_roundtrip() {
        let ev = Evidence::RuntimeBehaviorTrace {
            anomaly_kind: "tls-cleartext".into(),
            trace_excerpt: "write fd=3".into(),
            causally_related_events: vec!["e1".into()],
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn v04_detonation_verdict_roundtrip_with_and_without_family() {
        let ev1 = Evidence::DetonationVerdict {
            verdict: "malicious".into(),
            family: Some("Emotet".into()),
            confidence: Confidence::new(0.88).unwrap(),
            proof_excerpt: "shellcode".into(),
        };
        let ev2 = Evidence::DetonationVerdict {
            verdict: "likely_safe".into(),
            family: None,
            confidence: Confidence::new(0.7).unwrap(),
            proof_excerpt: "static".into(),
        };
        for ev in [ev1, ev2] {
            let json = serde_json::to_string(&ev).unwrap();
            let back: Evidence = serde_json::from_str(&json).unwrap();
            assert_eq!(back, ev);
        }
    }

    #[test]
    fn v04_invariant_violation_roundtrip() {
        let ev = Evidence::InvariantViolation {
            invariant: "must require ownership".into(),
            violation_detail: "b accessed a's resource".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn v04_confidence_rejects_nan_and_out_of_range() {
        assert!(Confidence::new(f32::NAN).is_err());
        assert!(Confidence::new(-0.1).is_err());
        assert!(Confidence::new(1.1).is_err());
        assert!(Confidence::new(0.0).is_ok());
        assert!(Confidence::new(1.0).is_ok());
    }

    #[test]
    fn serde_multiple_evidence_variants() {
        let samples = vec![
            Evidence::HttpRequest {
                method: "GET".into(),
                url: "https://example.com/login".into(),
                headers: vec![("host".into(), "example.com".into())],
                body: Some("a=1".into()),
            },
            Evidence::Certificate {
                subject: "CN=example".into(),
                san: vec!["DNS:example.com".into()],
                issuer: "Let's Encrypt".into(),
                expires: "2028-01-01".into(),
            },
            Evidence::PatternMatch {
                pattern: "api_key=[A-Za-z]+".into(),
                matched: "api_key=abc".into(),
            },
        ];

        for sample in samples {
            let json = serde_json::to_string(&sample).unwrap();
            let back: Evidence = serde_json::from_str(&json).unwrap();
            match (sample, back) {
                (
                    Evidence::HttpRequest { method: m1, .. },
                    Evidence::HttpRequest { method: m2, .. },
                ) => {
                    assert_eq!(m1, m2);
                }
                (
                    Evidence::Certificate { subject: s1, .. },
                    Evidence::Certificate { subject: s2, .. },
                ) => {
                    assert_eq!(s1, s2);
                }
                (
                    Evidence::PatternMatch { pattern: p1, .. },
                    Evidence::PatternMatch { pattern: p2, .. },
                ) => {
                    assert_eq!(p1, p2);
                }
                _ => panic!("roundtrip mismatch"),
            }
        }
    }
}
