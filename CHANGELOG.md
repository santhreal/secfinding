# Changelog

## v0.4.0

Published to [crates.io](https://crates.io/crates/secfinding). Additive extensions for the Santh unified-machine output.

### Documentation
- README documents `Evidence::raw()` for unstructured proof.
- `secir` feature stub for gated bridge tests until secir publishes. Zero breaking changes vs v0.3.0 (all additions land behind `#[non_exhaustive]` enums).

### New `Evidence` variants
- `AppMapReplay { endpoint, per_role, diff_summary }`
- `BolaProbe { owner_role, prober_role, resource_kind, resource_id_token, access_outcome, leaked_privacy_fields }`
- `LoginFlowTrace { steps, captured_cookies_count, captured_headers_count, canary_response_status }`
- `StealthProbe { profile_name, per_detector, overall_undetected }`
- `CaptchaBypass { vendor, challenge_type, time_to_solve_ms, retries, bypass_succeeded }`
- `WorkflowCrossStepWitness { workflow_id, injection_step, observation_step, observation_role, payload_excerpt }`
- `DomExecution { sink, source, executed, observed_marker }`
- `SourceLeak { file, line_start, line_end, secret_kind, confidence, rotation_url_hint }`
- `RuntimeBehaviorTrace { anomaly_kind, trace_excerpt, causally_related_events }`
- `DetonationVerdict { verdict, family, confidence, proof_excerpt }`
- `InvariantViolation { invariant, violation_detail }`

### New supporting types
- `Confidence` newtype around f32 (with NaN + range validation; Hash + Eq via bit pattern).
- `RoleResponseSample`, `AccessOutcome` enum, `DetectorOutcome`.

### New `FindingKind` variants
- `AccessControl`, `AuthFlow`, `BusinessLogic`, `BotDetection`, `CaptchaBypass`, `DetonationVerdict`, `BehavioralAnomaly`, `InvariantViolation`. All with `Display`, `FromStr`, `severity_floor`, `is_actionable`, `requires_severity_bump` wired.

### New `projection` module
- `ProjectionKey { system, key }`: secbench-side matchers extract via `Finding::projection_keys()` to dispatch on the well-known `Coord` system tags (`RoleMatrix`, `WorkflowStep`, `AppMapEntity`, `StealthProbe`, `CaptchaChallenge`, `AuthSession`, `RuntimeTrace`, `DetonationArtifact`, plus existing `Source` / `Http` / `Dataflow` / `Opaque`).

### Compatibility
- v0.3.0 consumers compile unchanged; new variants behind `#[non_exhaustive]`.
- Serde wire format additive per the existing internally-tagged convention.

## v0.2.0

- Added `#[non_exhaustive]` to extensible public enums such as `Severity`.
- Added `Display` implementations for printable public types including `Finding`, `FindingBuilder`, `FindingFilter`, and `Evidence`.
- Added `# Thread Safety` API docs for all public types and traits.
- Added `#[must_use]` to important constructors and builders that return values callers should not ignore.
