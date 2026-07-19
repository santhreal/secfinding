//! S-proptest-01: Finding / Evidence JSON roundtrips with arbitrary optional fields.

use crate::strategies::{arb_evidence_text, arb_scanner, arb_tag, arb_target};
use proptest::prelude::*;
use secfinding::{
    AccessOutcome, Confidence, DetectorOutcome, Evidence, Finding, FindingBuilder, FindingKind,
    FindingStatus, RoleResponseSample, Severity,
};
use std::sync::Arc;

fn json_roundtrip<T>(value: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let json = serde_json::to_string(value).expect("serialize");
    serde_json::from_str(&json).expect("deserialize")
}

fn assert_finding_fields_eq(
    original: &Finding,
    restored: &Finding,
) -> Result<(), proptest::test_runner::TestCaseError> {
    prop_assert_eq!(original.scanner(), restored.scanner());
    prop_assert_eq!(original.target(), restored.target());
    prop_assert_eq!(original.title(), restored.title());
    prop_assert_eq!(original.detail(), restored.detail());
    prop_assert_eq!(original.severity(), restored.severity());
    prop_assert_eq!(original.kind(), restored.kind());
    prop_assert_eq!(original.status(), restored.status());
    prop_assert_eq!(original.tags().len(), restored.tags().len());
    prop_assert_eq!(original.evidence().len(), restored.evidence().len());
    prop_assert_eq!(original.cve_ids().len(), restored.cve_ids().len());
    prop_assert_eq!(original.cwe_ids().len(), restored.cwe_ids().len());
    prop_assert_eq!(original.references().len(), restored.references().len());
    prop_assert_eq!(
        original.matched_values().len(),
        restored.matched_values().len()
    );
    prop_assert_eq!(original.confidence(), restored.confidence());
    prop_assert_eq!(original.cvss_score(), restored.cvss_score());
    prop_assert_eq!(original.scan_id(), restored.scan_id());
    prop_assert_eq!(original.exploit_hint(), restored.exploit_hint());
    prop_assert_eq!(original.remediation(), restored.remediation());
    Ok(())
}

const FINDING_KINDS: [FindingKind; 12] = [
    FindingKind::Vulnerability,
    FindingKind::Misconfiguration,
    FindingKind::Exposure,
    FindingKind::TechDetect,
    FindingKind::DefaultCredentials,
    FindingKind::InfoDisclosure,
    FindingKind::FileDiscovery,
    FindingKind::SecretLeak,
    FindingKind::MaliciousCode,
    FindingKind::SupplyChain,
    FindingKind::AccessControl,
    FindingKind::Other,
];

prop_compose! {
    fn arb_severity()(n in 0u8..5) -> Severity {
        Severity::try_from(n).unwrap()
    }
}

prop_compose! {
    fn arb_kind()(n in 0u8..12) -> FindingKind {
        FINDING_KINDS[n as usize % FINDING_KINDS.len()]
    }
}

prop_compose! {
    fn arb_status()(n in 0u8..4) -> FindingStatus {
        match n % 4 {
            0 => FindingStatus::Open,
            1 => FindingStatus::Confirmed,
            2 => FindingStatus::FalsePositive,
            _ => FindingStatus::Resolved,
        }
    }
}

prop_compose! {
    fn arb_confidence_bits()(bits in 0u32..=1_000_000u32) -> Confidence {
        let v = (bits % 1_000_001) as f32 / 1_000_000.0;
        Confidence::new(v).expect("valid confidence")
    }
}

fn ev_http_response(status: u16, text: &str, flag: bool) -> Evidence {
    let body = if flag {
        Some(Arc::<str>::from(text))
    } else {
        None
    };
    Evidence::HttpResponse {
        status,
        headers: vec![(Arc::from("X-Test"), Arc::from(text))],
        body_excerpt: body,
    }
}

fn ev_dns(text: &str) -> Evidence {
    Evidence::DnsRecord {
        record_type: Arc::from("A"),
        value: Arc::from(text),
    }
}

fn ev_banner(text: &str) -> Evidence {
    Evidence::Banner {
        raw: Arc::from(text),
    }
}

fn ev_js_snippet(status: u16, text: &str) -> Evidence {
    Evidence::JsSnippet {
        url: Arc::from("https://example.com/app.js"),
        line: 1usize.max(status as usize % 10_000),
        snippet: Arc::from(text),
    }
}

fn ev_certificate(text: &str) -> Evidence {
    Evidence::Certificate {
        subject: Arc::from("CN=test"),
        san: vec![Arc::from(text)],
        issuer: Arc::from("CN=issuer"),
        expires: Arc::from("2099-01-01"),
    }
}

fn ev_pattern_match(text: &str) -> Evidence {
    Evidence::PatternMatch {
        pattern: Arc::from("test.*"),
        matched: Arc::from(text),
    }
}

fn ev_http_request(text: &str, flag: bool) -> Evidence {
    let body = if flag { Some(Arc::from(text)) } else { None };
    Evidence::HttpRequest {
        method: Arc::from("GET"),
        url: Arc::from("https://example.com/"),
        headers: vec![(Arc::from("Host"), Arc::from("example.com"))],
        body,
    }
}

fn ev_appmap_replay(status: u16, text: &str, flag: bool) -> Evidence {
    Evidence::AppMapReplay {
        endpoint: Arc::from("/api"),
        per_role: vec![RoleResponseSample {
            role_id: Arc::from("admin"),
            status,
            response_hash: Arc::from("abc"),
            diff_excerpt: if flag { Some(Arc::from(text)) } else { None },
        }],
        diff_summary: Arc::from(text),
    }
}

fn ev_bola_probe(text: &str, flag: bool) -> Evidence {
    Evidence::BolaProbe {
        owner_role: Arc::from("owner"),
        prober_role: Arc::from("guest"),
        resource_kind: Arc::from("Note"),
        resource_id_token: Arc::from("id-1"),
        access_outcome: if flag {
            AccessOutcome::SuccessWithData
        } else {
            AccessOutcome::Denied
        },
        leaked_privacy_fields: vec![Arc::from(text)],
    }
}

fn ev_login_flow_trace(status: u16) -> Evidence {
    Evidence::LoginFlowTrace {
        steps: vec![Arc::from("login"), Arc::from("mfa")],
        captured_cookies_count: (status % 20) as usize,
        captured_headers_count: (status % 10) as usize,
        canary_response_status: status,
    }
}

fn ev_stealth_probe(text: &str, flag: bool) -> Evidence {
    Evidence::StealthProbe {
        profile_name: Arc::from("stealth"),
        per_detector: vec![DetectorOutcome {
            detector_id: Arc::from("waf"),
            passed: flag,
            detail: if flag { None } else { Some(Arc::from(text)) },
        }],
        overall_undetected: flag,
    }
}

fn ev_captcha_bypass(status: u16, flag: bool) -> Evidence {
    Evidence::CaptchaBypass {
        vendor: Arc::from("vendor"),
        challenge_type: Arc::from("image"),
        time_to_solve_ms: status as u64,
        retries: (status % 5) as u32,
        bypass_succeeded: flag,
    }
}

fn ev_workflow_witness(text: &str) -> Evidence {
    Evidence::WorkflowCrossStepWitness {
        workflow_id: Arc::from("wf-1"),
        injection_step: Arc::from("step-a"),
        observation_step: Arc::from("step-b"),
        observation_role: Arc::from("user"),
        payload_excerpt: Arc::from(text),
    }
}

fn ev_dom_execution(text: &str, flag: bool) -> Evidence {
    Evidence::DomExecution {
        sink: Arc::from("innerHTML"),
        source: Arc::from("url"),
        executed: flag,
        observed_marker: Arc::from(text),
    }
}

fn ev_source_leak(_text: &str, flag: bool, conf: Confidence) -> Evidence {
    Evidence::SourceLeak {
        file: Arc::from("src/main.rs"),
        line_start: 1,
        line_end: 2,
        secret_kind: Arc::from("api-key"),
        confidence: conf,
        rotation_url_hint: if flag {
            Some(Arc::from("https://rotate.example"))
        } else {
            None
        },
    }
}

fn ev_runtime_trace(text: &str) -> Evidence {
    Evidence::RuntimeBehaviorTrace {
        anomaly_kind: Arc::from("syscall"),
        trace_excerpt: Arc::from(text),
        causally_related_events: vec![Arc::from("evt-1")],
    }
}

fn ev_detonation_verdict(text: &str, flag: bool, conf: Confidence) -> Evidence {
    Evidence::DetonationVerdict {
        verdict: Arc::from("malicious"),
        family: if flag {
            Some(Arc::from("family"))
        } else {
            None
        },
        confidence: conf,
        proof_excerpt: Arc::from(text),
    }
}

fn ev_invariant_violation(text: &str) -> Evidence {
    Evidence::InvariantViolation {
        invariant: Arc::from("no-debug"),
        violation_detail: Arc::from(text),
    }
}

macro_rules! finding_props {
    ($($name:ident, $preset:ident);+ $(;)?) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(32))]
            $(
                #[test]
                fn $name(
                    scanner in arb_scanner(),
                    target in arb_target(),
                    title in arb_evidence_text(),
                    detail in arb_evidence_text(),
                    sev in arb_severity(),
                    kind in arb_kind(),
                    status in arb_status(),
                ) {
                    let mut builder =
                        Finding::builder(&scanner, &target, sev).title(&title).detail(&detail);
                    builder = builder.kind(kind).status(status);
                    builder = configure_finding(builder, FindingConfigure::$preset);
                    let Ok(finding) = builder.build() else {
                        return Ok(());
                    };
                    let restored: Finding = json_roundtrip(&finding);
                    assert_finding_fields_eq(&finding, &restored)?;
                }
            )+
        }
    };
}

#[derive(Clone, Copy)]
enum FindingConfigure {
    Minimal,
    Tags,
    CveCwe,
    References,
    Confidence,
    Cvss,
    ScanId,
    ExploitHint,
    Remediation,
    MatchedValues,
    EvidenceHttp,
    EvidenceRaw,
    AllOptionals,
}

fn configure_finding(builder: FindingBuilder, mode: FindingConfigure) -> FindingBuilder {
    match mode {
        FindingConfigure::Minimal => builder,
        FindingConfigure::Tags => builder.tag("alpha").tag("beta"),
        FindingConfigure::CveCwe => builder.cve("CVE-2024-0001").cwe("CWE-79"),
        FindingConfigure::References => builder.reference("https://example.com/advisory"),
        FindingConfigure::Confidence => builder.confidence(0.75),
        FindingConfigure::Cvss => builder.cvss_score(7.5),
        FindingConfigure::ScanId => builder.scan_id("scan-abc"),
        FindingConfigure::ExploitHint => builder.exploit_hint("curl -X POST ..."),
        FindingConfigure::Remediation => builder.remediation("rotate credentials"),
        FindingConfigure::MatchedValues => builder.matched_value("payload").matched_value("token"),
        FindingConfigure::EvidenceHttp => {
            if let Ok(ev) = Evidence::http_status(403) {
                builder.evidence(ev)
            } else {
                builder
            }
        }
        FindingConfigure::EvidenceRaw => builder.evidence(Evidence::raw("proof")),
        FindingConfigure::AllOptionals => {
            let mut b = builder
                .tag("t1")
                .cve("CVE-2024-1")
                .cwe("CWE-22")
                .reference("https://ref")
                .confidence(0.9)
                .cvss_score(9.0)
                .scan_id("sid")
                .exploit_hint("hint")
                .remediation("fix")
                .matched_value("mv");
            if let Ok(ev) = Evidence::http_status(500) {
                b = b.evidence(ev);
            }
            b
        }
    }
}

finding_props! {
    prop_finding_minimal_json, Minimal;
    prop_finding_with_tags, Tags;
    prop_finding_with_cve_cwe, CveCwe;
    prop_finding_with_references, References;
    prop_finding_with_confidence, Confidence;
    prop_finding_with_cvss, Cvss;
    prop_finding_with_scan_id, ScanId;
    prop_finding_with_exploit_hint, ExploitHint;
    prop_finding_with_remediation, Remediation;
    prop_finding_with_matched_values, MatchedValues;
    prop_finding_with_evidence_http, EvidenceHttp;
    prop_finding_with_evidence_raw, EvidenceRaw;
    prop_finding_all_optionals, AllOptionals;
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_evidence_http_response(
        status in 100u16..=599u16,
        text in arb_evidence_text(),
        flag in any::<bool>(),
    ) {
        let ev = ev_http_response(status, &text, flag);
        let back = json_roundtrip(&ev);
        prop_assert_eq!(ev, back);
    }

    #[test]
    fn prop_evidence_dns_record(text in arb_evidence_text()) {
        let ev = ev_dns(&text);
        let back = json_roundtrip(&ev);
        prop_assert_eq!(ev, back);
    }

    #[test]
    fn prop_evidence_banner(text in arb_evidence_text()) {
        let ev = ev_banner(&text);
        let back = json_roundtrip(&ev);
        prop_assert_eq!(ev, back);
    }

    #[test]
    fn prop_evidence_js_snippet(status in 100u16..=599u16, text in arb_evidence_text()) {
        let ev = ev_js_snippet(status, &text);
        let back = json_roundtrip(&ev);
        prop_assert_eq!(ev, back);
    }

    #[test]
    fn prop_evidence_certificate(text in arb_evidence_text()) {
        let ev = ev_certificate(&text);
        let back = json_roundtrip(&ev);
        prop_assert_eq!(ev, back);
    }

    #[test]
    fn prop_evidence_pattern_match(text in arb_evidence_text()) {
        let ev = ev_pattern_match(&text);
        let back = json_roundtrip(&ev);
        prop_assert_eq!(ev, back);
    }

    #[test]
    fn prop_evidence_raw(text in arb_evidence_text()) {
        let ev = Evidence::raw(text.as_str());
        let back = json_roundtrip(&ev);
        prop_assert_eq!(ev, back);
    }

    #[test]
    fn prop_evidence_http_request(text in arb_evidence_text(), flag in any::<bool>()) {
        let ev = ev_http_request(&text, flag);
        let back = json_roundtrip(&ev);
        prop_assert_eq!(ev, back);
    }

    #[test]
    fn prop_evidence_appmap_replay(
        status in 100u16..=599u16,
        text in arb_evidence_text(),
        flag in any::<bool>(),
    ) {
        let ev = ev_appmap_replay(status, &text, flag);
        let back = json_roundtrip(&ev);
        prop_assert_eq!(ev, back);
    }

    #[test]
    fn prop_evidence_bola_probe(text in arb_evidence_text(), flag in any::<bool>()) {
        let ev = ev_bola_probe(&text, flag);
        let back = json_roundtrip(&ev);
        prop_assert_eq!(ev, back);
    }

    #[test]
    fn prop_evidence_login_flow_trace(status in 100u16..=599u16) {
        let ev = ev_login_flow_trace(status);
        let back = json_roundtrip(&ev);
        prop_assert_eq!(ev, back);
    }

    #[test]
    fn prop_evidence_stealth_probe(text in arb_evidence_text(), flag in any::<bool>()) {
        let ev = ev_stealth_probe(&text, flag);
        let back = json_roundtrip(&ev);
        prop_assert_eq!(ev, back);
    }

    #[test]
    fn prop_evidence_captcha_bypass(status in 100u16..=599u16, flag in any::<bool>()) {
        let ev = ev_captcha_bypass(status, flag);
        let back = json_roundtrip(&ev);
        prop_assert_eq!(ev, back);
    }

    #[test]
    fn prop_evidence_workflow_witness(text in arb_evidence_text()) {
        let ev = ev_workflow_witness(&text);
        let back = json_roundtrip(&ev);
        prop_assert_eq!(ev, back);
    }

    #[test]
    fn prop_evidence_dom_execution(text in arb_evidence_text(), flag in any::<bool>()) {
        let ev = ev_dom_execution(&text, flag);
        let back = json_roundtrip(&ev);
        prop_assert_eq!(ev, back);
    }

    #[test]
    fn prop_evidence_source_leak(
        text in arb_evidence_text(),
        flag in any::<bool>(),
        conf in arb_confidence_bits(),
    ) {
        let ev = ev_source_leak(&text, flag, conf);
        let back = json_roundtrip(&ev);
        prop_assert_eq!(ev, back);
    }

    #[test]
    fn prop_evidence_runtime_trace(text in arb_evidence_text()) {
        let ev = ev_runtime_trace(&text);
        let back = json_roundtrip(&ev);
        prop_assert_eq!(ev, back);
    }

    #[test]
    fn prop_evidence_detonation_verdict(
        text in arb_evidence_text(),
        flag in any::<bool>(),
        conf in arb_confidence_bits(),
    ) {
        let ev = ev_detonation_verdict(&text, flag, conf);
        let back = json_roundtrip(&ev);
        prop_assert_eq!(ev, back);
    }

    #[test]
    fn prop_evidence_invariant_violation(text in arb_evidence_text()) {
        let ev = ev_invariant_violation(&text);
        let back = json_roundtrip(&ev);
        prop_assert_eq!(ev, back);
    }

    #[test]
    fn prop_evidence_code_snippet_roundtrip(
        file in "[a-zA-Z][a-zA-Z0-9/._-]{1,32}",
        line in 1usize..5000usize,
        snippet in "[a-zA-Z0-9]{1,64}",
        col in 1u32..200u32,
        lang in proptest::option::of("[a-z]{2,8}"),
    ) {
        let Ok(ev) = Evidence::code(&file, line, &snippet, Some(col as usize), lang) else {
            return Ok(());
        };
        let back = json_roundtrip(&ev);
        prop_assert_eq!(ev, back);
    }

    #[test]
    fn prop_evidence_http_status_roundtrip(status in 100u16..=599u16) {
        let ev = Evidence::http_status(status).expect("valid status");
        let back = json_roundtrip(&ev);
        prop_assert_eq!(ev, back);
    }

    #[test]
    fn prop_finding_evidence_vec_preserved(
        scanner in arb_scanner(),
        target in arb_target(),
        n in 1usize..4usize,
    ) {
        let mut builder = Finding::builder(&scanner, &target, Severity::Medium).title("t");
        for i in 0..n {
            if let Ok(ev) = Evidence::http_status(200 + i as u16) {
                builder = builder.evidence(ev);
            }
        }
        let Ok(finding) = builder.build() else { return Ok(()); };
        let restored: Finding = json_roundtrip(&finding);
        prop_assert_eq!(finding.evidence().len(), restored.evidence().len());
        prop_assert_eq!(finding.evidence().len(), n);
    }

    #[test]
    fn prop_finding_toml_then_json_stable_fields(
        scanner in arb_scanner(),
        target in arb_target(),
        tag in arb_tag(),
    ) {
        let finding = Finding::builder(&scanner, &target, Severity::High)
            .title("title")
            .tag(tag.as_str())
            .build()
            .expect("build");
        let json1 = serde_json::to_string(&finding).unwrap();
        let json2 = serde_json::to_string(&json_roundtrip::<Finding>(&finding)).unwrap();
        prop_assert_eq!(json1, json2);
    }
}
