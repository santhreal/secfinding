//! Integration round-trip for Evidence variants used by the detonation fleet.

use secfinding::{Confidence, Evidence, Finding, FindingKind, Severity};

fn roundtrip(ev: &Evidence) {
    let json = serde_json::to_string(ev).expect("serialize evidence");
    let back: Evidence = serde_json::from_str(&json).expect("deserialize evidence");
    assert_eq!(&back, ev);
}

#[test]
fn detonation_verdict_evidence_roundtrips() {
    roundtrip(&Evidence::DetonationVerdict {
        verdict: "malicious".into(),
        family: Some("Emotet".into()),
        confidence: Confidence::new(0.91).unwrap(),
        proof_excerpt: "shellcode stub".into(),
    });
    roundtrip(&Evidence::DetonationVerdict {
        verdict: "likely_safe".into(),
        family: None,
        confidence: Confidence::new(0.55).unwrap(),
        proof_excerpt: "benign manifest".into(),
    });
}

#[test]
fn source_leak_and_code_snippet_roundtrip_for_static_detonators() {
    roundtrip(&Evidence::SourceLeak {
        file: "src/index.js".into(),
        line_start: 4,
        line_end: 6,
        secret_kind: "GH_PAT".into(),
        confidence: Confidence::new(0.99).unwrap(),
        rotation_url_hint: None,
    });
    roundtrip(
        &Evidence::code("pkg/main.py", 10, "eval(user)", None, Some("python".into()))
            .expect("valid snippet"),
    );
}

#[test]
fn pattern_match_roundtrip_for_rule_hits() {
    roundtrip(&Evidence::PatternMatch {
        pattern: "extdet/eval".into(),
        matched: "eval(payload)".into(),
    });
}

#[test]
fn finding_with_detonation_evidence_serializes_as_document() {
    let finding = Finding::builder("jsdet", "https://evil.test/pkg.js", Severity::High)
        .title("Suspicious package behavior")
        .kind(FindingKind::DetonationVerdict)
        .tag("rule_id:jsdet/sandbox-rce")
        .evidence(Evidence::DetonationVerdict {
            verdict: "suspicious".into(),
            family: Some("stealer".into()),
            confidence: Confidence::new(0.8).unwrap(),
            proof_excerpt: "child_process.spawn".into(),
        })
        .build()
        .expect("valid finding");
    let json = serde_json::to_string(&finding).expect("serialize finding");
    let back: Finding = serde_json::from_str(&json).expect("deserialize finding");
    assert_eq!(back.scanner(), "jsdet");
    assert_eq!(back.kind(), FindingKind::DetonationVerdict);
    assert_eq!(back.evidence().len(), 1);
    roundtrip(&back.evidence()[0]);
}
