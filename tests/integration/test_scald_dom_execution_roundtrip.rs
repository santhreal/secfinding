//! Integration round-trip for `Evidence::DomExecution` (scald DOM-XSS emission).

use secfinding::{Evidence, Finding, FindingKind, Severity};

fn roundtrip(ev: &Evidence) {
    let json = serde_json::to_string(ev).expect("serialize evidence");
    let back: Evidence = serde_json::from_str(&json).expect("deserialize evidence");
    assert_eq!(&back, ev);
}

#[test]
fn dom_execution_evidence_roundtrips() {
    roundtrip(&Evidence::DomExecution {
        sink: "innerHTML".into(),
        source: "location.hash".into(),
        executed: true,
        observed_marker: "SCALD_MARKER".into(),
    });
}

#[test]
fn finding_with_dom_execution_embeds_in_document() {
    let finding = Finding::builder("scald", "https://target.test/dom", Severity::High)
        .title("DOM XSS in 'q' (HtmlBody)")
        .kind(FindingKind::Vulnerability)
        .tag("xss-dom")
        .evidence(Evidence::DomExecution {
            sink: "document.write".into(),
            source: "location.search".into(),
            executed: true,
            observed_marker: "<img src=x onerror=alert(1)>".into(),
        })
        .build()
        .expect("valid finding");
    let json = serde_json::to_string(&finding).expect("serialize finding");
    let back: Finding = serde_json::from_str(&json).expect("deserialize finding");
    assert_eq!(back.scanner(), "scald");
    roundtrip(&back.evidence()[0]);
}
