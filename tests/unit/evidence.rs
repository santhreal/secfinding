use secfinding::Evidence;

#[test]
fn serde_tagged() {
    let ev = Evidence::HttpResponse {
        status: 200,
        headers: vec![("Server".into(), "nginx".into())],
        body_excerpt: Some("test".into()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    assert!(json.contains("http_response"));
    assert!(json.contains("nginx"));
}

#[test]
fn display_formatting() {
    let ev = Evidence::http_status(404).unwrap();
    assert_eq!(
        ev.to_string(),
        "http-response status=404 headers=0 body_excerpt=none"
    );
}

// Ported from the previously dead tests/unit/test_evidence.rs (orphaned behind
// an unwired tests/unit/mod.rs). serde round-trips across every Evidence variant.
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
