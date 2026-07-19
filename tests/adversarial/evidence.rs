use secfinding::Evidence;

#[test]
fn evidence_deserialization_rejects_invalid_http_status() {
    let json = r#"{"type":"http_response","status":42,"headers":[]}"#;
    let error = serde_json::from_str::<Evidence>(json).unwrap_err();
    assert!(error.to_string().contains("between 100 and 599"));
}

#[test]
fn evidence_deserialization_rejects_zero_line_numbers() {
    let json = r#"{
        "type":"code_snippet",
        "file":"src/lib.rs",
        "line":0,
        "column":1,
        "snippet":"secret",
        "language":"rust"
    }"#;
    let error = serde_json::from_str::<Evidence>(json).unwrap_err();
    assert!(error.to_string().contains("1 or greater"));
}
