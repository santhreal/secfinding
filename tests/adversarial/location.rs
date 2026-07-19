use secfinding::Location;

#[test]
fn location_deserialization_rejects_path_traversal() {
    let json = r#"{"file":"../secret","line":1}"#;
    let error = serde_json::from_str::<Location>(json).unwrap_err();
    assert!(error.to_string().contains("directory traversal"));
}

#[test]
fn location_deserialization_rejects_zero_coordinates() {
    let json = r#"{"file":"src/main.rs","line":0,"column":0}"#;
    let error = serde_json::from_str::<Location>(json).unwrap_err();
    assert!(error.to_string().contains("1 or greater"));
}
