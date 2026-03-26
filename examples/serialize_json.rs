//! Example demonstrating JSON serialization of findings.
//!
//! Run: cargo run --example serialize_json

use secfinding::{Finding, Severity};

fn main() {
    let finding = Finding::builder("my-scanner", "192.168.1.100", Severity::Critical)
        .title("Default Credentials")
        .detail("Admin interface uses admin:admin")
        .tag("auth")
        .build();

    let json = serde_json::to_string_pretty(&finding).expect("Failed to serialize");
    println!("Serialized Finding:\n{}", json);
}
