use secfinding::{Finding, Severity};

fn main() {
    let finding = Finding::builder("basic-scanner", "https://example.com", Severity::High)
        .title("Potential command injection")
        .detail("Untrusted input reaches shell execution")
        .tag("rce")
        .evidence(secfinding::Evidence::http_status(500).unwrap())
        .build()
        .unwrap();

    println!("{finding}");

    let json = serde_json::to_string_pretty(&finding).unwrap();
    println!("{json}");
}
