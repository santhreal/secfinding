# secfinding

A typed security finding. Instead of passing around JSON blobs with maybe-there-maybe-not fields, you get a struct with a builder, proper severity levels, evidence types, and a trait that lets any scanner's output type plug into the reporting pipeline.

```rust
use secfinding::{Finding, Severity};

let f = Finding::builder("my-scanner", "https://example.com", Severity::High)
    .title("SQL Injection")
    .detail("User input reaches database query unsanitized")
    .cve("CVE-2024-12345")
    .tag("sqli")
    .build();
```

## The Reportable trait

You probably already have your own finding type. You don't need to switch to ours. Implement `Reportable` and your type works with `secreport` for SARIF/JSON/Markdown output:

```rust
use secfinding::{Reportable, Severity};

struct MyFinding {
    name: String,
    sev: u8,
}

impl Reportable for MyFinding {
    fn scanner(&self) -> &str { "my-tool" }
    fn target(&self) -> &str { "target" }
    fn severity(&self) -> Severity { Severity::from(self.sev) }
    fn title(&self) -> &str { &self.name }
}
```

Four required methods. Everything else has defaults. Your type now gets free SARIF output, JSON serialization, Markdown reports.

## Severity

Five levels: Info, Low, Medium, High, Critical. Ordered, comparable, serializable. Parse from strings:

```rust
use secfinding::Severity;

let s = Severity::from("high");    // from &str
let s = Severity::from(3u8);       // from number (0=Info, 4=Critical)
let s: Severity = "critical".into();
```

## Evidence

Typed proof attached to findings. HTTP responses, code snippets, DNS records, banners:

```rust
use secfinding::Evidence;

let ev = Evidence::HttpResponse {
    status: 500,
    headers: vec![],
    body_excerpt: Some("SQL syntax error near".into()),
};
```

## Filtering

Filter findings by severity, scanner, tags:

```rust
use secfinding::{filter, FindingFilter};

let config = FindingFilter {
    min_severity: Some(Severity::Medium),
    ..Default::default()
};
let filtered = filter(&findings, &config);
```

## Contributing

Pull requests are welcome. There is no such thing as a perfect crate. If you find a bug, a better API, or just a rough edge, open a PR. We review quickly.

## License

MIT. Copyright 2026 CORUM COLLECTIVE LLC.

[![crates.io](https://img.shields.io/crates/v/secfinding.svg)](https://crates.io/crates/secfinding)
[![docs.rs](https://docs.rs/secfinding/badge.svg)](https://docs.rs/secfinding)
