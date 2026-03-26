//! Typed evidence attached to findings.
//!
//! Each variant carries structured proof. Consumers use the tag to
//! render evidence correctly (terminal, markdown, SARIF, etc.).

use serde::{Deserialize, Serialize};

/// Concrete evidence proving a finding is real.
///
/// Extensible via `#[non_exhaustive]` — new evidence types can be added
/// for new tools (firmware, mobile, etc.) without breaking existing consumers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Evidence {
    /// HTTP response data (status, headers, body excerpt).
    HttpResponse {
        /// HTTP status code.
        status: u16,
        /// Response headers as key-value pairs.
        headers: Vec<(String, String)>,
        /// First N bytes of the response body.
        body_excerpt: Option<String>,
    },

    /// DNS record evidence.
    DnsRecord {
        /// Record type (A, AAAA, CNAME, MX, TXT, etc.).
        record_type: String,
        /// Record value.
        value: String,
    },

    /// Service banner captured during port scanning.
    Banner {
        /// Raw banner text.
        raw: String,
    },

    /// JavaScript source snippet with context.
    JsSnippet {
        /// URL of the JS file.
        url: String,
        /// Line number in the file.
        line: usize,
        /// The matched code snippet.
        snippet: String,
    },

    /// TLS certificate information.
    Certificate {
        /// Certificate subject (CN).
        subject: String,
        /// Subject Alternative Names.
        san: Vec<String>,
        /// Certificate issuer.
        issuer: String,
        /// Expiration date.
        expires: String,
    },

    /// Source code snippet (for SAST, malware detection).
    CodeSnippet {
        /// File path.
        file: String,
        /// Line number.
        line: usize,
        /// Column number (optional).
        column: Option<usize>,
        /// The matched code.
        snippet: String,
        /// Programming language.
        language: Option<String>,
    },

    /// HTTP request that triggered the finding (for template/vuln scanners).
    HttpRequest {
        /// HTTP method.
        method: String,
        /// Full URL.
        url: String,
        /// Request headers.
        headers: Vec<(String, String)>,
        /// Request body.
        body: Option<String>,
    },

    /// Matched pattern or regex (for pattern-based scanners).
    PatternMatch {
        /// The pattern or regex that matched.
        pattern: String,
        /// The matched content.
        matched: String,
    },

    /// Unstructured evidence — fallback for anything that doesn't fit above.
    Raw(String),
}

impl Evidence {
    /// Create an HTTP response evidence with just a status code.
    pub fn http_status(status: u16) -> Result<Self, &'static str> {
        if !(100..=599).contains(&status) {
            return Err("HTTP status code must be between 100 and 599");
        }
        Ok(Self::HttpResponse {
            status,
            headers: vec![],
            body_excerpt: None,
        })
    }

    /// Create a code snippet evidence.
    #[must_use]
    pub fn code(
        file: impl Into<String>,
        line: usize,
        snippet: impl Into<String>,
        column: Option<usize>,
        language: Option<String>,
    ) -> Self {
        Self::CodeSnippet {
            file: file.into(),
            line,
            column,
            snippet: snippet.into(),
            language,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_tagged() {
        let ev = Evidence::HttpResponse {
            status: 403,
            headers: vec![("server".into(), "cloudflare".into())],
            body_excerpt: Some("blocked".into()),
        };
        let json = serde_json::to_value(&ev).unwrap();
        assert_eq!(json["type"], "http_response");
        assert_eq!(json["status"], 403);
    }

    #[test]
    fn code_snippet_roundtrip() {
        let ev = Evidence::code("src/main.rs", 42, "let key = \"AKIA...\";", None, None);
        let json = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&json).unwrap();
        if let Evidence::CodeSnippet {
            file,
            line,
            snippet,
            ..
        } = back
        {
            assert_eq!(file, "src/main.rs");
            assert_eq!(line, 42);
            assert_eq!(snippet, "let key = \"AKIA...\";");
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

        let snippet = Evidence::code("lib.rs", 10, "secret = 'x'", None, None);
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
}
