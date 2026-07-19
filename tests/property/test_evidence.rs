use proptest::prelude::*;
use secfinding::Evidence;

use crate::strategies::{arb_detail, arb_printable};

proptest! {
    #[test]
    fn test_evidence_serialization_symmetry(
        status in 100u16..=599u16,
        body in arb_detail(),
        file in "[a-zA-Z0-9/._-]*",
        line in 1usize..10000usize,
        snippet in arb_printable(200),
    ) {
        if file.is_empty() {
            return Ok(());
        }
        let ev_http = Evidence::HttpResponse {
            status,
            headers: vec![],
            body_excerpt: Some(body.into()),
        };
        let serialized_http = serde_json::to_string(&ev_http).unwrap();
        let deserialized_http: Evidence = serde_json::from_str(&serialized_http).unwrap();
        match (ev_http, deserialized_http) {
            (Evidence::HttpResponse { status: s1, .. }, Evidence::HttpResponse { status: s2, .. }) => {
                assert_eq!(s1, s2);
            },
            _ => panic!("Expected HttpResponse"),
        }

        if let Ok(ev_code) = Evidence::code(&file, line, &snippet, None, None) {
             let serialized_code = serde_json::to_string(&ev_code).unwrap();
             let deserialized_code: Evidence = serde_json::from_str(&serialized_code).unwrap();
             match (ev_code, deserialized_code) {
                 (Evidence::CodeSnippet { file: f1, line: l1, .. }, Evidence::CodeSnippet { file: f2, line: l2, .. }) => {
                     assert_eq!(f1, f2);
                     assert_eq!(l1, l2);
                 },
                 _ => panic!("Expected CodeSnippet"),
             }
        }
    }
}
